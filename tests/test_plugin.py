"""The plugin with a stand-in Hermes session and approval gate, and a fake gatekeeper."""

import ast
import importlib.machinery
import importlib.util
import json
import os
import re
import sys
import threading
import tomllib
import unittest
import uuid
from pathlib import Path

from plugin_support import PLUGIN_DIR, ROOT, PluginTestCase, bind_session, load_plugin, plugin_module, using_real_hermes

ALICE, BOB = "alice@gmail.com", "bob@gmail.com"
VECTORS = json.loads((ROOT / "tests/email_vectors.json").read_text())


class RecordingContext:
    def __init__(self):
        self.tools, self.hooks, self.skills = {}, {}, {}

    def register_tool(self, name, toolset, schema, handler, check_fn=None, **kwargs):
        self.tools[name] = {"toolset": toolset, "schema": schema, "handler": handler, "check_fn": check_fn}

    def register_hook(self, name, callback):
        self.hooks[name] = callback

    def register_skill(self, name, path):
        self.skills[name] = path



def _manifest_list(key):
    text = (PLUGIN_DIR / "plugin.yaml").read_text()
    block = re.search(rf"^{key}:\n((?:  - .+\n)+)", text, re.M)
    return re.findall(r"  - (.+)", block.group(1))


class Manifest(unittest.TestCase):
    def setUp(self):
        self.ctx = RecordingContext()
        load_plugin().register(self.ctx)

    def test_manifest_matches_registrations(self):
        self.assertEqual(sorted(_manifest_list("provides_tools")), sorted(self.ctx.tools))
        self.assertEqual(sorted(_manifest_list("provides_hooks")), sorted(self.ctx.hooks))

    def test_skill_exists_with_frontmatter(self):
        text = Path(self.ctx.skills["app-hosting"]).read_text()
        self.assertTrue(text.startswith("---\nname: app-hosting\n"))

    def test_schemas_have_no_sender_field_and_refuse_extras(self):
        for name, tool in self.ctx.tools.items():
            self.assertEqual(tool["schema"]["name"], name)
            parameters = tool["schema"]["parameters"]
            self.assertIs(parameters["additionalProperties"], False)
            for forbidden in ("sender", "user", "user_id", "requested_by", "created_by", "author"):
                self.assertNotIn(forbidden, parameters["properties"])

    def test_pyproject_declares_nothing_to_install(self):
        project = tomllib.loads((PLUGIN_DIR / "pyproject.toml").read_text())
        self.assertEqual(project["project"]["dependencies"], [])
        for key in ("build-system", "dependency-groups"):
            self.assertNotIn(key, project)

    def test_only_stdlib_and_documented_hermes_imports(self):
        allowed = {"agent", "gateway", "hermes_constants", "tools"}
        for path in PLUGIN_DIR.glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                modules = []
                if isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    modules = [node.module]
                for module in modules:
                    top = module.split(".")[0]
                    self.assertTrue(top in allowed or top in sys.stdlib_module_names, f"{path.name} imports {module}")

    def test_no_module_shadows_a_hermes_package(self):
        # A top-level tools.py in a plugin folder breaks tests run from there. See team_memory's README.
        names = {path.stem for path in PLUGIN_DIR.glob("*.py")}
        self.assertFalse(names & {"tools", "gateway", "agent", "hermes_cli", "requests"})

    def test_repo_holds_no_host_specific_values(self):
        # Add your own domain or ids at release time, without writing them here: APP_PLATFORM_FORBIDDEN=a|b
        extra = os.environ.get("APP_PLATFORM_FORBIDDEN", "")
        pattern = re.compile(r"/home/[a-z]|/Users/[a-z]" + (f"|{extra}" if extra else ""))
        for path in ROOT.rglob("*"):
            relative = path.relative_to(ROOT)
            if not path.is_file() or relative.parts[0] == ".git" or "__pycache__" in relative.parts:
                continue
            if relative == Path("tests/test_plugin.py"):
                continue  # this file names the patterns
            self.assertIsNone(pattern.search(path.read_text(errors="ignore")), str(relative))


class Sender(PluginTestCase):
    """Spoofing, and calls with no sender."""

    def setUp(self):
        super().setUp()
        self.keeper = self.start_gatekeeper()

    def test_sender_comes_from_the_session_never_the_arguments(self):
        bind_session(user_id="real-user", user_name="Ada")
        spoof = {"user_id": "spoofed", "sender": "telegram:spoofed", "requested_by": "telegram:spoofed",
                 "created_by": "telegram:spoofed", "author": "spoofed"}
        self.call(self.handlers.app_publish, {"name": "myapp", "port": 3001, **spoof})
        self.call(self.handlers.app_unpublish, {"name": "myapp", **spoof})
        self.call(self.handlers.app_list, spoof)
        self.call(self.handlers.app_revoke, {"name": "myapp", "emails": [ALICE], **spoof})
        self.gate.call("app_grant", self.handlers.app_grant, {"name": "myapp", "emails": [ALICE], **spoof})
        self.assertEqual(len(self.keeper.requests), 5)
        for request in self.keeper.requests:
            self.assertEqual(request["requested_by"], "telegram:real-user")
            self.assertLessEqual(set(request), {"id", "action", "requested_by", "name", "port", "emails"})

    def test_no_sender_is_refused_by_every_tool(self):
        calls = [(self.handlers.app_publish, {"name": "myapp", "port": 3001}), (self.handlers.app_unpublish, {"name": "myapp"}),
                 (self.handlers.app_list, {}), (self.handlers.app_grant, {"name": "myapp", "emails": [ALICE]}),
                 (self.handlers.app_revoke, {"name": "myapp", "emails": [ALICE]})]
        for bind in (None, dict(user_id=""), dict(platform="", user_id="user-1")):
            if bind is not None:
                bind_session(**bind)
            for handler, args in calls:
                with self.subTest(handler=handler.__name__, bind=bind):
                    self.assertIn("sender", self.call(handler, args)["error"])
        self.assertEqual(self.keeper.requests, [])

    def test_environment_cannot_stand_in_for_a_session(self):
        os.environ.update(HERMES_SESSION_PLATFORM="telegram", HERMES_SESSION_USER_ID="from-env")
        self.addCleanup(lambda: [os.environ.pop(k, None) for k in ("HERMES_SESSION_PLATFORM", "HERMES_SESSION_USER_ID")])
        self.assertIn("sender", self.call(self.handlers.app_list, {})["error"])
        self.assertEqual(self.keeper.requests, [])

    def test_platform_not_allowed(self):
        bind_session(platform="local", user_id="uid:1002")
        self.assertIn("not enabled", self.call(self.handlers.app_list, {})["error"])
        blocked = self.gate.call("app_grant", self.handlers.app_grant, {"name": "myapp", "emails": [ALICE]})
        self.assertIn("not enabled", blocked["blocked"])
        self.assertEqual((self.gate.prompts, self.keeper.requests), ([], []))

    def test_strange_user_id_refused(self):
        bind_session(user_id="a b\nc")
        self.assertIn("cannot record", self.call(self.handlers.app_list, {})["error"])

    def test_each_concurrent_sender_is_recorded_as_themselves(self):
        results = []

        def one(user_id):
            bind_session(user_id=user_id)
            results.append(self.call(self.handlers.app_list, {}))

        threads = [threading.Thread(target=one, args=(f"user-{i}",)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(r["requested_by"] for r in self.keeper.requests), [f"telegram:user-{i}" for i in range(8)])


class Approval(PluginTestCase):
    def setUp(self):
        super().setUp()
        self.keeper = self.start_gatekeeper()
        bind_session(user_id="user-1", user_name="Ada")
        self.args = {"name": "myapp", "emails": [ALICE, "Bob@Gmail.com"]}

    def grant(self, args=None, **kwargs):
        return self.gate.call("app_grant", self.handlers.app_grant, args or self.args, **kwargs)

    def assert_nobody_added(self):
        self.assertEqual([r for r in self.keeper.requests if r["action"] == "grant"], [])

    def test_approved_grant_sends_exactly_what_was_shown(self):
        result = self.grant()
        self.assertEqual(result["status"], "granted")
        prompt = self.gate.prompts[0]
        self.assertIn("'myapp'", prompt)
        self.assertIn(ALICE, prompt)
        self.assertIn(BOB, prompt)
        self.assertEqual(self.keeper.requests[0]["emails"], [ALICE, BOB])

    def test_only_app_grant_asks(self):
        for tool in ("app_publish", "app_unpublish", "app_list", "app_revoke", "terminal"):
            self.assertIsNone(self.hooks.require_grant_approval(tool_name=tool, args={"name": "x"}))

    def test_denied_timed_out_or_undelivered_adds_nobody(self):
        for answer in ("deny", "timeout", "cancelled", "notify_failed", "smart_approve", "", "ONCE", None):
            with self.subTest(answer):
                self.approvals.clear()
                self.gate.answer = answer
                result = self.grant()
                self.assertTrue("blocked" in result or "error" in result, result)
                self.assert_nobody_added()

    def test_a_negative_answer_leaves_nothing_the_handler_can_spend(self):
        # Hermes wouldn't call the handler after these, so reach it directly: the ticket itself must say no.
        for answer in ("deny", "timeout", "cancelled", "notify_failed", "smart_approve", "", "ONCE", None, 1):
            with self.subTest(answer):
                self.approvals.clear()
                directive = self.hooks.require_grant_approval(tool_name="app_grant", args=self.args)
                self.hooks.record_approval(pattern_key=f"plugin_rule:{directive['rule_key']}", choice=answer)
                self.assertIn("no person approved", self.call(self.handlers.app_grant, self.args)["error"])
        self.assert_nobody_added()

    def test_prompt_skipped_by_yolo_or_approvals_off_adds_nobody(self):
        self.gate.answer = None  # Hermes returns approved and no observer fires
        self.assertIn("no person approved", self.grant()["error"])
        self.assert_nobody_added()

    def test_failed_hook_adds_nobody(self):
        self.gate.hook_raises = True  # Hermes then runs the tool anyway
        self.assertIn("no person approved", self.grant()["error"])
        self.assert_nobody_added()

    def test_handler_reached_without_the_hook_adds_nobody(self):
        self.assertIn("no person approved", self.call(self.handlers.app_grant, self.args)["error"])
        self.assert_nobody_added()

    def test_arguments_changed_after_approval_add_nobody(self):
        result = self.grant(rewrite_args={"name": "myapp", "emails": ["mallory@gmail.com"]})
        self.assertIn("no person approved", result["error"])
        result = self.grant(rewrite_args={"name": "other-app", "emails": self.args["emails"]})
        self.assertIn("no person approved", result["error"])
        self.assert_nobody_added()

    def test_one_approval_is_spent_once(self):
        self.assertEqual(self.grant()["status"], "granted")
        self.assertIn("no person approved", self.call(self.handlers.app_grant, self.args)["error"])

    def test_always_answer_does_not_cover_a_later_grant(self):
        self.gate.answer = "always"
        self.assertEqual(self.grant()["status"], "granted")
        self.grant()
        self.assertEqual(len(self.gate.prompts), 2)
        self.assertNotEqual(*self.gate.rule_keys)  # Hermes keys its allowlist on this

    def test_approval_for_one_sender_does_not_serve_another(self):
        directive = self.hooks.require_grant_approval(tool_name="app_grant", args=self.args)
        self.hooks.record_approval(pattern_key=f"plugin_rule:{directive['rule_key']}", choice="once")
        bind_session(user_id="user-2")
        self.assertIn("no person approved", self.call(self.handlers.app_grant, self.args)["error"])

    def test_other_rules_answers_are_ignored(self):
        directive = self.hooks.require_grant_approval(tool_name="app_grant", args=self.args)
        for key in ("rm_rf", "plugin_rule:other", f"plugin_rule:app_grant:{'0' * 32}", None, 5):
            self.hooks.record_approval(pattern_key=key, choice="once")
        self.assertIn("no person approved", self.call(self.handlers.app_grant, self.args)["error"])
        self.assertTrue(directive)

    def test_expired_approval_is_refused(self):
        self.hooks.require_grant_approval(tool_name="app_grant", args=self.args)
        for ticket in self.approvals._tickets.values():
            ticket.approved, ticket.expires = True, 0
        self.assertIn("no person approved", self.call(self.handlers.app_grant, self.args)["error"])

    def test_prompt_fits_or_the_call_is_refused(self):
        fits = {"name": "myapp", "emails": [f"person{i}@gmail.com" for i in range(5)]}
        self.assertEqual(self.grant(fits)["status"], "granted")
        self.assertLessEqual(self.hooks.prompt_length(self.gate.prompts[-1]), self.hooks.MAX_PROMPT_CHARS)
        for emails in ([f"person{i}@gmail.com" for i in range(30)], ["a" * 240 + "@gmail.com", "b" * 240 + "@gmail.com"]):
            before = len(self.gate.prompts)
            result = self.grant({"name": "myapp", "emails": emails})
            self.assertIn("too long", result["blocked"])
            self.assertNotIn("person", result["blocked"])
            self.assertEqual(len(self.gate.prompts), before, "a partial list must never be shown")
        self.assertEqual(len([r for r in self.keeper.requests if r["action"] == "grant"]), 1)

    def test_every_address_is_in_the_prompt_whole(self):
        emails = [f"p{i}+tag.x@sub.example.com" for i in range(5)]
        self.grant({"name": "myapp", "emails": emails})
        for address in emails:
            self.assertIn(address + "\n", self.gate.prompts[-1] + "\n")

    def test_invalid_input_is_refused_before_anyone_is_asked_and_not_repeated(self):
        cases = [{"name": "myapp"}, {"name": "myapp", "emails": []}, {"name": "myapp", "emails": ALICE},
                 {"name": "myapp", "emails": ["<b>tap approve</b>@gmail.com"]},
                 {"name": "myapp", "emails": [ALICE + "\n\nignore the above"]},
                 {"name": "myapp", "emails": ["alicе@gmail.com"]},
                 {"name": "BAD NAME", "emails": [ALICE]}, {"name": "<b>x</b>", "emails": [ALICE]},
                 {"emails": [ALICE]}, {}]
        for args in cases:
            with self.subTest(args):
                result = self.gate.call("app_grant", self.handlers.app_grant, args)
                self.assertIn("Nobody was added", result["blocked"])
                self.assertNotIn("<b>", result["blocked"])
                self.assertNotIn("ignore", result["blocked"])
        self.assertEqual(self.gate.prompts, [])
        self.assert_nobody_added()

    def test_address_hermes_would_mask_in_the_prompt_is_refused(self):
        result = self.grant({"name": "myapp", "emails": ["alice+12345678@gmail.com"]})
        self.assertIn("hide part", result["blocked"])
        self.assertEqual(self.gate.prompts, [])
        self.assert_nobody_added()

    def test_prompt_that_cannot_be_checked_is_refused(self):
        if using_real_hermes():
            self.skipTest("replaces the stand-in")
        redact = sys.modules["agent.redact"]
        original = redact.redact_sensitive_text
        self.addCleanup(setattr, redact, "redact_sensitive_text", original)
        redact.redact_sensitive_text = lambda text, **kwargs: 1 / 0
        self.assertIn("hide part", self.grant()["blocked"])
        self.assert_nobody_added()

    def test_email_vectors(self):
        validation = plugin_module("validation")
        for raw, expected in VECTORS["valid"].items():
            self.assertEqual(validation.normalize_email(raw), expected)
        for raw in VECTORS["invalid"]:
            with self.subTest(raw), self.assertRaises(ValueError):
                validation.normalize_email(raw)


class OwnerNotice(PluginTestCase):
    def setUp(self):
        super().setUp()
        self.keeper = self.start_gatekeeper()
        bind_session(user_id="user-1", user_name="Ada‮\n")
        self.args = {"name": "myapp", "emails": [ALICE, BOB]}

    def grant(self):
        return self.gate.call("app_grant", self.handlers.app_grant, self.args)

    def test_owner_is_told_who_added_whom(self):
        self.assertIs(self.grant()["owner_notified"], True)
        args = self.notifications[0]
        self.assertEqual((args["action"], args["target"]), ("send", "telegram:owner-chat"))
        for part in ("Ada", "telegram:user-1", "myapp", ALICE, BOB):
            self.assertIn(part, args["message"])
        self.assertNotIn("‮", args["message"])

    def test_only_guests_really_added_are_named(self):
        self.keeper.reply = lambda request: {"status": "ok", "url": "u", "added": [BOB], "already": [ALICE]}
        self.grant()
        self.assertIn(BOB, self.notifications[0]["message"])
        self.assertNotIn(ALICE, self.notifications[0]["message"])

    def test_nothing_new_means_no_notice(self):
        self.keeper.reply = lambda request: {"status": "ok", "url": "u", "added": [], "already": [ALICE, BOB]}
        self.assertIsNone(self.grant()["owner_notified"])
        self.assertEqual(self.notifications, [])

    def test_failed_notice_is_reported_and_does_not_undo_the_grant(self):
        for failure in (json.dumps({"error": "no adapter"}), "not json", RuntimeError("boom"), json.dumps({"skipped": True}),
                        json.dumps({"success": False}), json.dumps({"success": True, "error": "partly failed"})):
            with self.subTest(failure):
                self.notify_result = failure
                result = self.grant()
                self.assertEqual(result["status"], "granted")
                self.assertIs(result["owner_notified"], False)

    def test_refused_grant_means_no_notice(self):
        self.keeper.reply = lambda request: {"status": "error", "reason": "'myapp' is not published"}
        self.assertIn("not published", self.grant()["error"])
        self.assertEqual(self.notifications, [])


class GatekeeperClient(PluginTestCase):
    def setUp(self):
        super().setUp()
        bind_session(user_id="user-1")

    def test_publish_result_and_request_file(self):
        keeper = self.start_gatekeeper()
        result = self.call(self.handlers.app_publish, {"name": "myapp", "port": 3001})
        self.assertEqual(result["status"], "published")
        self.assertEqual(keeper.requests[0]["port"], 3001)
        self.assertRegex(keeper.requests[0]["id"], r"^[0-9a-f]{32}$")
        self.assertEqual(os.listdir(self.root / "inbox/tmp"), [])

    def test_refusal_reaches_the_model(self):
        keeper = self.start_gatekeeper()
        keeper.reply = lambda request: {"status": "error", "reason": "port 3001 is not owned by agent"}
        self.assertIn("not owned", self.call(self.handlers.app_publish, {"name": "myapp", "port": 3001})["error"])

    def test_no_answer_says_the_outcome_is_unknown(self):
        keeper = self.start_gatekeeper()
        keeper.silent = True
        self.write_config(result_timeout_seconds=1)
        self.assertIn("unknown", self.call(self.handlers.app_list, {})["error"])

    def test_answer_for_another_request_is_refused(self):
        keeper = self.start_gatekeeper()
        keeper.silent = True
        client = plugin_module("gatekeeper_client")
        config = plugin_module("config").load_config()
        request_id = uuid.uuid4().hex
        (self.root / "results" / f"{request_id}.json").write_text(json.dumps({"id": "other", "status": "ok"}))
        with self.assertRaises(client.GatekeeperError):
            client._wait_for_result(config, request_id)

    def test_missing_inbox_is_a_clear_error(self):
        self.write_config(inbox_dir=str(self.root / "absent"))
        self.assertIn("not be installed", self.call(self.handlers.app_list, {})["error"])

    def test_bad_inputs_never_reach_the_gatekeeper(self):
        keeper = self.start_gatekeeper()
        for args in ({"name": "BAD", "port": 3001}, {"name": "../x", "port": 3001}, {"name": "myapp", "port": "3001"},
                     {"name": "myapp", "port": True}, {"name": "myapp"}):
            self.assertIn("error", self.call(self.handlers.app_publish, args))
        self.assertIn("error", self.call(self.handlers.app_revoke, {"name": "myapp", "emails": ["nope"]}))
        self.assertEqual(keeper.requests, [])


class Config(PluginTestCase):
    def test_availability(self):
        self.assertTrue(self.handlers.is_available())
        for overrides in ({"notify_target": "telegram:REPLACE_ME_OWNER_CHAT_ID"}, {"notify_target": ""}, {"inbox_dir": "relative"},
                          {"allowed_platforms": []}, {"result_timeout_seconds": 0}, {"unknown_field": 1}):
            with self.subTest(overrides):
                self.write_config(**overrides)
                self.assertFalse(self.handlers.is_available())

    def test_group_writable_config_is_refused(self):
        os.chmod(self.config_file, 0o664)
        self.assertFalse(self.handlers.is_available())

    def test_missing_config(self):
        os.unlink(self.config_file)
        self.assertFalse(self.handlers.is_available())

    def test_example_shape_is_known_but_placeholder_is_refused(self):
        example = json.loads((PLUGIN_DIR / "app_platform.example.json").read_text())
        self.config_file.write_text(json.dumps(example))
        os.chmod(self.config_file, 0o600)
        with self.assertRaisesRegex(plugin_module("config").ConfigError, "notify_target"):
            plugin_module("config").load_config()


class WithRealGatekeeper(PluginTestCase):
    """The real gatekeeper code on the other side of the inbox: only the listener check, chown and user
    lookups are faked. Publish, grant, approve, revoke and list, as the target flow runs them."""

    def setUp(self):
        super().setUp()
        loader = importlib.machinery.SourceFileLoader("gatekeeper_e2e", str(ROOT / "gatekeeper/hermes-app-gatekeeper"))
        spec = importlib.util.spec_from_loader("gatekeeper_e2e", loader)
        gatekeeper = importlib.util.module_from_spec(spec)
        loader.exec_module(gatekeeper)
        gatekeeper.log.disabled = True
        gatekeeper.check_listener = lambda port, settings: None
        (self.root / "registry").mkdir()
        config = {"domain": "example.net", "agent_user": "agent", "requester_user": "hermes", "registry_group": "r",
                  "result_group": "h", "reserved_names": ["hermes"], "inbox_dir": str(self.root / "inbox/new"),
                  "result_dir": str(self.root / "results"), "registry_dir": str(self.root / "registry")}
        (self.root / "gk.json").write_text(json.dumps(config))
        settings = gatekeeper.Settings(str(self.root / "gk.json"))
        settings.__class__ = type("S", (gatekeeper.Settings,), {
            "requester_uid": os.getuid(), "agent_uid": 1003, "registry_gid": os.getgid(), "result_gid": os.getgid()})
        real_chown = os.chown
        os.chown = lambda *a, **k: None
        self.addCleanup(setattr, os, "chown", real_chown)
        stop = threading.Event()

        def run():
            while not stop.wait(0.01):
                if os.listdir(settings.inbox_dir):
                    gatekeeper.process_requests(settings)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(stop.set)

    def entry(self, name):
        return json.loads((self.root / "registry" / f"{name}.json").read_text())

    def test_the_target_flow(self):
        bind_session(user_id="teammate-1", user_name="Ada")
        published = self.call(self.handlers.app_publish, {"name": "myapp", "port": 3001})
        self.assertEqual(published["url"], "https://myapp.example.net")
        self.assertEqual(self.entry("myapp")["created_by"], "telegram:teammate-1")
        bind_session(user_id="teammate-2", user_name="Grace")
        granted = self.gate.call("app_grant", self.handlers.app_grant, {"name": "myapp", "emails": ["Alice@Gmail.com", BOB]})
        self.assertEqual(granted["added"], [ALICE, BOB])
        self.assertEqual(self.entry("myapp")["guests"], [ALICE, BOB])
        self.assertIn("telegram:teammate-2", self.notifications[0]["message"])
        self.assertEqual(self.entry("myapp")["created_by"], "telegram:teammate-1")
        revoked = self.call(self.handlers.app_revoke, {"name": "myapp", "emails": [BOB]})
        self.assertEqual(revoked["removed"], [BOB])
        apps = self.call(self.handlers.app_list, {})["apps"]
        self.assertEqual(apps[0]["guests"], [ALICE])
        self.assertEqual(self.call(self.handlers.app_unpublish, {"name": "myapp"})["status"], "unpublished")
        self.assertEqual(self.call(self.handlers.app_list, {})["apps"], [])

    def test_gatekeeper_refusals_come_back(self):
        bind_session(user_id="teammate-1")
        self.assertIn("reserved", self.call(self.handlers.app_publish, {"name": "hermes", "port": 3001})["error"])
        self.assertIn("between", self.call(self.handlers.app_publish, {"name": "myapp", "port": 9119})["error"])
        result = self.gate.call("app_grant", self.handlers.app_grant, {"name": "absent", "emails": [ALICE]})
        self.assertIn("not published", result["error"])
        self.assertEqual(self.notifications, [])


if __name__ == "__main__":
    unittest.main()
