"""Unit tests for hermes-app-gatekeeper. They use temp folders and fake the listener check, except
where stated, and run as an ordinary user, so chown is faked too."""
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import stat
import tempfile
import unittest
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
loader = importlib.machinery.SourceFileLoader("gatekeeper", str(ROOT / "gatekeeper/hermes-app-gatekeeper"))
spec = importlib.util.spec_from_loader("gatekeeper", loader)
gk = importlib.util.module_from_spec(spec)
loader.exec_module(gk)
gk.log.disabled = True  # refusals are asserted, not printed
VECTORS = json.loads((ROOT / "tests/email_vectors.json").read_text())
ALICE, BOB = "alice@gmail.com", "bob@gmail.com"


class Case(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        for sub in ("inbox", "results", "registry"):
            (root / sub).mkdir()
        config = {"domain": "example.net", "agent_user": "agent", "requester_user": "hermes",
                  "registry_group": "router", "result_group": "hermes", "reserved_names": ["hermes", "browser", "www"],
                  "inbox_dir": str(root / "inbox"), "result_dir": str(root / "results"),
                  "registry_dir": str(root / "registry"), "max_apps": 2, "max_guests_per_app": 3,
                  "max_emails_per_request": 3}
        (root / "s.json").write_text(json.dumps(config))
        self.s = gk.Settings(str(root / "s.json"))
        # The properties look up real system users, which tests don't have.
        settings_class = type("TestSettings", (gk.Settings,), {
            "requester_uid": os.getuid(), "agent_uid": 1003, "registry_gid": 0, "result_gid": 0})
        self.s.__class__ = settings_class
        self.root = root
        self.listener_error = None
        patches = {"check_listener": self.fake_listener}
        for name, value in patches.items():
            original = getattr(gk, name)
            setattr(gk, name, value)
            self.addCleanup(setattr, gk, name, original)
        real_chown = os.chown
        os.chown = lambda *a, **k: None
        self.addCleanup(setattr, os, "chown", real_chown)

    def fake_listener(self, port, settings):
        if self.listener_error:
            raise gk.Rejected(self.listener_error)

    def send(self, action, requested_by="telegram:42", **fields):
        request_id = uuid.uuid4().hex
        body = {"id": request_id, "action": action, "requested_by": requested_by, **fields}
        (self.root / "inbox" / f"{request_id}.json").write_text(json.dumps(body))
        self.run_it()
        return self.result(request_id)

    def raw(self, body):
        request_id = uuid.uuid4().hex
        (self.root / "inbox" / f"{request_id}.json").write_text(body if isinstance(body, str) else json.dumps(body))
        self.run_it()
        return self.result(request_id)

    def run_it(self):
        gk.process_requests(self.s)
        self.assertEqual(os.listdir(self.root / "inbox"), [], "requests must always be removed")

    def result(self, request_id):
        return json.loads((self.root / "results" / f"{request_id}.json").read_text())

    def ok(self, action, **fields):
        result = self.send(action, **fields)
        self.assertEqual(result["status"], "ok", result)
        return result

    def error(self, action, **fields):
        result = self.send(action, **fields)
        self.assertEqual(result["status"], "error", result)
        return result["reason"]

    def entry(self, name):
        return json.loads((self.root / "registry" / f"{name}.json").read_text())

    def registry_files(self):
        return sorted(os.listdir(self.root / "registry"))


class Publish(Case):
    def test_publish_writes_the_agreed_entry_and_unpublish_removes_it(self):
        result = self.ok("publish", name="myapp", port=3001)
        self.assertEqual(result["url"], "https://myapp.example.net")
        entry = self.entry("myapp")
        self.assertEqual(set(entry), {"name", "port", "created_by", "created_at", "guests"})
        self.assertEqual((entry["name"], entry["port"], entry["created_by"], entry["guests"]),
                         ("myapp", 3001, "telegram:42", []))
        mode = stat.S_IMODE(os.stat(self.root / "registry/myapp.json").st_mode)
        self.assertEqual(mode, 0o640)
        self.ok("unpublish", name="myapp")
        self.assertEqual(self.registry_files(), [])

    def test_republish_same_port_changes_nothing(self):
        self.ok("publish", name="myapp", port=3001)
        before = self.entry("myapp")
        result = self.send("publish", name="myapp", port=3001, requested_by="telegram:99")
        self.assertFalse(result["changed"])
        self.assertEqual(self.entry("myapp"), before)

    def test_port_can_move_without_guests_but_not_with_them(self):
        self.ok("publish", name="myapp", port=3001)
        self.ok("publish", name="myapp", port=3002)
        self.assertEqual(self.entry("myapp")["port"], 3002)
        self.ok("grant", name="myapp", emails=[ALICE])
        self.assertIn("has guests", self.error("publish", name="myapp", port=3003))
        self.assertEqual(self.entry("myapp")["port"], 3002)

    def test_guests_do_not_come_back_after_unpublish(self):
        self.ok("publish", name="myapp", port=3001)
        self.ok("grant", name="myapp", emails=[ALICE])
        self.ok("unpublish", name="myapp")
        self.ok("publish", name="myapp", port=3001)
        self.assertEqual(self.entry("myapp")["guests"], [])

    def test_field_rejections(self):
        cases = [
            ({"name": "hermes", "port": 3001}, "reserved"),
            ({"name": "browser", "port": 3001}, "reserved"),
            ({"name": "low", "port": 2999}, "between"),
            ({"name": "high", "port": 4000}, "between"),
            ({"name": "dash", "port": 9119}, "between"),
            ({"name": "boolp", "port": True}, "integer"),
            ({"name": "strp", "port": "3001"}, "integer"),
            ({"name": "floatp", "port": 3001.0}, "integer"),
            ({"name": "UPPER", "port": 3001}, "match"),
            ({"name": "a", "port": 3001}, "match"),
            ({"name": "x" * 32, "port": 3001}, "match"),
            ({"name": "../evil", "port": 3001}, "match"),
            ({"name": "a.b", "port": 3001}, "match"),
            ({"name": "trail-", "port": 3001}, "hyphen"),
            ({"name": "xn--abc", "port": 3001}, "hyphen"),
            ({"name": 7, "port": 3001}, "match"),
        ]
        for fields, expect in cases:
            with self.subTest(fields):
                self.assertIn(expect, self.error("publish", **fields))
        self.assertEqual(self.registry_files(), [])

    def test_port_collision_and_app_cap(self):
        self.ok("publish", name="one", port=3001)
        self.assertIn("already published", self.error("publish", name="two", port=3001))
        self.ok("publish", name="two", port=3002)
        self.assertIn("limit", self.error("publish", name="three", port=3003))

    def test_listener_failure_rejected(self):
        self.listener_error = "port 3001 is not owned by agent"
        self.assertIn("not owned", self.error("publish", name="myapp", port=3001))
        self.assertEqual(self.registry_files(), [])

    def test_unknown_app(self):
        self.assertIn("not published", self.error("unpublish", name="nope"))
        self.assertIn("not published", self.error("grant", name="nope", emails=[ALICE]))
        self.assertIn("not published", self.error("revoke", name="nope", emails=[ALICE]))


class Guests(Case):
    def setUp(self):
        super().setUp()
        self.ok("publish", name="myapp", port=3001)

    def test_grant_normalises_and_dedupes(self):
        result = self.ok("grant", name="myapp", emails=["Alice@GMail.com", ALICE, BOB])
        self.assertEqual(result["added"], [ALICE, BOB])
        self.assertEqual(self.entry("myapp")["guests"], [ALICE, BOB])
        result = self.ok("grant", name="myapp", emails=[ALICE])
        self.assertEqual((result["added"], result["already"]), ([], [ALICE]))

    def test_revoke(self):
        self.ok("grant", name="myapp", emails=[ALICE, BOB])
        result = self.ok("revoke", name="myapp", emails=["ALICE@gmail.com", "carol@gmail.com"])
        self.assertEqual((result["removed"], result["not_found"]), ([ALICE], ["carol@gmail.com"]))
        self.assertEqual(self.entry("myapp")["guests"], [BOB])

    def test_guest_cap_applies_and_changes_nothing(self):
        self.ok("grant", name="myapp", emails=["a1@gmail.com", "a2@gmail.com"])
        self.assertIn("at most", self.error("grant", name="myapp", emails=["a3@gmail.com", "a4@gmail.com"]))
        self.assertEqual(len(self.entry("myapp")["guests"]), 2)

    def test_request_cap(self):
        emails = [f"a{i}@gmail.com" for i in range(4)]
        self.assertIn("per request", self.error("grant", name="myapp", emails=emails))

    def test_one_bad_address_rejects_all_and_is_not_echoed(self):
        reason = self.error("grant", name="myapp", emails=[ALICE, "<script>@gmail.com"])
        self.assertIn("number 2", reason)
        self.assertNotIn("script", reason)
        self.assertEqual(self.entry("myapp")["guests"], [])

    def test_shape_rejections(self):
        for emails in ([], "alice@gmail.com", None, {"a": 1}, [1], [None], [[ALICE]]):
            with self.subTest(emails):
                self.assertEqual(self.send("grant", name="myapp", emails=emails)["status"], "error")

    def test_email_vectors(self):
        for raw, expected in VECTORS["valid"].items():
            self.assertEqual(gk.normalize_email(raw), expected)
        for raw in VECTORS["invalid"]:
            with self.subTest(raw), self.assertRaises(ValueError):
                gk.normalize_email(raw)

    def test_list(self):
        self.ok("grant", name="myapp", emails=[ALICE])
        apps = self.ok("list")["apps"]
        self.assertEqual([(a["name"], a["url"], a["guests"]) for a in apps],
                         [("myapp", "https://myapp.example.net", [ALICE])])


class HostileRequests(Case):
    def test_bad_filenames_are_discarded_without_a_result(self):
        for bad in ("UPPER.json", "a.json", "no-extension", "x y.json", "..json", "dot.dot.json", "-a.json",
                    "myapp.json", "A" * 32 + ".json", "0" * 32, ".tmp"):
            (self.root / "inbox" / bad).write_text("{}")
        self.run_it()
        self.assertEqual(os.listdir(self.root / "results"), [])

    def test_symlink_rejected_and_target_untouched(self):
        secret = self.root / "secret.json"
        secret.write_text(json.dumps({"action": "list"}))
        request_id = uuid.uuid4().hex
        os.symlink(secret, self.root / "inbox" / f"{request_id}.json")
        self.run_it()
        self.assertIn("regular file", self.result(request_id)["reason"])
        self.assertTrue(secret.exists())

    def test_fifo_does_not_block(self):
        request_id = uuid.uuid4().hex
        os.mkfifo(self.root / "inbox" / f"{request_id}.json")
        self.run_it()
        self.assertIn("regular file", self.result(request_id)["reason"])

    def test_directory_request_is_removed_without_following_links(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "keep").write_text("x")
        request_id = uuid.uuid4().hex
        directory = self.root / "inbox" / f"{request_id}.json"
        directory.mkdir()
        os.symlink(outside, directory / "link")
        self.run_it()
        self.assertIn("regular file", self.result(request_id)["reason"])
        self.assertTrue((outside / "keep").exists())

    def test_hard_link_rejected(self):
        other = self.root / "other"
        other.write_text("{}")
        request_id = uuid.uuid4().hex
        os.link(other, self.root / "inbox" / f"{request_id}.json")
        self.run_it()
        self.assertIn("regular file", self.result(request_id)["reason"])

    def test_inbox_replaced_by_a_symlink_is_refused(self):
        real = self.root / "inbox"
        real.rename(self.root / "moved")
        os.symlink(self.root / "moved", real)
        with self.assertRaises(OSError):
            gk.process_requests(self.s)

    def test_file_of_another_owner_rejected(self):
        self.s.__class__.requester_uid = os.getuid() + 1
        request_id = uuid.uuid4().hex
        (self.root / "inbox" / f"{request_id}.json").write_text("{}")
        self.run_it()
        self.assertIn("not owned", self.result(request_id)["reason"])

    def test_junk_contents(self):
        cases = [("x" * (gk.MAX_REQUEST_BYTES + 1), "larger"), ("{not json", "JSON"), ("[1]", "object"),
                 (b"\xff\xfe".decode("latin-1"), "JSON"), ("[" * 8000, "JSON")]
        for body, expect in cases:
            with self.subTest(expect):
                self.assertIn(expect, self.raw(body)["reason"])

    def test_duplicate_keys_rejected(self):
        request_id = uuid.uuid4().hex
        body = '{"id":"%s","action":"list","action":"list","requested_by":"telegram:1"}' % request_id
        (self.root / "inbox" / f"{request_id}.json").write_text(body)
        self.run_it()
        self.assertIn("JSON", self.result(request_id)["reason"])

    def test_mismatched_id_unknown_action_and_extra_fields(self):
        request_id = uuid.uuid4().hex
        (self.root / "inbox" / f"{request_id}.json").write_text(json.dumps(
            {"id": "f" * 32, "action": "list", "requested_by": "telegram:1"}))
        self.run_it()
        self.assertIn("match", self.result(request_id)["reason"])
        self.assertIn("action", self.error("destroy", name="x"))
        self.assertIn("action", self.error("__class__"))
        self.assertIn("wrong fields", self.error("publish", name="myapp", port=3001, guests=[ALICE]))
        self.assertIn("wrong fields", self.error("publish", name="myapp", port=3001, created_by="telegram:1"))
        self.assertIn("wrong fields", self.error("publish", name="myapp"))
        self.assertEqual(self.registry_files(), [])

    def test_bad_requester(self):
        for requester in ("", "nocolon", "telegram:", "telegram:has space", "x" * 40 + ":1", None, 5, "a:b\nc"):
            with self.subTest(requester):
                self.assertIn("requested_by", self.error("list", requested_by=requester))

    def test_more_than_a_run_can_take_are_left_for_the_next_run(self):
        ids = [uuid.uuid4().hex for _ in range(gk.MAX_REQUESTS_PER_RUN + 5)]
        for request_id in ids:
            (self.root / "inbox" / f"{request_id}.json").write_text(json.dumps(
                {"id": request_id, "action": "list", "requested_by": "telegram:1"}))
        gk.process_requests(self.s)
        self.assertEqual(len(os.listdir(self.root / "inbox")), 5)
        gk.process_requests(self.s)
        self.assertEqual(os.listdir(self.root / "inbox"), [])
        self.assertEqual(len(os.listdir(self.root / "results")), len(ids))

    def test_damaged_registry_stops_changes(self):
        self.ok("publish", name="good", port=3001)
        for body in ("{oops", '{"name":"bad"}', json.dumps({"name": "other", "port": 3002, "created_by": "x",
                     "created_at": "y", "guests": []}), json.dumps({"name": "bad", "port": 80, "created_by": "x",
                     "created_at": "y", "guests": []}), json.dumps({"name": "bad", "port": 3002, "created_by": "x",
                     "created_at": "y", "guests": ["NOT AN EMAIL"]})):
            with self.subTest(body):
                (self.root / "registry/bad.json").write_text(body)
                self.assertIn("damaged", self.error("publish", name="three", port=3003))
                self.assertIn("damaged", self.error("list"))
                self.assertEqual(self.entry("good")["port"], 3001)

    def test_old_results_are_pruned(self):
        old = self.root / "results" / ("a" * 32 + ".json")
        old.write_text("{}")
        os.utime(old, (1, 1))
        self.ok("list")
        self.assertFalse(old.exists())

    def test_result_cap(self):
        self.s.max_results = 3
        for _ in range(5):
            self.ok("list")
        self.assertEqual(len(os.listdir(self.root / "results")), 3)


class Listener(unittest.TestCase):
    def run_check(self, listeners, owner, require_container=False, executable="/usr/bin/rootlesskit"):
        fresh = importlib.util.module_from_spec(spec)
        loader.exec_module(fresh)
        fresh.log.disabled = True
        fresh.listeners_on = lambda port: listeners
        def readlink(path):
            if executable is None:
                raise OSError("gone")
            return executable

        fresh.os = type("O", (), {"stat": staticmethod(lambda p: type("S", (), {"st_uid": owner})()),
                                  "readlink": staticmethod(readlink)})
        settings = type("S", (), {"agent_uid": 1003, "agent_user": "agent", "require_container": require_container})()
        fresh.check_listener(3001, settings)

    def test_good(self):
        self.run_check([("127.0.0.1:3001", [10])], 1003)

    def test_nothing(self):
        with self.assertRaisesRegex(Exception, "nothing is listening"):
            self.run_check([], 1003)

    def test_wildcard(self):
        with self.assertRaisesRegex(Exception, "127.0.0.1 only"):
            self.run_check([("0.0.0.0:3001", [10])], 1003)

    def test_also_on_ipv6(self):
        with self.assertRaisesRegex(Exception, "127.0.0.1 only"):
            self.run_check([("127.0.0.1:3001", [10]), ("[::]:3001", [11])], 1003)

    def test_foreign_owner(self):
        with self.assertRaisesRegex(Exception, "not owned"):
            self.run_check([("127.0.0.1:3001", [10])], 1002)

    def test_unknown_pid(self):
        with self.assertRaisesRegex(Exception, "identify"):
            self.run_check([("127.0.0.1:3001", [])], 1003)

    def test_container_required_accepts_rootlesskit(self):
        self.run_check([("127.0.0.1:3001", [10])], 1003, require_container=True)

    def test_container_required_refuses_plain_process(self):
        with self.assertRaisesRegex(Exception, "plain process"):
            self.run_check([("127.0.0.1:3001", [10])], 1003, require_container=True, executable="/usr/bin/python3.12")

    def test_container_required_refuses_rootlesskit_lookalike(self):
        with self.assertRaisesRegex(Exception, "plain process"):
            self.run_check([("127.0.0.1:3001", [10])], 1003, require_container=True, executable="/tmp/rootlesskit")

    def test_container_required_refuses_unreadable_executable(self):
        with self.assertRaisesRegex(Exception, "identify"):
            self.run_check([("127.0.0.1:3001", [10])], 1003, require_container=True, executable=None)

    def test_plain_process_allowed_when_not_required(self):
        self.run_check([("127.0.0.1:3001", [10])], 1003, executable="/usr/bin/python3.12")

    def test_ss_line_parsing(self):
        fresh = importlib.util.module_from_spec(spec)
        loader.exec_module(fresh)
        line = 'LISTEN 0 4096 127.0.0.1:3001 0.0.0.0:* users:(("rootlesskit",pid=2041,fd=12),("node",pid=2050,fd=3))\n'
        fresh.subprocess = type("SP", (), {
            "run": staticmethod(lambda *a, **k: type("R", (), {"stdout": line})()),
            "SubprocessError": Exception})
        self.assertEqual(fresh.listeners_on(3001), [("127.0.0.1:3001", [2041, 2050])])


class ConfigFile(unittest.TestCase):
    def test_example_config_loads(self):
        settings = gk.Settings(str(ROOT / "deploy/gatekeeper.example.json"))
        self.assertEqual((settings.port_min, settings.port_max), (3000, 3999))
        self.assertIn("hermes", settings.reserved)


if __name__ == "__main__":
    unittest.main()
