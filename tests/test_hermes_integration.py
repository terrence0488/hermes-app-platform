"""Prove the sender, approval and owner-notice paths against real Hermes code. Skipped unless run inside a Hermes install.

Run it with Hermes's own interpreter, from outside the plugin folder:

    APP_PLATFORM_REAL_HERMES=1 PYTHONDONTWRITEBYTECODE=1 hermes --run-module unittest discover -v -s <repo>/tests -p 'test_hermes_integration.py'

It uses a throwaway Hermes home, temporary folders and a fake gatekeeper. It does not touch a real gateway, the
registry or the model, and it replaces the last step of the Telegram send, so nothing leaves the machine. It covers the
real session context, the real thread-propagation helper tool batches use, the real tool registry dispatch, the real
hook dispatch and approval gate, and the real send_message_tool down to that last step.

The home has to be throwaway. The first hook call makes Hermes discover plugins in its home. In a real home that
loads the installed app_platform, whose tools and approval tickets are separate from the copy under test.
"""

import asyncio
import contextvars
import json
import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from plugin_support import PluginTestCase, bind_session, load_plugin, plugin_module, using_real_hermes

ALICE = "alice@gmail.com"
OWNER_CHAT = "424242"
FAKE_TOKEN = "123456:not-a-real-token"
_saved_home = None
_temporary_home = None


def setUpModule():
    """Before any Hermes code asks where its home is."""
    global _saved_home, _temporary_home
    if using_real_hermes():
        _saved_home = os.environ.get("HERMES_HOME")
        _temporary_home = tempfile.mkdtemp(prefix="app-platform-hermes-home-")
        os.environ["HERMES_HOME"] = _temporary_home


def tearDownModule():
    if using_real_hermes():
        if _saved_home is None:
            os.environ.pop("HERMES_HOME", None)
        else:
            os.environ["HERMES_HOME"] = _saved_home
        shutil.rmtree(_temporary_home, ignore_errors=True)


@unittest.skipUnless(using_real_hermes(), "set APP_PLATFORM_REAL_HERMES=1 and use the Hermes interpreter")
class RealHermes(PluginTestCase):
    @classmethod
    def setUpClass(cls):
        """Set up once: tools and hooks must belong to one copy of the plugin for the whole run."""
        from hermes_cli.plugins import get_plugin_manager
        from hermes_constants import get_hermes_home
        from tools.registry import registry

        if Path(get_hermes_home()).resolve() != Path(_temporary_home).resolve():
            raise RuntimeError(f"expected the throwaway home, but Hermes is using {get_hermes_home()}")
        cls.registry = registry
        manager = get_plugin_manager()
        manager.discover_and_load()  # now, so it can't happen later and change what is registered
        load_plugin()
        handlers, hooks, schemas = plugin_module("handlers"), plugin_module("hooks"), plugin_module("schemas")
        for schema, handler in ((schemas.APP_LIST, handlers.app_list), (schemas.APP_GRANT, handlers.app_grant)):
            registry.register(name=schema["name"], toolset="app_platform", schema=schema, handler=handler,
                              check_fn=handlers.is_available)
        cls.hook_list = [("pre_tool_call", hooks.require_grant_approval), ("post_approval_response", hooks.record_approval)]
        for name, callback in cls.hook_list:
            manager._hooks.setdefault(name, []).append(callback)
        cls.manager = manager

    @classmethod
    def tearDownClass(cls):
        for name, callback in cls.hook_list:
            cls.manager._hooks[name].remove(callback)

    def setUp(self):
        super().setUp()
        self.keeper = self.start_gatekeeper()
        self.write_config(notify_target=f"telegram:{OWNER_CHAT}")
        self.answers = []
        environment = mock.patch.dict(os.environ, {"HERMES_INTERACTIVE": "1", "TELEGRAM_BOT_TOKEN": FAKE_TOKEN})
        environment.start()
        self.addCleanup(environment.stop)
        # The last step before the network. Everything above it in send_message_tool is the real code.
        self.send = mock.AsyncMock(return_value={"success": True, "platform": "telegram", "chat_id": OWNER_CHAT, "message_id": "1"})
        sender = mock.patch("tools.send_message_tool._send_telegram", self.send)
        sender.start()
        self.addCleanup(sender.stop)

    def dispatch_like_hermes(self, tool, args):
        """What the tool executor does: hooks and approval first, then the registry, unless blocked."""
        from hermes_cli.plugins import _dispatch_pre_tool_call_hooks
        from tools.terminal_tool import set_approval_callback  # the CLI's callback answers the gate here

        set_approval_callback(lambda *a, **k: self.answers.pop(0))
        block, modified = _dispatch_pre_tool_call_hooks(tool, args, task_id="t", session_id="s", tool_call_id="c", turn_id="u")
        if block is not None:
            return {"blocked": block}
        return json.loads(self.registry.dispatch(tool, modified if modified is not None else args))

    def grant_in_a_tool_worker(self):
        """As in the gateway: an inbound task, an executor thread, then the tool's worker thread."""
        from tools.thread_context import propagate_context_to_thread

        async def inbound_message():
            bind_session(user_id="user-1", user_name="Ada")

            def turn():
                holder = {}
                worker = propagate_context_to_thread(lambda: holder.update(result=self.dispatch_like_hermes(
                    "app_grant", {"name": "myapp", "emails": [ALICE]})))
                thread = threading.Thread(target=worker)
                thread.start()
                thread.join()
                return holder["result"]

            return await asyncio.get_running_loop().run_in_executor(None, contextvars.copy_context().run, turn)

        self.answers = ["once"]
        return asyncio.run(inbound_message())

    def test_send_message_is_not_a_tool_but_the_function_exists(self):
        from tools.send_message_tool import send_message_tool

        self.assertNotIn("send_message", self.registry.get_all_tool_names())
        self.assertTrue(callable(send_message_tool))

    def test_owner_notice_goes_through_real_send_code(self):
        result = self.grant_in_a_tool_worker()
        self.assertEqual(result["status"], "granted", result)
        self.assertIs(result["owner_notified"], True, result)
        self.send.assert_awaited_once()
        token, chat_id, message = self.send.await_args.args[:3]
        self.assertEqual((token, str(chat_id)), (FAKE_TOKEN, OWNER_CHAT))
        for part in ("Ada", "telegram:user-1", "myapp", ALICE):
            self.assertIn(part, message)

    def test_failed_send_reports_false_and_keeps_the_grant(self):
        self.send.return_value = {"error": "telegram said no"}
        result = self.grant_in_a_tool_worker()
        self.assertEqual(result["status"], "granted", result)
        self.assertIs(result["owner_notified"], False, result)

    def test_unconfigured_platform_reports_false(self):
        with mock.patch.dict(os.environ):
            del os.environ["TELEGRAM_BOT_TOKEN"]
            result = self.grant_in_a_tool_worker()
        self.assertIs(result["owner_notified"], False, result)
        self.send.assert_not_awaited()

    def test_each_sender_in_a_tool_worker_thread(self):
        from tools.thread_context import propagate_context_to_thread

        async def one_message(user_id):
            bind_session(user_id=user_id, user_name=user_id)

            def turn():
                holder = {}
                worker = propagate_context_to_thread(lambda: holder.update(result=self.registry.dispatch("app_list", {})))
                thread = threading.Thread(target=worker)
                thread.start()
                thread.join()
                return holder["result"]

            return await asyncio.get_running_loop().run_in_executor(None, contextvars.copy_context().run, turn)

        async def run_all(users):
            return await asyncio.gather(*(asyncio.create_task(one_message(user)) for user in users))

        users = [f"user-{i}" for i in range(8)]
        asyncio.run(run_all(users))
        self.assertEqual(sorted(r["requested_by"] for r in self.keeper.requests), [f"telegram:{u}" for u in users])

    def test_approve_and_deny_through_the_real_gate(self):
        bind_session(user_id="user-1", user_name="Ada")
        args = {"name": "myapp", "emails": [ALICE]}
        self.answers = ["deny"]
        self.assertIn("blocked", self.dispatch_like_hermes("app_grant", args))
        self.assertEqual(self.keeper.requests, [])
        self.answers = ["once"]
        self.assertEqual(self.dispatch_like_hermes("app_grant", args)["status"], "granted")
        self.assertEqual(self.keeper.requests[0]["emails"], [ALICE])

    def test_approvals_off_is_refused_by_the_handler(self):
        bind_session(user_id="user-1")
        with mock.patch("tools.approval.approval_context._get_approval_mode", return_value="off"):
            result = self.dispatch_like_hermes("app_grant", {"name": "myapp", "emails": [ALICE]})
        self.assertIn("no person approved", result["error"])
        self.assertEqual(self.keeper.requests, [])

    def test_address_real_redaction_would_mask_is_refused(self):
        bind_session(user_id="user-1")
        result = self.dispatch_like_hermes("app_grant", {"name": "myapp", "emails": ["alice+12345678@gmail.com"]})
        self.assertIn("hide part", result["blocked"])
        self.assertEqual(self.keeper.requests, [])

    def test_plugin_loads_against_real_modules(self):
        self.assertTrue(callable(load_plugin().register))


if __name__ == "__main__":
    unittest.main()
