"""Prove the sender and approval paths against real Hermes code. Skipped unless run inside a Hermes install.

NOT RUN YET: this file was written from the v0.22.5 source but has never been executed. Run it with the
Hermes interpreter, then fix anything it finds before relying on it:

    cd <hermes-checkout>
    APP_PLATFORM_REAL_HERMES=1 <hermes-venv>/bin/python -m unittest discover -s <repo>/tests -p 'test_hermes_integration.py'

It uses temporary folders and a fake gatekeeper. It does not touch a real gateway, the registry, Telegram
or the model. It covers the real session context, the real thread-propagation helper tool batches use,
the real tool registry dispatch, and the real hook dispatch and approval gate.
"""

import asyncio
import contextvars
import json
import os
import threading
import unittest
from unittest import mock

from plugin_support import PluginTestCase, bind_session, load_plugin, plugin_module, using_real_hermes

ALICE = "alice@gmail.com"


@unittest.skipUnless(using_real_hermes(), "set APP_PLATFORM_REAL_HERMES=1 and use the Hermes interpreter")
class RealHermes(PluginTestCase):
    def setUp(self):
        super().setUp()
        from hermes_cli.plugins import get_plugin_manager
        from tools.registry import registry

        self.keeper = self.start_gatekeeper()
        self.registry = registry
        schemas = plugin_module("schemas")
        for schema, handler in ((schemas.APP_LIST, self.handlers.app_list), (schemas.APP_GRANT, self.handlers.app_grant)):
            registry.register(name=schema["name"], toolset="app_platform", schema=schema, handler=handler,
                              check_fn=self.handlers.is_available, override=True)
        hooks = get_plugin_manager()._hooks
        for name, callback in (("pre_tool_call", self.hooks.require_grant_approval),
                               ("post_approval_response", self.hooks.record_approval)):
            hooks.setdefault(name, []).append(callback)
            self.addCleanup(hooks[name].remove, callback)
        self.answers = []
        environment = mock.patch.dict(os.environ, {"HERMES_INTERACTIVE": "1"})
        environment.start()
        self.addCleanup(environment.stop)

    def dispatch_like_hermes(self, tool, args):
        """What the tool executor does: hooks and approval first, then the registry, unless blocked."""
        from hermes_cli.plugins import _dispatch_pre_tool_call_hooks
        from tools.terminal_tool import set_approval_callback  # the CLI's callback answers the gate here

        set_approval_callback(lambda *a, **k: self.answers.pop(0))
        block, modified = _dispatch_pre_tool_call_hooks(tool, args, task_id="t", session_id="s", tool_call_id="c", turn_id="u")
        if block is not None:
            return {"blocked": block}
        return json.loads(self.registry.dispatch(tool, modified if modified is not None else args))

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
