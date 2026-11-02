"""Test helpers for the plugin: a stand-in for the Hermes session API and approval gate.

Tests run on the standard library alone and never need Hermes. ``FakeGate`` copies the behaviour of
``_dispatch_pre_tool_call_hooks`` and ``_run_approval_gate`` as read from the v0.22.5 source; it does
not run them. ``test_hermes_integration.py`` checks the same path against real Hermes code.
"""

from __future__ import annotations

import contextvars
import importlib.util
import json
import logging
import os
import re
import stat
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN_DIR = ROOT / "plugin"
PACKAGE = "app_platform_under_test"

logging.getLogger(PACKAGE).setLevel(logging.CRITICAL)  # refusals are asserted, not printed

_UNSET = object()
_VARS = {name: contextvars.ContextVar(name, default=_UNSET)
         for name in ("HERMES_SESSION_PLATFORM", "HERMES_SESSION_USER_ID", "HERMES_SESSION_USER_NAME")}
_engaged = False


def _get_session_env(name, default=""):
    value = _VARS[name].get() if name in _VARS else _UNSET
    return os.getenv(name, default) if value is _UNSET else value


def _session_context_engaged():
    return _engaged


def using_real_hermes() -> bool:
    return os.environ.get("APP_PLATFORM_REAL_HERMES") == "1"


def _install_fake_hermes() -> None:
    gateway = types.ModuleType("gateway")
    gateway.__path__ = []
    session_context = types.ModuleType("gateway.session_context")
    session_context.get_session_env = _get_session_env
    session_context.session_context_engaged = _session_context_engaged
    gateway.session_context = session_context
    constants = types.ModuleType("hermes_constants")
    constants.get_hermes_home = lambda: tempfile.gettempdir()
    # send_message is not a registered tool in Hermes: the plugin imports this function, as `hermes send` does.
    tools = types.ModuleType("tools")
    tools.__path__ = []
    send_module = types.ModuleType("tools.send_message_tool")
    send_module.send_message_tool = lambda args, **kwargs: json.dumps({"error": "no notifier in this test"})
    tools.send_message_tool = send_module
    sys.modules.update({"tools": tools, "tools.send_message_tool": send_module})
    agent = types.ModuleType("agent")
    agent.__path__ = []
    redact = types.ModuleType("agent.redact")
    # One pattern copied from agent/redact.py in v0.22.5: the one an email address can trip.
    redact.redact_sensitive_text = lambda text, **kwargs: re.sub(r"(\+[1-9]\d{6,14})(?![A-Za-z0-9])", "+***", text)
    agent.redact = redact
    sys.modules.update({"gateway": gateway, "gateway.session_context": session_context, "hermes_constants": constants,
                        "agent": agent, "agent.redact": redact})


if not using_real_hermes():
    _install_fake_hermes()


def load_plugin():
    """Import the plugin the way Hermes does: a package under a private name."""
    if PACKAGE in sys.modules:
        return sys.modules[PACKAGE]
    spec = importlib.util.spec_from_file_location(
        PACKAGE, PLUGIN_DIR / "__init__.py", submodule_search_locations=[str(PLUGIN_DIR)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[PACKAGE] = module
    spec.loader.exec_module(module)
    return module


def plugin_module(name: str):
    load_plugin()
    return sys.modules[f"{PACKAGE}.{name}"]


def bind_session(platform="telegram", user_id="", user_name="") -> None:
    """Bind the sender for the current context, as the gateway does for each inbound message."""
    global _engaged
    if using_real_hermes():
        from gateway.session_context import set_session_vars

        set_session_vars(platform=platform, user_id=user_id, user_name=user_name)
        return
    _engaged = True
    _VARS["HERMES_SESSION_PLATFORM"].set(platform)
    _VARS["HERMES_SESSION_USER_ID"].set(user_id)
    _VARS["HERMES_SESSION_USER_NAME"].set(user_name)


def unbind_session() -> None:
    """Return to a process in which no session was ever bound."""
    global _engaged
    if using_real_hermes():
        from gateway.session_context import reset_session_vars

        reset_session_vars()
        return
    _engaged = False
    for var in _VARS.values():
        var.set(_UNSET)


class FakeGatekeeper:
    """Answers requests from a temp inbox with a canned reply, and records them."""

    def __init__(self, inbox: Path, results: Path):
        self.inbox, self.results = inbox, results
        self.requests: list[dict] = []
        self.reply = lambda request: {"status": "ok", "name": request.get("name"), "url": "https://x.example.net",
                                      "added": request.get("emails", []), "already": []}
        self.silent = False
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.wait(0.01):
            for path in (self.inbox / "new").glob("*.json"):
                request = json.loads(path.read_text())
                self.requests.append(request)
                path.unlink()
                if self.silent:
                    continue
                body = {"id": request["id"], "at": "now", **self.reply(request)}
                temporary = self.results / f".{request['id']}.tmp"
                temporary.write_text(json.dumps(body))
                temporary.rename(self.results / f"{request['id']}.json")

    def close(self):
        self._stop.set()
        self._thread.join()


class FakeGate:
    """Runs a tool call as Hermes does: pre_tool_call hook, approval gate, observer hook, handler."""

    def __init__(self, hooks):
        self.hooks = hooks
        self.answer = "once"  # what the person taps; None means Hermes skips the prompt (YOLO, approvals off)
        self.prompts: list[str] = []
        self.rule_keys: list[str] = []
        self.hook_raises = False

    def call(self, name: str, handler, args: dict, rewrite_args: dict | None = None) -> dict:
        try:
            if self.hook_raises:
                raise RuntimeError("hook failed")
            directive = self.hooks.require_grant_approval(tool_name=name, args=args, task_id="t")
        except RuntimeError:
            directive = None  # agent/tool_executor.py: "Hook failures never block."
        if directive and directive["action"] == "block":
            return {"blocked": directive["message"]}
        if directive and directive["action"] == "approve":
            self.prompts.append(directive["message"])
            self.rule_keys.append(directive["rule_key"])
            if self.answer is not None:
                self.hooks.record_approval(pattern_key=f"plugin_rule:{directive['rule_key']}", choice=self.answer,
                                           surface="gateway", session_key="s")
                if self.answer not in ("once", "session", "always"):
                    return {"blocked": f"BLOCKED: {self.answer}"}
        return json.loads(handler(rewrite_args if rewrite_args is not None else args))


class PluginTestCase(unittest.TestCase):
    """Each test gets a temp inbox and results folder, a fake gatekeeper and an unbound session."""

    def setUp(self):
        self.plugin = load_plugin()
        self.handlers = plugin_module("handlers")
        self.hooks = plugin_module("hooks")
        self.approvals = plugin_module("approvals")
        self.approvals.clear()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for sub in ("inbox/tmp", "inbox/new", "results"):
            (self.root / sub).mkdir(parents=True)
        self.config_file = self.root / "app_platform.json"
        self.write_config()
        previous = os.environ.get("APP_PLATFORM_CONFIG")
        os.environ["APP_PLATFORM_CONFIG"] = str(self.config_file)
        self.addCleanup(self._restore_env, previous)
        self.notifications: list[tuple] = []
        self.notify_result = json.dumps({"success": True})
        if not using_real_hermes():
            sys.modules["tools.send_message_tool"].send_message_tool = self._notifier
        self.gate = FakeGate(self.hooks)
        unbind_session()
        self.addCleanup(unbind_session)

    def _notifier(self, args, **kwargs):
        self.notifications.append(args)
        if isinstance(self.notify_result, Exception):
            raise self.notify_result
        return self.notify_result

    def start_gatekeeper(self) -> FakeGatekeeper:
        gatekeeper = FakeGatekeeper(self.root / "inbox", self.root / "results")
        self.addCleanup(gatekeeper.close)
        return gatekeeper

    @staticmethod
    def _restore_env(previous):
        if previous is None:
            os.environ.pop("APP_PLATFORM_CONFIG", None)
        else:
            os.environ["APP_PLATFORM_CONFIG"] = previous

    def write_config(self, **overrides):
        config = {"inbox_dir": str(self.root / "inbox"), "result_dir": str(self.root / "results"),
                  "allowed_platforms": ["telegram"], "notify_target": "telegram:owner-chat",
                  "result_timeout_seconds": 3}
        config.update(overrides)
        self.config_file.write_text(json.dumps(config))
        os.chmod(self.config_file, stat.S_IRUSR | stat.S_IWUSR)

    def call(self, handler, args) -> dict:
        result = handler(args)
        self.assertIsInstance(result, str, "handlers must return a JSON string")
        return json.loads(result)
