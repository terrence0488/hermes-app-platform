"""Tool handlers. Each one takes the sender from the session, never from its arguments."""

from __future__ import annotations

import json
import logging
from typing import Any

from . import approvals
from .config import ConfigError, load_config
from .identity import IdentityError, Sender, sender_from_session
from .gatekeeper_client import GatekeeperError, submit
from .validation import app_name, email_list

logger = logging.getLogger(__name__)

_HANDLED = (ConfigError, IdentityError, ValueError, GatekeeperError)


def _error(message: object) -> str:
    return json.dumps({"error": str(message)})


def is_available() -> bool:
    """Hide the tools from the model when the config cannot be used. Makes no network calls."""
    try:
        load_config()
    except ConfigError as exc:
        logger.warning("app_platform tools are disabled: %s", exc)
        return False
    return True


def _notify_owner(target: str, sender: Sender, name: str, url: object, added: list[str]) -> bool:
    """Tell the owner who added whom. The grant has happened by now, so a failure is reported, not undone."""
    message = (f"App guest added.\nApp: {name} ({url})\nAdded by: {sender.name} ({sender.key})\n"
               f"Guests: {', '.join(added)}")
    try:
        # send_message is deliberately not a registered tool, so ctx.dispatch_tool can't reach it. This is
        # the function `hermes send` calls. It runs in this process with the gateway's own config.
        from tools.send_message_tool import send_message_tool

        result = json.loads(send_message_tool({"action": "send", "target": target, "message": message}))
    except Exception:
        logger.exception("could not notify the owner about a grant")
        return False
    if isinstance(result, dict) and result.get("success") and not result.get("error"):
        return True
    logger.error("could not notify the owner about a grant: %s", result.get("error") if isinstance(result, dict) else result)
    return False


def app_publish(args: dict, **kwargs: Any) -> str:
    try:
        config = load_config()
        sender = sender_from_session(config)
        name = app_name(args.get("name"))
        port = args.get("port")
        if isinstance(port, bool) or not isinstance(port, int):
            raise ValueError("'port' must be an integer")
        result = submit(config, "publish", sender.key, name=name, port=port)
        return json.dumps({"status": "published", "access": "team only until guests are added", **result})
    except _HANDLED as exc:
        return _error(exc)
    except Exception:
        logger.exception("app_publish failed")
        return _error("app_publish failed unexpectedly")


def app_unpublish(args: dict, **kwargs: Any) -> str:
    try:
        config = load_config()
        sender = sender_from_session(config)
        result = submit(config, "unpublish", sender.key, name=app_name(args.get("name")))
        return json.dumps({"status": "unpublished", **result})
    except _HANDLED as exc:
        return _error(exc)
    except Exception:
        logger.exception("app_unpublish failed")
        return _error("app_unpublish failed unexpectedly")


def app_list(args: dict, **kwargs: Any) -> str:
    try:
        config = load_config()
        sender = sender_from_session(config)
        return json.dumps(submit(config, "list", sender.key))
    except _HANDLED as exc:
        return _error(exc)
    except Exception:
        logger.exception("app_list failed")
        return _error("app_list failed unexpectedly")


def app_grant(args: dict, **kwargs: Any) -> str:
    try:
        config = load_config()
        sender = sender_from_session(config)
        name = app_name(args.get("name"))
        emails = email_list(args.get("emails"))
        # Bound to what was shown: another plugin rewriting the arguments after approval fails here.
        if not approvals.spend_approval(approvals.digest_for(sender.key, name, emails)):
            return _error("Nobody was added: no person approved this exact request. Hermes grants need a person to "
                          "tap approve, so they are refused while YOLO or approvals.mode off is on.")
        result = submit(config, "grant", sender.key, name=name, emails=emails)
        added = result.get("added") if isinstance(result.get("added"), list) else []
        notified = _notify_owner(config.notify_target, sender, name, result.get("url"), added) if added else None
        return json.dumps({"status": "granted", **result, "owner_notified": notified})
    except _HANDLED as exc:
        return _error(exc)
    except Exception:
        logger.exception("app_grant failed")
        return _error("app_grant failed unexpectedly")


def app_revoke(args: dict, **kwargs: Any) -> str:
    try:
        config = load_config()
        sender = sender_from_session(config)
        result = submit(config, "revoke", sender.key, name=app_name(args.get("name")), emails=email_list(args.get("emails")))
        return json.dumps({"status": "revoked", **result})
    except _HANDLED as exc:
        return _error(exc)
    except Exception:
        logger.exception("app_revoke failed")
        return _error("app_revoke failed unexpectedly")
