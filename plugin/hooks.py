"""Lifecycle hooks: send app_grant to a person for approval, and record the answer."""

from __future__ import annotations

import html
import logging
from typing import Any

from . import approvals
from .config import ConfigError, load_config
from .identity import IdentityError, sender_from_session
from .validation import app_name, email_list

logger = logging.getLogger(__name__)

# Hermes v0.22.5 cuts the approval reason to 300 escaped characters on Discord and 500 on Telegram
# and Slack. Past this size a person could approve addresses the prompt no longer shows.
MAX_PROMPT_CHARS = 300


def prompt_length(message: str) -> int:
    """Measure the worst case: after HTML escaping, in UTF-16 units as Telegram counts them."""
    return len(html.escape(message).encode("utf-16-le")) // 2


def prompt_text(name: str, emails: list[str]) -> str:
    lines = "\n".join(emails)
    return f"Let these people into app '{name}'?\n{lines}"


def shown_unchanged(message: str) -> bool:
    """Hermes masks secret-looking text in the prompt, such as the digits in alice+12345678@gmail.com.
    Nobody should approve an address they can't fully see, so check the prompt would arrive as written."""
    try:
        from agent.redact import redact_sensitive_text

        return redact_sensitive_text(message, force=True) == message
    except Exception:
        logger.exception("could not check the approval prompt")
        return False


def _block(message: str) -> dict:
    return {"action": "block", "message": message}


def require_grant_approval(tool_name: str = "", args: Any = None, **kwargs: Any) -> dict | None:
    """Ask a person to approve the exact app and addresses, or refuse before anyone is asked."""
    if tool_name != "app_grant":
        return None
    arguments = args if isinstance(args, dict) else {}
    try:
        config = load_config()
        sender = sender_from_session(config)
        name = app_name(arguments.get("name"))
        emails = email_list(arguments.get("emails"))
    except (ConfigError, IdentityError, ValueError) as exc:
        return _block(f"Nobody was added: {exc}")
    message = prompt_text(name, emails)
    if prompt_length(message) > MAX_PROMPT_CHARS:
        return _block("Nobody was added: that list is too long to show in full in the approval prompt. "
                      "Send fewer addresses at a time.")
    if not shown_unchanged(message):
        return _block("Nobody was added: Hermes would hide part of an address in the approval prompt, so it can't "
                      "be approved. Ask the user for the plain address.")
    rule_key = approvals.open_ticket(approvals.digest_for(sender.key, name, emails))
    return {"action": "approve", "message": message, "rule_key": rule_key}


def record_approval(pattern_key: Any = None, choice: Any = None, **kwargs: Any) -> None:
    approvals.record_answer(pattern_key, choice)
