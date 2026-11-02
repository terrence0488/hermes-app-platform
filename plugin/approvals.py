"""Proof that a person approved one exact grant.

Hermes skips the approval prompt, and reports approved, when YOLO or ``approvals.mode: off`` is on,
and it runs a tool anyway if a hook raises. So the handler doesn't rely on having been reached.
The hook opens a ticket for the exact sender, app and addresses. Hermes's observer hook marks the
ticket only when a person answers its prompt with an approval. The handler spends one marked ticket.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass

TICKET_SECONDS = 1800  # longer than the default five-minute approval wait
_RULE_PREFIX = "app_grant:"
_PATTERN_PREFIX = "plugin_rule:"
# Hermes also reports "deny", "timeout", "cancelled", "notify_failed" and more. Only these are a yes.
_APPROVING_CHOICES = frozenset({"once", "session", "always"})


@dataclass
class _Ticket:
    digest: str
    expires: float
    approved: bool = False


_lock = threading.Lock()
_tickets: dict[str, _Ticket] = {}


def digest_for(sender_key: str, name: str, emails: list[str]) -> str:
    payload = json.dumps([sender_key, name, sorted(emails)], separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _drop_expired(now: float) -> None:
    for key in [key for key, ticket in _tickets.items() if ticket.expires <= now]:
        del _tickets[key]


def open_ticket(digest: str) -> str:
    """Return a rule key used once. An "always" answer stored under it can never match a later grant."""
    nonce = secrets.token_hex(16)
    now = time.monotonic()
    with _lock:
        _drop_expired(now)
        _tickets[nonce] = _Ticket(digest=digest, expires=now + TICKET_SECONDS)
    return f"{_RULE_PREFIX}{nonce}"


def record_answer(pattern_key: object, choice: object) -> None:
    if not isinstance(pattern_key, str) or not pattern_key.startswith(_PATTERN_PREFIX + _RULE_PREFIX):
        return
    nonce = pattern_key[len(_PATTERN_PREFIX + _RULE_PREFIX):]
    with _lock:
        ticket = _tickets.get(nonce)
        if ticket is None:
            return
        if isinstance(choice, str) and choice in _APPROVING_CHOICES:
            ticket.approved = True
        else:
            del _tickets[nonce]


def spend_approval(digest: str) -> bool:
    """True once for each approval of exactly this sender, app and set of addresses."""
    now = time.monotonic()
    with _lock:
        _drop_expired(now)
        for nonce, ticket in _tickets.items():
            if ticket.approved and ticket.digest == digest:
                del _tickets[nonce]
                return True
    return False


def clear() -> None:
    with _lock:
        _tickets.clear()
