"""Work out who is talking to Hermes, from data the model cannot touch.

The sender always comes from the session Hermes bound for the inbound message. Tool arguments are
never consulted. Anything uncertain is refused rather than attributed to a guess.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from .config import Config

_MAX_NAME_CHARS = 64
# The gatekeeper refuses any other shape, so a strange id is stopped here with a clearer message.
_PLATFORM_RE = re.compile(r"[a-z0-9_.-]{1,32}")
_USER_ID_RE = re.compile(r"[A-Za-z0-9_.@:+=-]{1,128}")


class IdentityError(Exception):
    """No trustworthy sender for this call. The message is safe to show to the model."""


@dataclass(frozen=True)
class Sender:
    platform: str
    user_id: str
    name: str

    @property
    def key(self) -> str:
        """Stable identity. Platform ids alone can collide."""
        return f"{self.platform}:{self.user_id}"


def clean_display_name(name: str) -> str:
    """Display names are chosen by users, so drop control and format characters and cap the length."""
    kept = "".join(ch for ch in name if unicodedata.category(ch) not in ("Cc", "Cf", "Zl", "Zp"))
    return kept.strip()[:_MAX_NAME_CHARS]


def sender_from_session(config: Config) -> Sender:
    """Read the sender bound to the current turn."""
    try:
        from gateway.session_context import get_session_env, session_context_engaged
    except ImportError:
        raise IdentityError("the app platform needs the Hermes gateway session context") from None
    # get_session_env falls back to os.environ when a task has no binding. Before any session is
    # bound, an environment value is all it could return, and that is not a verified sender.
    if not session_context_engaged():
        raise IdentityError("the app platform needs an identified sender, and this session has none")
    platform = get_session_env("HERMES_SESSION_PLATFORM", "").strip().lower()
    user_id = get_session_env("HERMES_SESSION_USER_ID", "").strip()
    name = get_session_env("HERMES_SESSION_USER_NAME", "")
    if not platform or not user_id:
        raise IdentityError("the app platform needs an identified sender, and this session has none")
    if platform not in config.allowed_platforms:
        raise IdentityError(f"the app platform is not enabled for platform '{platform}'")
    if not _PLATFORM_RE.fullmatch(platform) or not _USER_ID_RE.fullmatch(user_id):
        raise IdentityError("the app platform cannot record this sender's id")
    return Sender(platform=platform, user_id=user_id, name=clean_display_name(name) or user_id)
