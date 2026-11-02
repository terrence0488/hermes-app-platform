"""Input checks. The gatekeeper repeats them all: these only give a quick, clear refusal, and make
sure the approval prompt shows exactly what the gatekeeper will be asked to do."""

from __future__ import annotations

import re

_NAME_RE = re.compile(r"[a-z][a-z0-9-]{1,30}")
_EMAIL_RE = re.compile(
    r"[a-z0-9_%+-]+(\.[a-z0-9_%+-]+)*"
    r"@([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])")
_MAX_EMAIL_CHARS = 254


def app_name(value: object) -> str:
    if not isinstance(value, str) or not _NAME_RE.fullmatch(value) or value.endswith("-") or "--" in value:
        raise ValueError("'name' must use lower case letters, digits and single hyphens, and start with a letter")
    return value


def normalize_email(value: object) -> str:
    """The one normalisation: ASCII only, lower-cased. The gatekeeper and router apply the same rule."""
    if not isinstance(value, str) or not value.isascii() or len(value) > _MAX_EMAIL_CHARS:
        raise ValueError("not a valid address")
    lowered = value.lower()
    if not _EMAIL_RE.fullmatch(lowered):
        raise ValueError("not a valid address")
    return lowered


def email_list(value: object) -> list[str]:
    """Normalised, without repeats, in the order given. Input that isn't valid is never repeated back."""
    if not isinstance(value, list) or not value:
        raise ValueError("'emails' must be a non-empty list of addresses")
    cleaned: list[str] = []
    for position, item in enumerate(value, 1):
        try:
            address = normalize_email(item)
        except ValueError:
            raise ValueError(f"email number {position} is not a valid address") from None
        if address not in cleaned:
            cleaned.append(address)
    return cleaned
