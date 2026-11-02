"""Hand a request to the root gatekeeper and wait for its answer.

Requests go into a folder only this user can reach. A file appears in new/ only once it is complete,
because the gatekeeper removes anything it finds there.
"""

from __future__ import annotations

import json
import os
import time
import uuid

from .config import Config

_POLL_SECONDS = 0.1


class GatekeeperError(Exception):
    """The gatekeeper refused the request or did not answer. The message is safe to show to the model."""


def submit(config: Config, action: str, requested_by: str, **fields: object) -> dict:
    request_id = uuid.uuid4().hex
    body = json.dumps({"id": request_id, "action": action, "requested_by": requested_by, **fields})
    temporary = config.inbox_dir / "tmp" / f"{request_id}.json"
    final = config.inbox_dir / "new" / f"{request_id}.json"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(body)
        os.rename(temporary, final)
    except OSError:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise GatekeeperError("could not write the request; the app platform may not be installed") from None
    return _wait_for_result(config, request_id)


def _wait_for_result(config: Config, request_id: str) -> dict:
    path = config.result_dir / f"{request_id}.json"
    deadline = time.monotonic() + config.result_timeout_seconds
    while True:
        try:
            with open(path, encoding="utf-8") as file:
                result = json.load(file)
            break
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            raise GatekeeperError("could not read the gatekeeper's answer") from None
        if time.monotonic() >= deadline:
            raise GatekeeperError(
                f"the gatekeeper did not answer within {config.result_timeout_seconds:g} seconds, so the outcome "
                "is unknown. Check with app_list before trying again.")
        time.sleep(_POLL_SECONDS)
    if not isinstance(result, dict) or result.get("id") != request_id:
        raise GatekeeperError("the gatekeeper's answer was not for this request")
    if result.get("status") != "ok":
        raise GatekeeperError(str(result.get("reason") or "the gatekeeper refused the request"))
    return {key: value for key, value in result.items() if key not in ("id", "status", "at")}
