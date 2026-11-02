"""Load and validate the plugin's JSON config file. It holds paths and ids, no secrets."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

CONFIG_FILENAME = "app_platform.json"
CONFIG_PATH_ENV = "APP_PLATFORM_CONFIG"
_TARGET_RE = re.compile(r"[a-z0-9_-]+:[A-Za-z0-9_.@:+=-]+")
_FIELDS = {"inbox_dir", "result_dir", "allowed_platforms", "notify_target", "result_timeout_seconds"}


class ConfigError(Exception):
    """The config file is missing, unsafe or invalid. The message is safe to show to the model."""


@dataclass(frozen=True)
class Config:
    inbox_dir: Path
    result_dir: Path
    allowed_platforms: frozenset[str]
    notify_target: str
    result_timeout_seconds: float


def config_path() -> Path:
    override = os.environ.get(CONFIG_PATH_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    from hermes_constants import get_hermes_home

    return Path(get_hermes_home()) / CONFIG_FILENAME


def load_config() -> Config:
    """Read the file on each call: it is small, and an edit applies with no restart."""
    path = config_path()
    try:
        info = os.stat(path)
        with open(path, encoding="utf-8") as file:
            raw = json.load(file)
    except FileNotFoundError:
        raise ConfigError(f"the app platform is not configured: {path} does not exist") from None
    except (OSError, ValueError):
        raise ConfigError(f"the app platform config {path} cannot be read") from None
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
        raise ConfigError(f"the app platform config {path} must be owned by this user and writable only by it")
    if not isinstance(raw, dict) or set(raw) - _FIELDS:
        raise ConfigError("the app platform config has unknown fields")
    inbox, results = raw.get("inbox_dir"), raw.get("result_dir")
    if not isinstance(inbox, str) or not os.path.isabs(inbox) or not isinstance(results, str) or not os.path.isabs(results):
        raise ConfigError("inbox_dir and result_dir must be absolute paths")
    platforms = raw.get("allowed_platforms")
    if not isinstance(platforms, list) or not platforms or not all(isinstance(p, str) and p for p in platforms):
        raise ConfigError("allowed_platforms must be a non-empty list")
    target = raw.get("notify_target")
    if not isinstance(target, str) or not _TARGET_RE.fullmatch(target) or "REPLACE_ME" in target:
        raise ConfigError("notify_target must look like telegram:<chat id>")
    timeout = raw.get("result_timeout_seconds", 15)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= 60:
        raise ConfigError("result_timeout_seconds must be between 1 and 60")
    return Config(Path(inbox), Path(results), frozenset(p.lower() for p in platforms), target, float(timeout))
