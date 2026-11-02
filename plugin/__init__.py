"""app_platform: publish AI-built apps and manage guests. Registration only; no I/O happens here."""

from __future__ import annotations

from pathlib import Path

from . import handlers, hooks, schemas


def register(ctx):
    for schema, handler in (
        (schemas.APP_PUBLISH, handlers.app_publish),
        (schemas.APP_UNPUBLISH, handlers.app_unpublish),
        (schemas.APP_LIST, handlers.app_list),
        (schemas.APP_GRANT, handlers.app_grant),
        (schemas.APP_REVOKE, handlers.app_revoke),
    ):
        ctx.register_tool(
            name=schema["name"],
            toolset="app_platform",
            schema=schema,
            handler=handler,
            check_fn=handlers.is_available,
        )
    ctx.register_hook("pre_tool_call", hooks.require_grant_approval)
    ctx.register_hook("post_approval_response", hooks.record_approval)
    ctx.register_skill("app-hosting", Path(__file__).parent / "skills" / "app-hosting" / "SKILL.md")
