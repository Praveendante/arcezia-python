"""
AutoGen integration for Arcezia (SaaS client).

All verification runs in Arcezia's secure cloud via the proprietary engine.
The API surface is stable, so your integration code stays unchanged.

Supports both major AutoGen generations:

  AutoGen 0.2 (ConversableAgent, sync):
    guard.wrap() / guard.wrap_many()

  AutoGen 0.4 / autogen-agentchat (FunctionTool, async):
    guard.wrap_async() / guard.wrap_many_async() / guard.wrap_sync_as_async()

─────────────────────────────────────────────────────────────────────
AutoGen 0.2 example:

    from arcezia import Arcezia
    from arcezia.integrations.autogen import ArceziaAutoGenGuard

    az    = Arcezia(api_key="ar_live_...", task="migrate the users table")
    guard = ArceziaAutoGenGuard(az)

    safe_execute_sql = guard.wrap("execute_sql", db.execute, domain="database_ops")

    @user_proxy.register_for_execution()
    @assistant.register_for_llm(description="Execute a SQL query")
    def execute_sql(query: str) -> str:
        return safe_execute_sql(query=query)

─────────────────────────────────────────────────────────────────────
AutoGen 0.4 example:

    from arcezia import Arcezia
    from arcezia.integrations.autogen import ArceziaAutoGenGuard
    from autogen_core.tools import FunctionTool

    az    = Arcezia(api_key="ar_live_...", task="migrate the users table")
    guard = ArceziaAutoGenGuard(az)

    async def execute_sql(query: str) -> str:
        return await db.execute(query)

    safe_execute_sql = guard.wrap_async("execute_sql", execute_sql, domain="database_ops")
    tool  = FunctionTool(safe_execute_sql, description="Execute SQL against the database")
    agent = AssistantAgent("sql_agent", tools=[tool], model_client=model_client)

─────────────────────────────────────────────────────────────────────
Multi-tool example:

    safe_fns = guard.wrap_many([
        ("execute_sql",  execute_sql,  "database_ops"),
        ("write_file",   write_file,   "filesystem_ops"),
        ("send_email",   send_email,   "agent_action"),
    ])

Beyond Level 1
--------------
This adapter implements Level 1 (every tool call gated). Levels 2-4 are
reached through ``guard.az`` — the same Arcezia client, no private access:

    guard = ArceziaAutoGenGuard(az)

    # Level 2 — verify the whole plan before running any of it
    result = guard.az.verify_chain({"steps": [
        {"step_id": "s1", "action_type": "execute_sql",
         "domain": "database_ops", "action_description": "SELECT ..."},
    ]})
    if result["overall_verdict"] != "SAFE":
        abort(result["blocked_at"])        # the step_id that failed

    # Post-execution audit
    guard.az.verify_outcome(action_type="execute_sql",
                          action_description="DELETE FROM orders ...",
                          outcome={"rows_affected": 50000},
                          expected={"rows_affected": 1})

    # Level 3 — ground human intent (a model cannot forge this)
    guard.az.authorize(token=user_approval_token)

Levels explained in full: ``help(arcezia)`` or https://arcezia.com/docs

"""
from __future__ import annotations

import asyncio
import functools
from typing import Any, Callable, Coroutine

from arcezia.client import Arcezia, ArceziaUnavailableError
from arcezia.integrations._common import coerce_az


# Domain inference from tool/function name
_DOMAIN_MAP: dict[str, str] = {
    "sql":      "database_ops",
    "query":    "database_ops",
    "db":       "database_ops",
    "database": "database_ops",
    "postgres": "database_ops",
    "mysql":    "database_ops",
    "file":     "filesystem_ops",
    "shell":    "filesystem_ops",
    "bash":     "filesystem_ops",
    "terminal": "filesystem_ops",
    "git":      "filesystem_ops",
    "execute":  "filesystem_ops",
    "email":    "agent_action",
    "gmail":    "agent_action",
    "slack":    "agent_action",
    "send":     "agent_action",
    "deploy":   "agent_action",
    "api":      "agent_action",
    "http":     "agent_action",
    "post":     "agent_action",
}


def _infer_domain(name: str) -> str:
    lower = name.lower()
    for kw, domain in _DOMAIN_MAP.items():
        if kw in lower:
            return domain
    return "agent_action"


def _describe_call(name: str, args: tuple, kwargs: dict) -> str:
    parts = [repr(a)[:80] for a in args]
    parts += [f"{k}={v!r}"[:80] for k, v in kwargs.items()]
    return f"{name}({', '.join(parts)[:300]})"


class ArceziaAutoGenGuard:
    """
    Arcezia safety guard for AutoGen agents (SaaS client).

    One instance per agent session. All calls go to the Arcezia API.
    Compatible with both AutoGen 0.2 (sync) and AutoGen 0.4 (async).
    """

    def __init__(self, az: Arcezia = None, *, api_key=None, task=None, api_url=None, capability_envelope=None):
        self.az = coerce_az(az, api_key=api_key, task=task, api_url=api_url,
                       capability_envelope=capability_envelope)

    # ── AutoGen 0.2 — synchronous ──────────────────────────────────────

    def wrap(
        self,
        name: str,
        fn: Callable,
        domain: str | None = None,
    ) -> Callable:
        """
        Return a sync wrapper that calls Arcezia before executing fn.
        Raises RuntimeError on BLOCK or REVIEW.
        """
        effective_domain = domain or _infer_domain(name)

        @functools.wraps(fn)
        def _guarded(*args, **kwargs):
            cert = self.az.verify(
                action_type=name,
                action_description=_describe_call(name, args, kwargs),
                domain=effective_domain,
            )
            if cert.block:
                msg = (
                    f"[Arcezia BLOCK] {cert.summary} | "
                    f"trust={cert.trust_score:.0%}"
                )
                if cert.fabrication_detected:
                    msg += f" | FABRICATION: {cert.fabricated_constraints}"
                if cert.violated:
                    msg += f" | Violated: {', '.join(cert.violated)}"
                raise RuntimeError(msg)
            if cert.review:
                raise RuntimeError(
                    f"[Arcezia REVIEW] Human confirmation required before "
                    f"'{name}' can execute. {cert.summary} | "
                    f"Missing evidence: {', '.join(cert.missing)}"
                )
            if cert.degraded:
                raise ArceziaUnavailableError(
                    RuntimeError(
                        f"Degraded certificate (unverified): {cert.summary}. "
                        "The action was not verified by the engine."
                    )
                )
            return fn(*args, **kwargs)

        return _guarded

    def wrap_many(
        self,
        fns: list[tuple[str, Callable, str | None]],
    ) -> dict[str, Callable]:
        """Wrap multiple functions at once. Returns {name: guarded_callable}."""
        return {name: self.wrap(name, fn, domain) for name, fn, domain in fns}

    # ── AutoGen 0.4 — async ────────────────────────────────────────────

    def wrap_async(
        self,
        name: str,
        fn: Callable[..., Coroutine],
        domain: str | None = None,
    ) -> Callable[..., Coroutine]:
        """
        Return an async wrapper for AutoGen 0.4 FunctionTool.
        The Arcezia HTTP call runs in a thread pool via asyncio.to_thread().
        Raises RuntimeError on BLOCK or REVIEW.
        """
        effective_domain = domain or _infer_domain(name)

        @functools.wraps(fn)
        async def _guarded_async(*args, **kwargs):
            cert = await asyncio.to_thread(
                self.az.verify,
                action_type=name,
                action_description=_describe_call(name, args, kwargs),
                domain=effective_domain,
            )
            if cert.block:
                msg = (
                    f"[Arcezia BLOCK] {cert.summary} | "
                    f"trust={cert.trust_score:.0%}"
                )
                if cert.fabrication_detected:
                    msg += f" | FABRICATION: {cert.fabricated_constraints}"
                if cert.violated:
                    msg += f" | Violated: {', '.join(cert.violated)}"
                raise RuntimeError(msg)
            if cert.review:
                raise RuntimeError(
                    f"[Arcezia REVIEW] Human confirmation required before "
                    f"'{name}' can execute. {cert.summary} | "
                    f"Missing evidence: {', '.join(cert.missing)}"
                )
            if cert.degraded:
                raise ArceziaUnavailableError(
                    RuntimeError(
                        f"Degraded certificate (unverified): {cert.summary}. "
                        "The action was not verified by the engine."
                    )
                )
            return await fn(*args, **kwargs)

        return _guarded_async

    def wrap_sync_as_async(
        self,
        name: str,
        fn: Callable,
        domain: str | None = None,
    ) -> Callable[..., Coroutine]:
        """
        Wrap a synchronous fn as async for AutoGen 0.4 FunctionTool.
        Both the Arcezia call and the function execution run in a thread pool.
        """
        effective_domain = domain or _infer_domain(name)

        @functools.wraps(fn)
        async def _guarded_as_async(*args, **kwargs):
            cert = await asyncio.to_thread(
                self.az.verify,
                action_type=name,
                action_description=_describe_call(name, args, kwargs),
                domain=effective_domain,
            )
            if cert.block:
                msg = (
                    f"[Arcezia BLOCK] {cert.summary} | "
                    f"trust={cert.trust_score:.0%}"
                )
                if cert.fabrication_detected:
                    msg += f" | FABRICATION: {cert.fabricated_constraints}"
                raise RuntimeError(msg)
            if cert.review:
                raise RuntimeError(
                    f"[Arcezia REVIEW] Human confirmation required: "
                    f"{cert.summary} | Missing: {', '.join(cert.missing)}"
                )
            if cert.degraded:
                raise ArceziaUnavailableError(
                    RuntimeError(
                        f"Degraded certificate (unverified): {cert.summary}. "
                        "The action was not verified by the engine."
                    )
                )
            return await asyncio.to_thread(fn, *args, **kwargs)

        return _guarded_as_async

    def wrap_many_async(
        self,
        fns: list[tuple[str, Callable, str | None]],
    ) -> dict[str, Callable[..., Coroutine]]:
        """Wrap multiple async functions at once."""
        return {name: self.wrap_async(name, fn, domain) for name, fn, domain in fns}
