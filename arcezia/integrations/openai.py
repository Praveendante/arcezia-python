"""
OpenAI function-calling / tool-use integration for Arcezia (SaaS client).

All verification runs in Arcezia's secure cloud via the proprietary engine.
The API surface is stable, so your integration code stays unchanged.

Usage with OpenAI function calling:

    from arcezia import Arcezia
    from arcezia.integrations.openai import ArceziaGuard
    from openai import OpenAI

    az = Arcezia(api_key="ar_live_...", task="help user manage their database")
    guard = ArceziaGuard(az)

    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4o",
        tools=tools,
        messages=messages,
    )

    # Safe execution — Arcezia gates every tool call:
    result = guard.execute_tool_call(
        tool_call=response.choices[0].message.tool_calls[0],
        tool_implementations={"execute_sql": db.execute},
    )

Usage with CrewAI:

    from arcezia.integrations.openai import ArceziaCrewTool

    class SafeSQLTool(ArceziaCrewTool):
        az = your_arcezia_instance
        domain = "database_ops"
        name = "execute_sql"
        description = "Execute SQL against the database"

        def _run(self, sql: str) -> str:
            return db.execute(sql)

Beyond Level 1
--------------
This adapter implements Level 1 (every tool call gated). Levels 2-4 are
reached through ``guard.az`` — the same Arcezia client, no private access:

    guard = ArceziaGuard(api_key=..., task=...)

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

import functools
from typing import Any, Callable, ClassVar

from arcezia.client import ArceziaUnavailableError
from arcezia.integrations._common import coerce_az


# Domain routing: map function name patterns to Arcezia domains
_DOMAIN_MAP: dict[str, str] = {
    "sql":     "database_ops",
    "query":   "database_ops",
    "db":      "database_ops",
    "file":    "filesystem_ops",
    "shell":   "filesystem_ops",
    "bash":    "filesystem_ops",
    "git":     "filesystem_ops",
    "email":   "agent_action",
    "send":    "agent_action",
    "deploy":  "agent_action",
    "post":    "agent_action",
    "delete":  "agent_action",
}


def _infer_domain(name: str) -> str:
    name_lower = name.lower()
    for kw, domain in _DOMAIN_MAP.items():
        if kw in name_lower:
            return domain
    return "agent_action"


class ArceziaGuard:
    """
    Guards OpenAI function/tool calls with Arcezia verification.
    Works with any dict-based function call interface
    (OpenAI, Anthropic tool_use, etc.)
    """

    def __init__(self, az=None, *, api_key=None, task=None, api_url=None, capability_envelope=None):
        self._az = coerce_az(az, api_key=api_key, task=task, api_url=api_url,
                       capability_envelope=capability_envelope)

    @property
    def az(self):
        """The underlying Arcezia client.

        Level 1 (per-call gating) is handled by this adapter. Reach the client
        for everything above it — see the "Beyond Level 1" section in this
        module's docstring, or ``help(arcezia)`` for all four levels:

            .az.verify_chain(manifest)     # Level 2 — verify a whole plan
            .az.verify_outcome(...)        # post-execution audit
            .az.authorize(token)           # Level 3 — ground human intent
        """
        return self._az

    def execute_tool_call(
        self,
        tool_call: Any,
        tool_implementations: dict[str, Callable],
        domain_overrides: dict[str, str] | None = None,
    ) -> dict:
        """
        Execute an OpenAI tool_call safely.

        tool_call:             OpenAI ToolCall object (has .function.name + .function.arguments)
                               or a plain dict with "name" and "arguments" keys.
        tool_implementations:  {"function_name": callable}
        domain_overrides:      {"function_name": "database_ops"} overrides domain inference

        Returns: {"result": ..., "cert": ArceziaCertificate, "blocked": bool}
        """
        import json
        overrides = domain_overrides or {}

        # Handle both OpenAI object and dict
        if hasattr(tool_call, "function"):
            fn_name = tool_call.function.name
            fn_args_str = tool_call.function.arguments
        else:
            fn_name = tool_call.get("name", "")
            fn_args_str = tool_call.get("arguments", "{}")

        try:
            fn_args = json.loads(fn_args_str) if isinstance(fn_args_str, str) else fn_args_str
        except Exception:
            fn_args = {}

        domain = overrides.get(fn_name) or _infer_domain(fn_name)
        description = f"{fn_name}({json.dumps(fn_args, ensure_ascii=False)[:200]})"

        cert = self._az.verify(
            action_type=fn_name,
            action_description=description,
            domain=domain,
        )

        if cert.block:
            return {
                "result": None,
                "error": (
                    f"[Arcezia BLOCK] {cert.summary}"
                    + (f" | FABRICATION: {cert.fabricated_constraints}"
                       if cert.fabrication_detected else "")
                ),
                "cert": cert,
                "blocked": True,
            }
        if cert.review:
            return {
                "result": None,
                "error": (
                    f"[Arcezia REVIEW] {cert.summary} | "
                    f"Missing: {', '.join(cert.missing)}"
                ),
                "cert": cert,
                "blocked": True,
                "needs_review": True,
            }
        if cert.degraded:
            raise ArceziaUnavailableError(
                RuntimeError(
                    f"Degraded certificate (unverified): {cert.summary}. "
                    "The action was not verified by the engine."
                )
            )

        fn = tool_implementations.get(fn_name)
        if fn is None:
            return {
                "result": None,
                "error": f"No implementation for '{fn_name}'",
                "cert": cert,
                "blocked": False,
            }

        result = fn(**fn_args) if isinstance(fn_args, dict) else fn(fn_args)
        return {"result": result, "cert": cert, "blocked": False}

    def wrap_function(
        self,
        name: str,
        fn: Callable,
        domain: str | None = None,
    ) -> Callable:
        """
        Return a wrapped version of fn that runs Arcezia before executing.

        safe_execute = guard.wrap_function("execute_sql", db.execute, domain="database_ops")
        safe_execute(sql="DROP TABLE users")   # raises RuntimeError if blocked
        """
        effective_domain = domain or _infer_domain(name)

        @functools.wraps(fn)
        def safe_fn(*args, **kwargs):
            description = f"{name}(args={args!r}, kwargs={kwargs!r})"[:300]
            cert = self._az.verify(
                action_type=name,
                action_description=description,
                domain=effective_domain,
            )
            if cert.block:
                raise RuntimeError(
                    f"[Arcezia BLOCK] {cert.summary}"
                    + (f" | FABRICATION: {cert.fabricated_constraints}"
                       if cert.fabrication_detected else "")
                )
            if cert.review:
                raise RuntimeError(
                    f"[Arcezia REVIEW] {cert.summary} | "
                    f"Missing: {', '.join(cert.missing)}"
                )
            if cert.degraded:
                raise ArceziaUnavailableError(
                    RuntimeError(
                        f"Degraded certificate (unverified): {cert.summary}. "
                        "The action was not verified by the engine."
                    )
                )
            return fn(*args, **kwargs)

        return safe_fn


class ArceziaCrewTool:
    """
    Base class for CrewAI tools with built-in Arcezia verification.

    All verification runs in Arcezia's secure cloud (SaaS client version).

    Usage:

        from arcezia import Arcezia
        from arcezia.integrations.openai import ArceziaCrewTool

        az = Arcezia(api_key="ar_live_...", task="migrate the database")

        class SafeDBTool(ArceziaCrewTool):
            az = az
            domain = "database_ops"
            name = "execute_sql"
            description = "Run SQL against production database"

            def _run(self, sql: str) -> str:
                return db.execute(sql)
    """
    # ClassVar so pydantic never treats these as fields: CrewAI's BaseTool is a
    # pydantic model, and a subclass may co-inherit
    # (class MyTool(ArceziaCrewTool, BaseTool)). Unannotated attributes here
    # would surface as inherited fields and raise PydanticUserError.
    #
    # `name` and `description` are deliberately NOT declared: they belong to
    # CrewAI's BaseTool when co-inheriting, and declaring them here makes
    # pydantic warn that the subclass field shadows a parent attribute.
    # `name` is read defensively in _arcezia_gate.
    az: ClassVar[Any] = None
    domain: ClassVar[str] = "agent_action"

    def __init_subclass__(cls, **kwargs):
        """Gate the subclass's ``_run`` at definition time.

        The gate must sit on the method that actually executes, not on a
        wrapper the caller may skip. Subclasses implement ``_run``, so any
        caller that reaches ``_run`` directly — a framework calling it
        internally, a test, or user code — would otherwise execute the action
        unverified. Gating at the execution point makes this independent of
        how the caller enters.
        """
        super().__init_subclass__(**kwargs)
        impl = cls.__dict__.get("_run")
        if impl is None or getattr(impl, "_arcezia_gated", False):
            return

        @functools.wraps(impl)
        def _gated_run(self, *args, **kwargs):
            self._arcezia_gate(args, kwargs)
            return impl(self, *args, **kwargs)

        _gated_run._arcezia_gated = True          # type: ignore[attr-defined]
        cls._run = _gated_run

    def _arcezia_gate(self, args: tuple, kwargs: dict) -> None:
        """Verify before execution. Raises on BLOCK / REVIEW / degraded."""
        first = args[0] if args else next(iter(kwargs.values()), "")
        cert = self.az.verify(
            action_type=getattr(self, "name", "unnamed_tool"),
            action_description=str(first)[:300],
            domain=self.domain,
        )
        # Raise — never return a string. Returning "[BLOCKED]..." hands the
        # block message to the LLM which may rephrase and retry. An exception
        # propagates to the CrewAI task runner as a hard failure.
        if cert.block:
            raise RuntimeError(
                f"[Arcezia BLOCK] {cert.summary} | "
                f"trust={cert.trust_score:.0%}"
                + (f" | FABRICATION: {cert.fabricated_constraints}"
                   if cert.fabrication_detected else "")
            )
        if cert.review:
            raise RuntimeError(
                f"[Arcezia REVIEW] Human confirmation required: {cert.summary} | "
                f"Missing: {', '.join(cert.missing)}"
            )
        if cert.degraded:
            raise ArceziaUnavailableError(
                RuntimeError(
                    f"Degraded certificate (unverified): {cert.summary}. "
                    "The action was not verified by the engine."
                )
            )

    def run(self, *args, **kwargs) -> str:
        # The gate lives on _run (installed by __init_subclass__), so it holds
        # whether the caller enters through run() or _run().
        return self._run(*args, **kwargs)

    def _run(self, *args, **kwargs) -> str:
        raise NotImplementedError("Subclass must implement _run()")
