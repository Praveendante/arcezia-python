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
    if result["overall_verdict"] != "SAFE":   # dict access: still works, deprecated
        abort(result["blocked_at"])        # the step_id that failed
    # Current form — `result` is an ArceziaChainResult, and `.safe` is stricter
    # than the string: it is False on a degraded result, whose overall_verdict
    # reads "SAFE" under on_error="fail_open".
    #   if not result.safe: abort(result.blocked_at)

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

import warnings

import asyncio
import functools
from typing import Any, Callable, ClassVar

from arcezia.client import ArceziaUnavailableError
from arcezia.integrations._common import ACTION_KEYS, coerce_az, describe, refuse_unless_clean
from arcezia.integrations._params import scalar_params


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


_WARNED_DOMAINS: set[str] = set()


def _fabrication_note(cert) -> str:
    """The fabrication clause of a BLOCK message — three states, not two.

    `fabrication_detected` is None when the server did not report it (an older
    deployment, or a degraded certificate this SDK built locally). Rendering
    that the same as False would print nothing, and a silent message reads as
    "checked, clean". It is not; say so.
    """
    if cert.fabrication_detected is True:
        return f" | FABRICATION: {cert.fabricated_constraints}"
    if cert.fabrication_detected is None:
        return " | fabrication: not reported by this server"
    return ""


def _warn_inferred_domain(tool_name: str) -> None:
    """Warn once per tool that its domain was guessed, not declared."""
    if tool_name in _WARNED_DOMAINS:
        return
    _WARNED_DOMAINS.add(tool_name)
    warnings.warn(
        f"Arcezia: no domain declared for tool {tool_name!r} and none could be "
        f"inferred from its name, so it will be verified against 'agent_action'. "
        f"If this tool touches a database, the filesystem, or another domain, "
        f"declare it explicitly — otherwise it is checked against the wrong "
        f"rules and may be held for review with no obvious reason.",
        stacklevel=3,
    )


def _infer_domain(name: str) -> str:
    name_lower = name.lower()
    for kw, domain in _DOMAIN_MAP.items():
        if kw in name_lower:
            return domain
    # No keyword matched — a fail-safe guess, not a fact. A wrong guess
    # surfaces later as an unexplainable hold, so say it once, plainly.
    _warn_inferred_domain(name)
    return "agent_action"


class ArceziaGuard:
    """
    Guards OpenAI function/tool calls with Arcezia verification.
    Works with any dict-based function call interface
    (OpenAI, Anthropic tool_use, etc.)
    """

    def __init__(self, az=None, *, api_key=None, task=None, api_url=None, capability_envelope=None,
                 data_subject_reference=None):
        # data_subject_reference: optional identifier for the person these
        # verifications are about. Record-only — never changes a verdict.
        self._az = coerce_az(az, api_key=api_key, task=task, api_url=api_url,
                       capability_envelope=capability_envelope,
                       data_subject_reference=data_subject_reference)

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

        Returns: {"result": ..., "cert": ArceziaCertificate, "blocked": bool,
                  "needs_review": bool}, plus "error" whenever result is None.

        `needs_review` is present on every path. It used to be set only on the
        REVIEW branch, so the documented `r["needs_review"]` raised KeyError on
        an ALLOW and on a BLOCK — the two commonest outcomes. Both `blocked`
        and `needs_review` are True on REVIEW: nothing ran, and a person can
        clear it.
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
        # All arguments, one shared budget, an explicit marker when clipped —
        # this was `json.dumps(fn_args)[:200]`, so a 200-char benign prefix
        # authorised whatever followed it (A5-5). See _common.describe.
        description = describe(
            fn_name,
            kwargs=fn_args if isinstance(fn_args, dict) else {"arguments": fn_args},
            priority=ACTION_KEYS,
        )

        cert = self._az.verify(
            action_type=fn_name,
            action_description=description,
            domain=domain,
            # Typed function-call arguments → probe lookup keys (bounds-safe).
            action_parameters=scalar_params(fn_args if isinstance(fn_args, dict) else None),
        )

        if cert.block:
            return {
                "result": None,
                "error": (
                    f"[Arcezia BLOCK] {cert.summary}"
                    + _fabrication_note(cert)
                ),
                "cert": cert,
                "blocked": True,
                "needs_review": False,
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
        # An ALLOW whose fabrication channel never reported is not a
        # clearance (T7). One helper, every adapter — see _common.
        refuse_unless_clean(cert)

        fn = tool_implementations.get(fn_name)
        if fn is None:
            return {
                "result": None,
                "error": f"No implementation for '{fn_name}'",
                "cert": cert,
                "blocked": False,
                "needs_review": False,
            }

        result = fn(**fn_args) if isinstance(fn_args, dict) else fn(fn_args)
        return {"result": result, "cert": cert, "blocked": False,
                "needs_review": False}

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

        def _gate(args, kwargs):
            # Was clipped at 300 while the full args were executed (A5-5).
            description = describe(name, args, kwargs, priority=ACTION_KEYS)
            cert = self._az.verify(
                action_type=name,
                action_description=description,
                domain=effective_domain,
                # Typed keyword arguments → probe lookup keys (bounds-safe).
                action_parameters=scalar_params(kwargs),
            )
            if cert.block:
                raise RuntimeError(
                    f"[Arcezia BLOCK] {cert.summary}"
                    + _fabrication_note(cert)
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
            # An ALLOW whose fabrication channel never reported is not a
            # clearance (T7). One helper, every adapter — see _common.
            refuse_unless_clean(cert)
            return cert

        # An async `fn` needs an async wrapper. A sync wrapper around a
        # coroutine function returns the coroutine OBJECT: the caller gets
        # something that has not run, the verification and the execution stop
        # being adjacent, and `RuntimeWarning: coroutine was never awaited` is
        # the only sign. Same shape as A5-16 in openclaw; universal.py already
        # splits the two, and this path is the sibling that did not.
        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def safe_afn(*args, **kwargs):
                # verify() is blocking HTTP; keep it off the event loop.
                await asyncio.to_thread(_gate, args, kwargs)
                return await fn(*args, **kwargs)

            return safe_afn

        @functools.wraps(fn)
        def safe_fn(*args, **kwargs):
            _gate(args, kwargs)
            return fn(*args, **kwargs)

        return safe_fn


# The execution entry points of a CrewAI tool. Both are gated, neither is
# special-cased: `_run` is the sync one, `_arun` the async one CrewAI's BaseTool
# declares so async tools can override it (and which `arun()` calls). A guard
# that enumerates one and misses its twin is the defect class this list closes
# (A5-1); adding a third entry point here is the whole change needed if CrewAI
# ever grows one.
_GATED_ENTRY_POINTS = frozenset({"_run", "_arun"})


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

    Co-inheriting with CrewAI's own BaseTool — the form you need when the tool
    has to BE a crewai BaseTool — requires the ClassVar annotations, because
    crewai's BaseTool is a pydantic model and pydantic rejects the SUBCLASS's
    own un-annotated assignments (`PydanticUserError: A non-annotated
    attribute was detected: 'az'`). Annotate them and it works:

        from typing import Any, ClassVar
        from crewai.tools import BaseTool as CrewBaseTool

        class SafeDBTool(ArceziaCrewTool, CrewBaseTool):
            az: ClassVar[Any] = az
            domain: ClassVar[str] = "database_ops"
            name: str = "execute_sql"                # a real pydantic field
            description: str = "Run SQL against production database"

            def _run(self, sql: str) -> str:
                return db.execute(sql)

            async def _arun(self, sql: str) -> str:  # gated exactly like _run
                return await db.aexecute(sql)
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
        """Gate the subclass's ``_run`` AND ``_arun`` at definition time.

        The gate must sit on the method that actually executes, not on a
        wrapper the caller may skip. Subclasses implement ``_run``, so any
        caller that reaches ``_run`` directly — a framework calling it
        internally, a test, or user code — would otherwise execute the action
        unverified. Gating at the execution point makes this independent of
        how the caller enters.

        ``_arun`` is the sibling execution entry point, not a variant of the
        same one: CrewAI's ``BaseTool`` declares it precisely so async tools
        override it, and ``arun()`` calls it. Enumerating ``_run`` alone left
        every async CrewAI tool ungated (A5-1). A guard that names one entry
        point and not its twin is the defect class, so both are wrapped here
        and neither is special-cased.

        A subclass that defines neither is left alone: CrewAI's
        ``NotImplementedError`` stays in place.
        """
        super().__init_subclass__(**kwargs)

        sync_impl = cls.__dict__.get("_run")
        if sync_impl is not None and not getattr(sync_impl, "_arcezia_gated", False):
            @functools.wraps(sync_impl)
            def _gated_run(self, *args, **kwargs):
                self._arcezia_gate(args, kwargs)
                return sync_impl(self, *args, **kwargs)

            _gated_run._arcezia_gated = True       # type: ignore[attr-defined]
            cls._run = _gated_run

        async_impl = cls.__dict__.get("_arun")
        if async_impl is not None and not getattr(async_impl, "_arcezia_gated", False):
            @functools.wraps(async_impl)
            async def _gated_arun(self, *args, **kwargs):
                # verify() is blocking HTTP; run it off the event loop so a
                # gated async tool does not stall the whole loop.
                await asyncio.to_thread(self._arcezia_gate, args, kwargs)
                return await async_impl(self, *args, **kwargs)

            _gated_arun._arcezia_gated = True      # type: ignore[attr-defined]
            cls._arun = _gated_arun

    def _arcezia_gate(self, args: tuple, kwargs: dict) -> None:
        """Verify before execution. Raises on BLOCK / REVIEW / degraded."""
        # Every argument, not just the first. It described `str(args[0])[:300]`
        # and nothing else, so a CrewAI tool called as
        # `run(table="users", where="1=1; DELETE FROM users")` was verified on
        # the string 'users' and then executed the delete (A5-5).
        cert = self.az.verify(
            action_type=getattr(self, "name", "unnamed_tool"),
            action_description=describe(
                getattr(self, "name", "unnamed_tool"), args, kwargs,
                priority=ACTION_KEYS,
            ),
            domain=self.domain,
            # Typed keyword arguments → probe lookup keys (bounds-safe).
            action_parameters=scalar_params(kwargs),
        )
        # Raise — never return a string. Returning "[BLOCKED]..." hands the
        # block message to the LLM which may rephrase and retry. An exception
        # propagates to the CrewAI task runner as a hard failure.
        if cert.block:
            raise RuntimeError(
                f"[Arcezia BLOCK] {cert.summary} | "
                f"trust={cert.trust_score:.0%}"
                + _fabrication_note(cert)
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
        # An ALLOW whose fabrication channel never reported is not a
        # clearance (T7). One helper, every adapter — see _common.
        refuse_unless_clean(cert)

    def __getattribute__(self, name):
        """Gate ``_run`` / ``_arun`` at ACCESS time, not at definition time.

        ``__init_subclass__`` can only see a ``_run`` present in the class
        body. A ``_run`` assigned afterwards — ``Late._run = fn``, a
        monkeypatch, an instance attribute, a mixin applied later — carried no
        gate and executed unverified (A5-18). Definition time is the wrong
        instant to decide this: the only instant at which the executing
        callable is known is the instant it is fetched. So every fetch of an
        execution entry point returns something gated, however the callable
        arrived and whoever fetches it — ``run()``, CrewAI's own machinery, a
        test, or user code reaching for ``tool._run`` directly.

        Idempotent: a callable already carrying ``_arcezia_gated`` is returned
        as-is, so a class-body ``_run`` wrapped by ``__init_subclass__`` is
        never verified twice. The base stubs below are left alone so a tool
        that implements neither still raises CrewAI's ``NotImplementedError``
        without a verification round trip first.
        """
        attr = super().__getattribute__(name)
        if name not in _GATED_ENTRY_POINTS:
            return attr
        if not callable(attr):
            return attr
        if getattr(attr, "_arcezia_gated", False) or getattr(attr, "_arcezia_stub", False):
            return attr

        if name == "_arun":
            @functools.wraps(attr)
            async def _gated(*args, **kwargs):
                # verify() is blocking HTTP; keep it off the event loop.
                await asyncio.to_thread(self._arcezia_gate, args, kwargs)
                return await attr(*args, **kwargs)
        else:
            @functools.wraps(attr)
            def _gated(*args, **kwargs):
                self._arcezia_gate(args, kwargs)
                return attr(*args, **kwargs)

        _gated._arcezia_gated = True               # type: ignore[attr-defined]
        return _gated

    def run(self, *args, **kwargs) -> str:
        # The gate lives on _run — installed by __init_subclass__ for a
        # class-body implementation, and by __getattribute__ for every other
        # way one can arrive — so it holds whether the caller enters through
        # run() or _run(), and it fires exactly once.
        return self._run(*args, **kwargs)

    async def arun(self, *args, **kwargs) -> str:
        # Async twin of run(): CrewAI's BaseTool.arun() calls _arun, which is
        # gated by the same rule. Enumerating the sync entry point and missing
        # its async sibling is what left every async CrewAI tool ungated.
        return await self._arun(*args, **kwargs)

    def _run(self, *args, **kwargs) -> str:
        raise NotImplementedError("Subclass must implement _run()")

    async def _arun(self, *args, **kwargs) -> str:
        raise NotImplementedError(
            "Subclass must implement _arun() for async execution "
            "(or call run() / _run() for the sync path)."
        )

    # Not gated: refusing to execute is already the safe outcome, and wrapping
    # these would spend a verification on a call that cannot run.
    _run._arcezia_stub = True                      # type: ignore[attr-defined]
    _arun._arcezia_stub = True                     # type: ignore[attr-defined]
