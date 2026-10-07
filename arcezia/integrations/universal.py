"""
Framework-agnostic guard — wrap ANY Python callable used as an agent tool.

This is the universal integration: it imports no agent framework and makes no
assumption about the framework's tool object. It simply verifies an action
before the underlying callable runs. Because nearly every modern agent framework
registers tools as plain Python functions, one guard covers them all:

    Pydantic AI · smolagents · OpenAI Agents SDK · Google ADK · Strands · LlamaIndex
    FunctionTool · CrewAI @tool · or your own hand-rolled tool loop.

Two forms:

    from arcezia import Arcezia, guard

    az = Arcezia(api_key="ar_live_...", task="...")

    # 1) Decorator
    @guard(az, domain="database_ops")
    def run_sql(query: str) -> str:
        return db.execute(query)

    # 2) Wrap an existing callable (e.g. before registering it as a tool)
    safe_fn = guard_callable(run_sql, az)

Behaviour:
    ALLOW  → the callable runs and returns normally.
    BLOCK  → raises ArceziaBlockError (never runs the callable).
    REVIEW → raises ArceziaReviewError by default (human confirmation required);
             pass block_on_review=False to let REVIEW through.

The wrapper preserves the original function's name, docstring, type hints and
signature (via functools.wraps), so frameworks that build a tool schema by
introspecting the function — Pydantic AI, OpenAI Agents SDK, smolagents — see an
unchanged signature. Both sync and async callables are supported.
"""
from __future__ import annotations

import warnings

import asyncio
import functools
from typing import Any, Callable, Optional

from arcezia.client import ArceziaBlockError, ArceziaReviewError, ArceziaUnavailableError
from arcezia.integrations._common import call_of, coerce_az, describe, refuse_unless_clean
from arcezia.integrations._params import scalar_params


# Lightweight name → domain inference (kept independent of any other adapter).
_DOMAIN_MAP = {
    "sql": "database_ops", "query": "database_ops", "db": "database_ops",
    "database": "database_ops", "postgres": "database_ops", "mysql": "database_ops",
    "file": "filesystem_ops", "shell": "filesystem_ops", "bash": "filesystem_ops",
    "terminal": "filesystem_ops", "git": "filesystem_ops", "exec": "filesystem_ops",
    "write": "filesystem_ops", "read": "filesystem_ops", "delete": "filesystem_ops",
    "email": "agent_action", "slack": "agent_action", "send": "agent_action",
    "deploy": "agent_action", "http": "agent_action", "api": "agent_action",
    "post": "agent_action",
}


_WARNED_DOMAINS: set[str] = set()


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
    lower = name.lower()
    for kw, domain in _DOMAIN_MAP.items():
        if kw in lower:
            return domain
    # No keyword matched — a fail-safe guess, not a fact. A wrong guess
    # surfaces later as an unexplainable hold, so say it once, plainly.
    _warn_inferred_domain(name)
    return "agent_action"


def _describe(action_type: str, args: tuple, kwargs: dict) -> str:
    """One shared description for every adapter — see ``_common.describe``."""
    return describe(action_type, args, kwargs)


def guard_callable(
    fn: Callable,
    az: Any = None,
    *,
    domain: Optional[str] = None,
    action_type: Optional[str] = None,
    block_on_review: bool = True,
    api_key: Optional[str] = None,
    task: Optional[str] = None,
    api_url: Optional[str] = None,
    capability_envelope: Optional[dict] = None,
    evidence_provider: Optional[Callable] = None,
    data_subject_reference: Optional[str] = None,
) -> Callable:
    """
    Return a verification-guarded version of ``fn``.

    Pass an existing client as ``az`` or inline ``api_key=``/``task=``. Works on
    both sync and async callables; the returned wrapper matches the original.

    capability_envelope: What the session may do (allowed_domains, max_scope,
        ...), set by a person. Applied to the session when it is created.
    evidence_provider: Optional callable(action_type, args, kwargs) → dict,
        sent as agent_evidence: what the agent says. It can never clear an
        action on its own.
    data_subject_reference: Optional identifier for the person this tool's
        actions are about, attached to every verification the wrapper makes.
        Record-only — never changes a verdict.
    """
    client = coerce_az(az, api_key=api_key, task=task, api_url=api_url,
                       capability_envelope=capability_envelope)
    atype = action_type or getattr(fn, "__name__", "tool")
    dom = domain or _infer_domain(atype)

    def _verify(args: tuple, kwargs: dict):
        ev = None
        if evidence_provider:
            try:
                ev = evidence_provider(atype, args, kwargs)
            except Exception:
                pass  # a failing evidence provider sends nothing; it never clears anything
        # Per-call subject kwarg only when set: keeps the call compatible with
        # user-supplied clients whose verify() predates the parameter.
        _subject_kw = (
            {"data_subject_reference": data_subject_reference}
            if data_subject_reference is not None else {}
        )
        cert = client.verify(
            action_type=atype,
            action_description=_describe(atype, args, kwargs),
            domain=dom,
            agent_evidence=ev,
            # Typed keyword arguments, forwarded to your registered checks.
            action_parameters=scalar_params(kwargs),
            **_subject_kw,
        )
        if cert.block:
            raise ArceziaBlockError(cert)
        if cert.review and block_on_review:
            raise ArceziaReviewError(cert)
        # A degraded certificate (credential=None, trust_score=0) was built
        # locally because the service could not be reached. Nothing was
        # verified, so raise and let the caller decide.
        if cert.degraded:
            raise ArceziaUnavailableError(
                RuntimeError(
                    f"Degraded certificate (unverified): {cert.summary}. "
                    "The action was not verified by the engine."
                )
            )
        # An ALLOW whose fabrication result was never reported is not a
        # clearance, and an ALLOW runs only on a pass naming THIS call
        # (recomputed from the arguments that will execute). One helper,
        # every adapter — see _common.
        refuse_unless_clean(cert, call_of(atype, dom, _describe(atype, args, kwargs),
                                          scalar_params(kwargs)))
        return cert

    if asyncio.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def _async_wrapper(*args, **kwargs):
            # Run the (sync, HTTP) verify off the event loop so it never blocks it.
            await asyncio.to_thread(_verify, args, kwargs)
            return await fn(*args, **kwargs)

        _async_wrapper.__arcezia_guarded__ = True  # type: ignore[attr-defined]
        return _async_wrapper

    @functools.wraps(fn)
    def _sync_wrapper(*args, **kwargs):
        _verify(args, kwargs)
        return fn(*args, **kwargs)

    _sync_wrapper.__arcezia_guarded__ = True  # type: ignore[attr-defined]
    return _sync_wrapper


def guard(
    az: Any = None,
    *,
    domain: Optional[str] = None,
    action_type: Optional[str] = None,
    block_on_review: bool = True,
    api_key: Optional[str] = None,
    task: Optional[str] = None,
    api_url: Optional[str] = None,
    capability_envelope: Optional[dict] = None,
    evidence_provider: Optional[Callable] = None,
    data_subject_reference: Optional[str] = None,
):
    """
    Decorator factory. Equivalent to ``guard_callable`` applied as a decorator:

        @guard(az, domain="filesystem_ops", capability_envelope={...})
        def write_file(path: str, content: str) -> str:
            ...
    """
    def decorator(fn: Callable) -> Callable:
        return guard_callable(
            fn, az,
            domain=domain, action_type=action_type, block_on_review=block_on_review,
            api_key=api_key, task=task, api_url=api_url,
            capability_envelope=capability_envelope,
            evidence_provider=evidence_provider,
            data_subject_reference=data_subject_reference,
        )
    return decorator
