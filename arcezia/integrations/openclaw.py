"""
Arcezia ⨉ OpenCLAW / generic dispatch-loop agents — dispatch guard.

Why wrap dispatch rather than individual tools:

    A gate only catches what must pass through it.

For CLI-based and dispatch-loop agents (OpenCLAW, AutoAgent, Aider-style
systems, any framework with a single `dispatch(tool, args)` entry point),
every tool call funnels through that one function.  Wrapping it once gates
every tool call the agent will ever make — including tools added at runtime —
without needing to enumerate tools upfront.

Usage (wrapping a dispatch function):
    from arcezia.integrations.openclaw import DispatchGuard

    guard = DispatchGuard(
        api_key="ar_live_...",
        task="refactor authentication module",
        domain="filesystem_ops",
    )

    # Replace your agent's dispatch callsite:
    result = guard.dispatch("write_file", {"path": "/etc/passwd", "content": "..."})
    # Raises ArceziaBlockError on BLOCK; ArceziaReviewError on REVIEW by default.

Usage (wrapping an existing dispatch callable):
    safe_dispatch = DispatchGuard.wrap(
        original_dispatch_fn, api_key="ar_live_...", task="..."
    )
    result = safe_dispatch("write_file", {...})

CLI hook mode (stdin JSON, stdout JSON permission decision):
    python -m arcezia.integrations.openclaw hook

    Payload in: {"tool": "write_file", "args": {"path": "...", ...}}
    Payload out: {"decision": "allow"|"block"|"review", "reason": "..."}

Custom evidence provider:
    def my_probe(tool_name: str, args: dict) -> dict[str, bool]:
        return {"file_is_in_sandbox": args.get("path","").startswith("/tmp/"))

    guard = DispatchGuard(..., evidence_provider=my_probe)
    # Note: evidence from `evidence_provider` is CLAIMED — the agent side
    # asserted it, so it is recorded but never treated as authoritative.
    # For GROUNDED evidence register a webhook probe via POST /v1/probes.

Active-permission ledger:
    When principal memory is enabled (ARCEZIA_PRINCIPAL_MEMORY=1) the hosted
    engine tracks the capability ledger cross-session. Locally the guard can
    also maintain a session-scoped ledger (query with guard.active_permissions).

Beyond Level 1
--------------
This adapter implements Level 1 (every tool call gated). Levels 2-4 are
reached through ``guard.az`` — the same Arcezia client, no private access:

    guard = DispatchGuard(api_key=..., task=...)

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
import json
import os
import sys
from typing import Any, Callable, Optional

from arcezia.client import ArceziaBlockError, ArceziaReviewError, ArceziaUnavailableError
from arcezia.integrations._common import coerce_az
from arcezia.integrations.universal import _infer_domain, _describe


# ── domain inference for generic tool names ────────────────────────────────────

def _dispatch_describe(tool_name: str, args: dict) -> str:
    """Build a concise, meaningful action description from a tool call."""
    parts = [f"{k}={repr(v)[:80]}" for k, v in args.items()]
    return f"{tool_name}({', '.join(parts)})"[:500]


# ── DispatchGuard ──────────────────────────────────────────────────────────────

class DispatchGuard:
    """
    Gated dispatcher for any dispatch-loop agent.

    Every tool call goes through Arcezia before execution.  BLOCK → raises
    ArceziaBlockError; REVIEW → raises ArceziaReviewError (or prompts human if
    ``review_handler`` is set); ALLOW → passes through and records the
    granted capability in the session ledger.

    The guard is stateless w.r.t. the agent — it holds only the Arcezia client
    and optional config. Thread-safe; can be shared across coroutines.
    """

    def __init__(
        self,
        az: Any = None,
        *,
        api_key: Optional[str] = None,
        task: str = "",
        api_url: Optional[str] = None,
        domain: Optional[str] = None,
        block_on_review: bool = True,
        evidence_provider: Optional[Callable[[str, dict], dict]] = None,
        review_handler: Optional[Callable[[Any], bool]] = None,
        on_error: str = "fail_closed",
    ):
        """
        Args:
            az:                An existing Arcezia client, or pass api_key/task/api_url.
            domain:            Default domain for all dispatched tools. If None, the
                               guard infers from the tool name.
            block_on_review:   If True (default), REVIEW raises ArceziaReviewError.
                               If False, REVIEW actions pass through unblocked.
            evidence_provider: Callable(tool_name, args) → dict[str, bool].
                               Provides per-call CLAIMED evidence.  For GROUNDED
                               evidence, register a probe webhook via POST /v1/probes.
            review_handler:    Callable(cert) → bool. Called on REVIEW instead of
                               raising. Return True to allow; False to block.
                               Typical use: prompt the human ("allow? [y/N]").
            on_error:          Passed to the Arcezia client. "fail_closed" (default)
                               → block on unreachable; "review" → surface for human.
        """
        self._client = coerce_az(az, api_key=api_key, task=task, api_url=api_url)
        self._default_domain = domain
        self._block_on_review = block_on_review
        self._evidence_provider = evidence_provider
        self._review_handler = review_handler
        # Session-scoped active-permission ledger (domain:action_type → bool).
        # Mirrors what the server tracks in the session when memory is on.
        self._active_permissions: dict[str, float] = {}

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
        return self._client

    @property
    def active_permissions(self) -> dict:
        """Read-only view of session-scoped granted capabilities."""
        return dict(self._active_permissions)

    # ── sync dispatch ─────────────────────────────────────────────────────────

    def dispatch(
        self,
        tool_name: str,
        args: dict,
        *,
        fn: Optional[Callable] = None,
        domain: Optional[str] = None,
    ) -> Any:
        """
        Verify and (optionally) execute a tool call synchronously.

        Args:
            tool_name: The name of the tool (maps to action_type).
            args:      Tool arguments dict.
            fn:        The callable to invoke on ALLOW.  If None, returns the
                       ArceziaCertificate instead of calling anything.
            domain:    Override the guard's default domain for this call.

        Returns:
            fn(*args positional args from dict*) if fn is provided, else the
            ArceziaCertificate on ALLOW.

        Raises:
            ArceziaBlockError: on BLOCK.
            ArceziaReviewError: on REVIEW (when block_on_review=True and no
                review_handler set).
        """
        cert = self._verify(tool_name, args, domain=domain)
        if cert.block:
            raise ArceziaBlockError(cert)
        if cert.review:
            if self._review_handler is not None:
                allowed = self._review_handler(cert)
                if not allowed:
                    raise ArceziaBlockError(cert)
            elif self._block_on_review:
                raise ArceziaReviewError(cert)
        if cert.degraded:
            raise ArceziaUnavailableError(
                RuntimeError(
                    f"Degraded certificate (unverified): {cert.summary}. "
                    "The action was not verified by the engine."
                )
            )
        import time
        self._active_permissions[f"{domain or self._default_domain or _infer_domain(tool_name)}:{tool_name}"] = time.time()
        if fn is not None:
            return fn(**args) if isinstance(args, dict) else fn(*args)
        return cert

    # ── async dispatch ────────────────────────────────────────────────────────

    async def adispatch(
        self,
        tool_name: str,
        args: dict,
        *,
        fn: Optional[Callable] = None,
        domain: Optional[str] = None,
    ) -> Any:
        """Async version of dispatch.  verify() runs in a thread to avoid blocking."""
        cert = await asyncio.to_thread(self._verify, tool_name, args, domain=domain)
        if cert.block:
            raise ArceziaBlockError(cert)
        if cert.review:
            if self._review_handler is not None:
                if asyncio.iscoroutinefunction(self._review_handler):
                    allowed = await self._review_handler(cert)
                else:
                    allowed = await asyncio.to_thread(self._review_handler, cert)
                if not allowed:
                    raise ArceziaBlockError(cert)
            elif self._block_on_review:
                raise ArceziaReviewError(cert)
        if cert.degraded:
            raise ArceziaUnavailableError(
                RuntimeError(
                    f"Degraded certificate (unverified): {cert.summary}. "
                    "The action was not verified by the engine."
                )
            )
        import time
        self._active_permissions[f"{domain or self._default_domain or _infer_domain(tool_name)}:{tool_name}"] = time.time()
        if fn is not None:
            if asyncio.iscoroutinefunction(fn):
                return await fn(**args) if isinstance(args, dict) else await fn(*args)
            return await asyncio.to_thread(fn, **args) if isinstance(args, dict) else await asyncio.to_thread(fn, *args)
        return cert

    # ── wrap an existing dispatch callable ────────────────────────────────────

    @classmethod
    def wrap(
        cls,
        dispatch_fn: Callable[[str, dict], Any],
        *,
        az: Any = None,
        api_key: Optional[str] = None,
        task: str = "",
        api_url: Optional[str] = None,
        domain: Optional[str] = None,
        block_on_review: bool = True,
        evidence_provider: Optional[Callable[[str, dict], dict]] = None,
        review_handler: Optional[Callable[[Any], bool]] = None,
    ) -> Callable[[str, dict], Any]:
        """
        Return a gated version of an existing dispatch callable.

            safe_dispatch = DispatchGuard.wrap(agent.dispatch, api_key=..., task=...)
            agent.dispatch = safe_dispatch

        Matches the original signature dispatch(tool_name, args) → result.
        """
        guard = cls(
            az=az, api_key=api_key, task=task, api_url=api_url,
            domain=domain, block_on_review=block_on_review,
            evidence_provider=evidence_provider, review_handler=review_handler,
        )

        if asyncio.iscoroutinefunction(dispatch_fn):
            @functools.wraps(dispatch_fn)
            async def _async_gated(tool_name: str, args: dict, **kw):
                return await guard.adispatch(tool_name, args, fn=lambda **a: dispatch_fn(tool_name, a, **kw), domain=domain)
            return _async_gated

        @functools.wraps(dispatch_fn)
        def _sync_gated(tool_name: str, args: dict, **kw):
            return guard.dispatch(tool_name, args, fn=lambda **a: dispatch_fn(tool_name, a, **kw), domain=domain)
        return _sync_gated

    # ── internal verify ───────────────────────────────────────────────────────

    def _verify(self, tool_name: str, args: dict, *, domain: Optional[str] = None):
        dom = domain or self._default_domain or _infer_domain(tool_name)
        desc = _dispatch_describe(tool_name, args)
        evidence: Optional[dict] = None
        if self._evidence_provider:
            try:
                evidence = self._evidence_provider(tool_name, args)
            except Exception:
                pass  # evidence provider failure = Ω, never a block
        return self._client.verify(
            action_type=tool_name,
            action_description=desc,
            domain=dom,
            agent_evidence=evidence or None,
        )


# ── CLI hook mode (stdin/stdout, compatible with OpenCLAW plugin protocol) ─────

def _cli_decision(decision: str, reason: str) -> dict:
    return {"decision": decision, "reason": reason}


def run_cli_hook(stdin_text: str, *, verifier=None) -> dict:
    """
    CLI hook mode: read a tool call from stdin, return a decision to stdout.

    Input JSON:  {"tool": "write_file", "args": {"path": "...", "content": "..."}}
    Output JSON: {"decision": "allow"|"block"|"review", "reason": "..."}

    Compatible with any CLI agent that supports a pre-dispatch hook (similar to
    Claude Code's PreToolUse hook protocol).
    """
    try:
        payload = json.loads(stdin_text) if stdin_text.strip() else {}
    except json.JSONDecodeError:
        return _cli_decision("review", "Arcezia: could not parse tool call; manual review required.")

    tool_name = payload.get("tool") or payload.get("tool_name") or payload.get("name") or ""
    args = payload.get("args") or payload.get("tool_input") or payload.get("input") or {}

    if not tool_name:
        return _cli_decision("review", "Arcezia: no tool name in payload; manual review.")

    if verifier is None:
        verifier = _default_guard()
        if verifier is None:
            return _cli_decision("review", "Arcezia not configured (set ARCEZIA_API_KEY); manual review.")

    try:
        dom = os.environ.get("ARCEZIA_DEFAULT_DOMAIN") or _infer_domain(tool_name)
        cert = verifier._verify(tool_name, args if isinstance(args, dict) else {}, domain=dom)
    except Exception as exc:
        return _cli_decision("block", f"Arcezia could not verify (fail-closed): {exc}")

    if cert.block:
        return _cli_decision("block", f"Arcezia BLOCK: {cert.summary}")
    if cert.degraded:
        return _cli_decision("block", f"Arcezia BLOCK (degraded cert — unverified): {cert.summary}")
    if cert.review:
        if os.environ.get("ARCEZIA_REVIEW_MODE", "review").lower() == "block":
            return _cli_decision("block", f"Arcezia REVIEW→block (re-request with grounding): {cert.summary}")
        return _cli_decision("review", f"Arcezia REVIEW (human approval required): {cert.summary}")
    return _cli_decision("allow", f"Arcezia ALLOW: {cert.summary}")


def _default_guard() -> Optional[DispatchGuard]:
    api_key = os.environ.get("ARCEZIA_API_KEY", "").strip()
    if not api_key:
        return None
    return DispatchGuard(
        api_key=api_key,
        task=os.environ.get("TASK", os.environ.get("ARCEZIA_TASK", "")),
        api_url=os.environ.get("ARCEZIA_API_URL", "https://api.arcezia.com"),
        domain=os.environ.get("ARCEZIA_DEFAULT_DOMAIN"),
    )


def main(argv: Optional[list] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if argv and argv[0] == "hook":
        out = run_cli_hook(sys.stdin.read())
        print(json.dumps(out))
        return 0
    print(
        "Usage:\n"
        "  python -m arcezia.integrations.openclaw hook   # CLI hook mode\n"
        "\n"
        "Or in Python:\n"
        "  from arcezia.integrations.openclaw import DispatchGuard\n"
        "  guard = DispatchGuard(api_key=..., task=...)\n"
        "  result = guard.dispatch('write_file', {'path': '...', 'content': '...'})\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
