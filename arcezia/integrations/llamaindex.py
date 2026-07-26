"""
LlamaIndex integration for Arcezia (SaaS client).

Wrap a LlamaIndex ``FunctionTool`` so every invocation is verified before the
underlying function runs. The guarded tool is a real ``FunctionTool`` with the
original name / description / schema preserved, so it drops into agents, query
engines and tool specs unchanged.

    from llama_index.core.tools import FunctionTool
    from arcezia import Arcezia
    from arcezia.integrations.llamaindex import guard_tool, ArceziaLlamaToolkit

    az = Arcezia(api_key="ar_live_...", task="weekly cleanup")

    tool = FunctionTool.from_defaults(fn=run_sql)
    safe = guard_tool(tool, az)            # single tool
    # or many:
    safe_tools = ArceziaLlamaToolkit(az).wrap([tool_a, tool_b])

    agent = FunctionAgent(tools=safe_tools, llm=llm)

BLOCK raises ArceziaBlockError, REVIEW raises ArceziaReviewError (human
confirmation required), ALLOW runs the tool — the same semantics as every other
Arcezia adapter.

Beyond Level 1
--------------
This adapter implements Level 1 (every tool call gated). Levels 2-4 are
reached through ``toolkit.az`` — the same Arcezia client, no private access:

    toolkit = ArceziaLlamaToolkit(api_key=..., task=...)

    # Level 2 — verify the whole plan before running any of it
    result = toolkit.az.verify_chain({"steps": [
        {"step_id": "s1", "action_type": "execute_sql",
         "domain": "database_ops", "action_description": "SELECT ..."},
    ]})
    if result["overall_verdict"] != "SAFE":
        abort(result["blocked_at"])        # the step_id that failed

    # Post-execution audit
    toolkit.az.verify_outcome(action_type="execute_sql",
                          action_description="DELETE FROM orders ...",
                          outcome={"rows_affected": 50000},
                          expected={"rows_affected": 1})

    # Level 3 — ground human intent (a model cannot forge this)
    toolkit.az.authorize(token=user_approval_token)

Levels explained in full: ``help(arcezia)`` or https://arcezia.com/docs

"""
from __future__ import annotations

from typing import Any, Optional

from arcezia.integrations._common import coerce_az
from arcezia.integrations.universal import guard_callable, _infer_domain

try:
    from llama_index.core.tools import FunctionTool
    _LLAMAINDEX_AVAILABLE = True
except ImportError:
    _LLAMAINDEX_AVAILABLE = False


def _require_llamaindex():
    if not _LLAMAINDEX_AVAILABLE:
        raise ImportError(
            "llama-index-core is not installed. pip install llama-index-core"
        )


def guard_tool(tool: "FunctionTool", az: Any = None, *, domain: Optional[str] = None,
               block_on_review: bool = True, api_key=None, task=None, api_url=None,
               capability_envelope=None) -> "FunctionTool":
    """
    Return a new FunctionTool whose function is Arcezia-verified before it runs.

    Preserves the tool's name, description and parameter schema. Handles both
    sync and async LlamaIndex tools.
    """
    _require_llamaindex()
    client = coerce_az(az, api_key=api_key, task=task, api_url=api_url,
                       capability_envelope=capability_envelope)
    name = tool.metadata.name
    description = tool.metadata.description
    resolved_domain = domain or _infer_domain(name or "")

    # LlamaIndex FunctionTool may carry a sync fn, an async fn, or both.
    sync_fn = getattr(tool, "fn", None)
    async_fn = getattr(tool, "async_fn", None)

    guarded_sync = (
        guard_callable(sync_fn, client, domain=resolved_domain, action_type=name,
                       block_on_review=block_on_review)
        if sync_fn is not None else None
    )
    guarded_async = (
        guard_callable(async_fn, client, domain=resolved_domain, action_type=name,
                       block_on_review=block_on_review)
        if async_fn is not None else None
    )

    return FunctionTool.from_defaults(
        fn=guarded_sync,
        async_fn=guarded_async,
        name=name,
        description=description,
    )


class ArceziaLlamaToolkit:
    """Wraps a list of LlamaIndex FunctionTools with Arcezia verification."""

    def __init__(self, az: Any = None, *, api_key=None, task=None, api_url=None, capability_envelope=None):
        _require_llamaindex()
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

    def wrap(self, tools: list, domain_overrides: Optional[dict] = None,
             block_on_review: bool = True) -> list:
        overrides = domain_overrides or {}
        return [
            guard_tool(t, self._az, domain=overrides.get(t.metadata.name),
                       block_on_review=block_on_review)
            for t in tools
        ]
