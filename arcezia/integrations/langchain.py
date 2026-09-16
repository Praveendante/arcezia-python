"""
LangChain integration for Arcezia (SaaS client).

All verification runs in Arcezia's secure cloud via the proprietary engine.
The API surface is stable, so your integration code stays unchanged.

Two patterns:

1. Wrap individual tools:

    from arcezia import Arcezia
    from arcezia.integrations.langchain import ArceziaToolkit
    from langchain.tools import ShellTool, PythonREPLTool

    az = Arcezia(api_key="ar_live_...", task="help the user manage their AWS infrastructure")
    toolkit = ArceziaToolkit(az)

    safe_tools = toolkit.wrap([ShellTool(), PythonREPLTool()])
    # Every tool call is verified before execution.

2. Wrap an agent executor:

    from arcezia.integrations.langchain import ArceziaAgentGuard

    guard = ArceziaAgentGuard(az)
    safe_executor = guard.wrap(executor)
    safe_executor.run("Delete all test orders from the production database")

Beyond Level 1
--------------
This adapter implements Level 1 (every tool call gated). Levels 2-4 are
reached through ``toolkit.az`` — the same Arcezia client, no private access:

    toolkit = ArceziaToolkit(api_key=..., task=...)

    # Level 2 — verify the whole plan before running any of it
    result = toolkit.az.verify_chain({"steps": [
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
    toolkit.az.verify_outcome(action_type="execute_sql",
                          action_description="DELETE FROM orders ...",
                          outcome={"rows_affected": 50000},
                          expected={"rows_affected": 1})

    # Level 3 — ground human intent (a model cannot forge this)
    toolkit.az.authorize(token=user_approval_token)

Levels explained in full: ``help(arcezia)`` or https://arcezia.com/docs

"""
from __future__ import annotations

import warnings

from typing import Any

from arcezia.client import ArceziaUnavailableError
from arcezia.integrations._common import coerce_az, warn_if_fail_open, refuse_unless_clean

try:
    from langchain.tools import BaseTool
    try:
        from langchain_core.tools.base import ToolException
    except ImportError:
        from langchain.tools.base import ToolException  # type: ignore[no-redef]
    # StructuredTool builds real BaseTool instances for the LangGraph tool-calling
    # path (ToolNode / create_react_agent require genuine BaseTools).
    try:
        from langchain_core.tools import StructuredTool
    except ImportError:
        from langchain.tools import StructuredTool  # type: ignore[no-redef]
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False


def _require_langchain():
    if not _LANGCHAIN_AVAILABLE:
        raise ImportError(
            "langchain is not installed. pip install langchain"
        )


# Domain routing: map tool name patterns to Arcezia domains
_TOOL_DOMAIN_MAP = {
    "sql":        "database_ops",
    "database":   "database_ops",
    "postgres":   "database_ops",
    "mysql":      "database_ops",
    "shell":      "filesystem_ops",
    "bash":       "filesystem_ops",
    "terminal":   "filesystem_ops",
    "file":       "filesystem_ops",
    "git":        "filesystem_ops",
    "email":      "agent_action",
    "gmail":      "agent_action",
    "slack":      "agent_action",
    "api":        "agent_action",
    "http":       "agent_action",
    "request":    "agent_action",
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
        f"declare it (domain_overrides={{'{tool_name}': 'database_ops'}} or "
        f"domain=...) — otherwise it is checked against the wrong rules and may "
        f"be held for review with no obvious reason.",
        stacklevel=3,
    )


def _infer_domain(tool_name: str) -> str:
    name_lower = tool_name.lower()
    for kw, domain in _TOOL_DOMAIN_MAP.items():
        if kw in name_lower:
            return domain
    # No keyword matched. Falling back to the general domain is the fail-safe
    # choice, but it is a GUESS, and a wrong guess shows up later as a verdict
    # the caller cannot explain: a database tool checked against agent_action
    # rules, held because the envelope allows a different domain. Extending the
    # keyword list is not the fix — it is unbounded and language-bound. Saying
    # so once, plainly, is: the caller knows their tool's domain and can set it.
    _warn_inferred_domain(tool_name)
    return "agent_action"


# Attributes safe to proxy to the unwrapped tool: inert metadata and schema
# introspection that LangChain reads to DESCRIBE a tool. Nothing here can run
# the tool.
#
# This is an ALLOWLIST, and that direction is the whole point. It used to be a
# denylist of nine execution entry points, which cannot work: `BaseTool` is a
# `Runnable`, and every Runnable combinator returns a new Runnable that closes
# over the UNWRAPPED tool and executes it. That surface is unbounded and grows
# with each LangChain release, so any enumeration of it is stale on arrival.
#
# Measured against langchain_core 1.4.0 — each of these executed the tool with
# ZERO verification calls under the denylist:
#     with_config, bind, map, with_retry, pipe, as_tool,
#     transform, batch_as_completed, astream_events, astream_log
# `with_config` and `bind` are ordinary agent plumbing, so this was reachable
# in normal use, not only by an adversary.
#
# Unknown attribute now raises AttributeError, which is both the correct Python
# meaning of "this wrapper does not have that" and the fail-closed answer: a
# caller reaching for an ungated execution path gets an error naming the gated
# alternative, never a silent unverified run.
_PROXY_SAFE_ATTRS = frozenset({
    "name", "description", "args", "args_schema", "tool_call_schema",
    "return_direct", "metadata", "tags", "verbose", "callbacks",
    "handle_tool_error", "handle_validation_error", "response_format",
    "get_input_schema", "get_output_schema", "is_single_input",
})


class ArceziaTool:
    """
    A LangChain tool wrapper that runs Arcezia verification before execution.

    Gated entry points: ``run``, ``arun``, ``invoke``, ``ainvoke``. Any other
    execution entry point raises rather than silently bypassing the gate.

    For LangGraph / tool-calling graphs that need a genuine ``BaseTool``, use
    ``ArceziaToolkit.wrap_for_langgraph()``.
    """

    def __init__(self, tool: "BaseTool", az, domain: str | None = None):
        _require_langchain()
        self._tool = tool
        self._az = az
        # This one is constructed with a client directly rather than through
        # coerce_az, so the fail_open contradiction has to be said here too —
        # `_gate` below refuses a degraded certificate exactly like every other
        # adapter, whatever the client's on_error says.
        warn_if_fail_open(az)
        self._domain = domain or _infer_domain(tool.name)
        # Expose LangChain tool interface
        self.name = tool.name
        self.description = tool.description

    @property
    def az(self):
        """The underlying Arcezia client (see ArceziaToolkit.az)."""
        return self._az

    def _gate(self, tool_input) -> "ArceziaCertificate":
        """Verify before execution. Raises on BLOCK / REVIEW / degraded."""
        # One shared description for every adapter (see _common.describe). This
        # path never clipped, which was right, but it was also unbounded: an
        # input past the server's 100 000-char field bound came back a 422
        # rather than a verdict. describe() keeps every argument and marks any
        # clip explicitly, so the bound cannot silently become a refusal.
        input_str = (
            tool_input if isinstance(tool_input, str)
            else _describe(self._tool.name, kwargs=tool_input,
                           priority=_ACTION_KEYS)
            if isinstance(tool_input, dict)
            else str(tool_input)
        )
        if isinstance(input_str, str) and len(input_str) > _DESCRIBE_BUDGET:
            input_str = _clip_description(input_str, _DESCRIBE_BUDGET)
        cert = self._az.verify(
            action_type=self._tool.name,
            action_description=input_str,
            domain=self._domain,
            # Structured addressing (P2): forward the TYPED tool args exactly
            # as the StructuredTool path (wrap_tool_for_langgraph) does — this
            # classic path used to stringify and drop them, so probes only ever
            # saw prose here. Bounds-safe projection; never fails the call.
            action_parameters=_scalar_params(
                tool_input if isinstance(tool_input, dict) else None
            ),
        )
        if cert.block:
            raise ToolException(
                f"[Arcezia BLOCK] {cert.summary}\n"
                f"Trust: {cert.trust_score:.0%} | "
                # Plain words, not the raw field: it is three-state now, and a
                # printed "None" reads to a human as a value rather than as
                # "this server did not say".
                f"Fabrication: {cert.fabrication_status}"
            )
        if cert.review:
            raise ToolException(
                f"[Arcezia REVIEW] Human confirmation required: {cert.summary}\n"
                f"Missing evidence: {', '.join(cert.missing)}"
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

    def run(self, tool_input: str | dict, **kwargs) -> str:
        cert = self._gate(tool_input)
        result = self._tool.run(tool_input, **kwargs)
        return f"{result}\n[Arcezia ALLOW | trust={cert.trust_score:.0%}]"

    def invoke(self, input, config=None, **kwargs):
        """Modern LangChain entry point — gated, same as run()."""
        self._gate(input)
        return self._tool.invoke(input, config, **kwargs)

    async def ainvoke(self, input, config=None, **kwargs):
        """Async modern entry point — gated."""
        self._gate(input)
        return await self._tool.ainvoke(input, config, **kwargs)

    async def arun(self, tool_input, **kwargs):
        """Async legacy entry point — gated."""
        cert = self._gate(tool_input)
        result = await self._tool.arun(tool_input, **kwargs)
        return f"{result}\n[Arcezia ALLOW | trust={cert.trust_score:.0%}]"

    def __getattr__(self, name):
        # Fail closed by default: proxy only what is known inert. Anything else
        # may be — or may return — an execution path to the unwrapped tool, and
        # forwarding it would run the action with no verification at all.
        if name in _PROXY_SAFE_ATTRS:
            return getattr(self._tool, name)
        raise AttributeError(
            f"ArceziaTool does not proxy {name!r} — it is not a known-inert "
            f"attribute, and forwarding it could execute the tool without "
            f"verification. Use .run()/.arun()/.invoke()/.ainvoke(), or "
            f"ArceziaToolkit.wrap_for_langgraph() for LangGraph and "
            f"tool-calling graphs."
        )


class ArceziaToolkit:
    """Wraps a list of LangChain tools with Arcezia verification.

    Construct with an existing client — ``ArceziaToolkit(az)`` — or with
    credentials directly — ``ArceziaToolkit(api_key="ar_live_...", task=...)``.
    """

    def __init__(self, az=None, *, api_key=None, task=None, api_url=None, capability_envelope=None,
                 data_subject_reference=None):
        # data_subject_reference: optional identifier for the person these
        # verifications are about. Record-only — never changes a verdict.
        _require_langchain()
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

    def wrap(
        self,
        tools: list["BaseTool"],
        domain_overrides: dict[str, str] | None = None,
    ) -> list[ArceziaTool]:
        overrides = domain_overrides or {}
        return [
            ArceziaTool(
                tool=t,
                az=self._az,
                domain=overrides.get(t.name),
            )
            for t in tools
        ]

    def wrap_for_langgraph(
        self,
        tools: list["BaseTool"],
        domain_overrides: dict[str, str] | None = None,
    ) -> list["BaseTool"]:
        """
        Wrap tools as genuine BaseTool instances for LangGraph.

        Use this when passing tools to LangGraph (`ToolNode`, `create_react_agent`)
        or any LangChain tool-calling path — these require real BaseTool objects,
        which `wrap()` (a composition wrapper for the classic AgentExecutor) is not.
        """
        overrides = domain_overrides or {}
        return [
            as_langgraph_tool(t, self._az, overrides.get(t.name)) for t in tools
        ]


# Bounded projection of typed tool-call args → action_parameters (shared by
# all integrations; always within the API bounds by construction).
from ._params import scalar_params as _scalar_params
from ._common import ACTION_KEYS as _ACTION_KEYS
from ._common import DESCRIBE_BUDGET as _DESCRIBE_BUDGET
from ._common import _clip as _clip_description
from ._common import describe as _describe


def as_langgraph_tool(tool: "BaseTool", az, domain: str | None = None) -> "BaseTool":
    """
    Wrap a LangChain tool as a *real* BaseTool that verifies before execution.

    Unlike ``ArceziaTool`` (a composition wrapper whose ``.run()`` suits the
    classic ``AgentExecutor``), this returns a genuine ``BaseTool``, so it plugs
    directly into LangGraph's ``ToolNode`` / ``create_react_agent`` and any
    LangChain ≥0.2 tool-calling graph. The original tool's ``args_schema`` is
    preserved so the model sees an unchanged signature.

    BLOCK / REVIEW raise ``ToolException`` (LangGraph surfaces it as an error
    ToolMessage); ALLOW delegates to the wrapped tool.
    """
    _require_langchain()
    resolved_domain = domain or _infer_domain(tool.name)

    def _verified(**kwargs):
        cert = az.verify(
            action_type=tool.name,
            action_description=_describe(tool.name, kwargs=kwargs,
                                         priority=_ACTION_KEYS),
            domain=resolved_domain,
            # Structured addressing for probe webhooks: the typed tool-call
            # arguments, NOT model-written prose. Registered probes receive
            # these as `parameters` and can answer by key lookup. The
            # projection below is bounds-safe by construction, so it can never
            # make verify() fail on an otherwise-valid call.
            action_parameters=_scalar_params(kwargs),
        )
        if cert.block:
            raise ToolException(
                f"[Arcezia BLOCK] {cert.summary}\n"
                f"Trust: {cert.trust_score:.0%} | "
                # Plain words, not the raw field: it is three-state now, and a
                # printed "None" reads to a human as a value rather than as
                # "this server did not say".
                f"Fabrication: {cert.fabrication_status}"
            )
        if cert.review:
            raise ToolException(
                f"[Arcezia REVIEW] Human confirmation required: {cert.summary}\n"
                f"Missing evidence: {', '.join(cert.missing)}"
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
        return tool.invoke(kwargs)

    return StructuredTool.from_function(
        func=_verified,
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
    )
