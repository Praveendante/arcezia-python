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

from typing import Any

from arcezia.client import ArceziaUnavailableError
from arcezia.integrations._common import coerce_az

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


def _infer_domain(tool_name: str) -> str:
    name_lower = tool_name.lower()
    for kw, domain in _TOOL_DOMAIN_MAP.items():
        if kw in name_lower:
            return domain
    return "agent_action"


# Execution entry points on a LangChain BaseTool. Those NOT explicitly gated on
# ArceziaTool must never fall through __getattr__ to the unwrapped tool — that
# would execute the action unverified. Gated here: run, arun, invoke, ainvoke.
_UNGATED_EXEC_ATTRS = frozenset({
    "_run", "_arun", "batch", "abatch", "stream", "astream",
    "func", "coroutine", "run_sync",
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
        input_str = (
            tool_input if isinstance(tool_input, str)
            else str(tool_input)
        )
        cert = self._az.verify(
            action_type=self._tool.name,
            action_description=input_str,
            domain=self._domain,
        )
        if cert.block:
            raise ToolException(
                f"[Arcezia BLOCK] {cert.summary}\n"
                f"Trust: {cert.trust_score:.0%} | "
                f"Fabrication: {cert.fabrication_detected}"
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
        # Fail closed: never proxy an execution entry point to the unwrapped
        # tool. Silently forwarding one (e.g. .batch/._run) would execute the
        # action with no verification at all.
        if name in _UNGATED_EXEC_ATTRS:
            raise AttributeError(
                f"ArceziaTool does not proxy {name!r} — calling it would bypass "
                f"verification. Use .run()/.invoke()/.ainvoke(), or "
                f"ArceziaToolkit.wrap_for_langgraph() for LangGraph and "
                f"tool-calling graphs."
            )
        return getattr(self._tool, name)


class ArceziaToolkit:
    """Wraps a list of LangChain tools with Arcezia verification.

    Construct with an existing client — ``ArceziaToolkit(az)`` — or with
    credentials directly — ``ArceziaToolkit(api_key="ar_live_...", task=...)``.
    """

    def __init__(self, az=None, *, api_key=None, task=None, api_url=None, capability_envelope=None):
        _require_langchain()
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
            action_description=str(kwargs),
            domain=resolved_domain,
        )
        if cert.block:
            raise ToolException(
                f"[Arcezia BLOCK] {cert.summary}\n"
                f"Trust: {cert.trust_score:.0%} | "
                f"Fabrication: {cert.fabrication_detected}"
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
        return tool.invoke(kwargs)

    return StructuredTool.from_function(
        func=_verified,
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
    )
