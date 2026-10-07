"""
Anthropic Claude tool_use integration for Arcezia (SaaS client).

All verification runs in Arcezia's secure cloud via the proprietary engine.
The API surface is stable, so your integration code stays unchanged.

Usage:

    import anthropic
    from arcezia import Arcezia
    from arcezia.integrations.anthropic import ArceziaAnthropicGuard

    az    = Arcezia(api_key="ar_live_...", task="analyse sales data and generate report")
    guard = ArceziaAnthropicGuard(az)

    client = anthropic.Anthropic()
    message = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1024,
        tools=[...],
        messages=[{"role": "user", "content": "..."}],
    )

    # Intercept tool_use blocks before running them:
    safe_uses, blocked = guard.filter_tool_uses(message.content)

    for tool_use in safe_uses:
        result = run_tool(tool_use.name, tool_use.input)

    for block, cert in blocked:
        print(f"Blocked {block.name}: {cert.summary}")

Or use the all-in-one run loop:

    results = guard.run_tools(message.content, tool_dispatch=your_tool_fn)

Beyond Level 1
--------------
This adapter implements Level 1 (every tool call gated). Levels 2-4 are
reached through ``guard.az`` — the same Arcezia client, no private access:

    guard = ArceziaAnthropicGuard(az)

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

    # Level 3 — attach a person's approval (a model cannot produce this)
    guard.az.authorize(token=user_approval_token)

Levels explained in full: ``help(arcezia)`` or https://arcezia.com/docs

"""
from __future__ import annotations

import warnings

from typing import Any, Callable, Optional

from arcezia.client import Arcezia, ArceziaCertificate, ArceziaBlockError, ArceziaUnavailableError
from arcezia.integrations._common import (
    ACTION_KEYS, call_of, coerce_az, describe, pass_hold_reason, refuse_unless_clean,
)
from arcezia.integrations._params import scalar_params


# Tool name → domain mapping
_DOMAIN_MAP: dict[str, str] = {
    # database
    "execute_sql":      "database_ops",
    "run_query":        "database_ops",
    "query_database":   "database_ops",
    # filesystem / shell
    "bash":             "filesystem_ops",
    "write_file":       "filesystem_ops",
    "edit_file":        "filesystem_ops",
    "read_file":        "filesystem_ops",
    "delete_file":      "filesystem_ops",
    "execute":          "filesystem_ops",
    "run_command":      "filesystem_ops",
    # communications / deployments
    "send_email":       "agent_action",
    "send_message":     "agent_action",
    "send_slack":       "agent_action",
    "deploy":           "agent_action",
    "run_ci":           "agent_action",
}

# Fallback pattern matching for names not in the exact map
_DOMAIN_PATTERNS: dict[str, str] = {
    "sql":      "database_ops",
    "query":    "database_ops",
    "db":       "database_ops",
    "file":     "filesystem_ops",
    "shell":    "filesystem_ops",
    "bash":     "filesystem_ops",
    "git":      "filesystem_ops",
    "email":    "agent_action",
    "send":     "agent_action",
    "deploy":   "agent_action",
    "api":      "agent_action",
    "http":     "agent_action",
    "post":     "agent_action",
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


def _infer_domain(tool_name: str) -> str:
    if tool_name in _DOMAIN_MAP:
        return _DOMAIN_MAP[tool_name]
    name_lower = tool_name.lower()
    for kw, domain in _DOMAIN_PATTERNS.items():
        if kw in name_lower:
            return domain
    # No keyword matched — a fail-safe guess, not a fact. A wrong guess
    # surfaces later as an unexplainable hold, so say it once, plainly.
    _warn_inferred_domain(tool_name)
    return "agent_action"


def _describe_tool_use(tool_name: str, tool_input: dict) -> str:
    """One shared description for every adapter — see ``_common.describe``.

    Every key of the tool input is described, so what is verified is what
    runs. Keys that usually carry the action come first.
    """
    if not tool_input:
        return tool_name
    return describe(tool_name, kwargs=tool_input, priority=ACTION_KEYS)


class ArceziaAnthropicGuard:
    """
    Arcezia safety guard for Anthropic Claude tool_use (SaaS client).

    Wraps an Arcezia instance and intercepts Claude's tool_use content blocks
    before the agent's tool dispatch code runs them.

    Each tool_use block is verified against the appropriate domain constraints.
    BLOCK results raise ArceziaBlockError. REVIEW results surface missing
    evidence to the caller so they can prompt the user for authorization.
    """

    def __init__(
        self,
        arcezia: Arcezia = None,
        domain_map: Optional[dict[str, str]] = None,
        raise_on_block: bool = True,
        *,
        api_key: Optional[str] = None,
        task: Optional[str] = None,
        api_url: Optional[str] = None,
        capability_envelope: Optional[dict] = None,
        data_subject_reference: Optional[str] = None,
    ):
        """
        Args:
            arcezia:        Arcezia client instance (already initialised with task).
                            Omit and pass api_key=/task= to build one inline.
            domain_map:     Optional override for tool_name → domain mapping.
            raise_on_block: If True (default), raise ArceziaBlockError on BLOCK.
                            If False, return blocked items in the blocked list.
            data_subject_reference: Optional identifier for the person these
                            verifications are about. Record-only — never
                            changes a verdict; enables per-person audit lookup.
        """
        self.az = coerce_az(arcezia, api_key=api_key, task=task, api_url=api_url,
                       capability_envelope=capability_envelope,
                       data_subject_reference=data_subject_reference)
        self._domain_map = {**_DOMAIN_MAP, **(domain_map or {})}
        self._raise_on_block = raise_on_block

    def _get_domain(self, tool_name: str) -> str:
        if tool_name in self._domain_map:
            return self._domain_map[tool_name]
        return _infer_domain(tool_name)

    def verify_tool_use(self, tool_name: str, tool_input: dict) -> ArceziaCertificate:
        """
        Verify a single tool_use call.

        Returns an ArceziaCertificate. Raises ArceziaBlockError if blocked and
        raise_on_block=True.
        """
        domain = self._get_domain(tool_name)
        description = _describe_tool_use(tool_name, tool_input)

        cert = self.az.verify(
            action_type=tool_name,
            action_description=description,
            domain=domain,
            # Typed tool_use input, forwarded to your registered checks.
            action_parameters=scalar_params(tool_input),
        )

        if cert.block and self._raise_on_block:
            raise ArceziaBlockError(cert)
        if cert.degraded:
            raise ArceziaUnavailableError(
                RuntimeError(
                    f"Degraded certificate (unverified): {cert.summary}. "
                    "The action was not verified by the engine."
                )
            )
        # An ALLOW whose fabrication result was never reported is not a
        # clearance, and an ALLOW runs only on a pass naming this tool_use
        # (recomputed from its input). One helper, every adapter — see _common.
        refuse_unless_clean(cert, call_of(
            tool_name, domain, _describe_tool_use(tool_name, tool_input),
            scalar_params(tool_input)))

        return cert

    def filter_tool_uses(
        self, content: list
    ) -> tuple[list, list[tuple[Any, ArceziaCertificate]]]:
        """
        Filter a Claude message's content blocks.

        Returns:
            safe_uses:  list of tool_use blocks that passed verification
            blocked:    list of (tool_use_block, ArceziaCertificate) that were blocked

        Does NOT raise on block — returns blocked items for caller to handle.
        """
        safe_uses = []
        blocked = []

        for block in content:
            # Read both shapes. Previously a dict-shaped block failed the
            # hasattr() check and fell into safe_uses unverified — a message
            # that had been JSON round-tripped (logged, queued, replayed) would
            # have every tool call pass through as "safe". Non-tool blocks
            # (text, thinking) are still passed through, which is correct;
            # only tool_use must never skip verification.
            if isinstance(block, dict):
                b_type = block.get("type")
                b_name, b_input = block.get("name"), block.get("input")
            else:
                b_type = getattr(block, "type", None)
                b_name, b_input = getattr(block, "name", None), getattr(block, "input", None)
            if b_type != "tool_use":
                safe_uses.append(block)
                continue

            domain = self._get_domain(b_name)
            description = _describe_tool_use(b_name, b_input or {})

            cert = self.az.verify(
                action_type=b_name,
                action_description=description,
                domain=domain,
                # Typed tool_use input, forwarded to your registered checks.
                action_parameters=scalar_params(b_input or {}),
            )

            # Fail-closed: a degraded certificate means the verifier could not be
            # reached (unverified). Treat it as blocked, never safe — matching
            # verify_tool_use / run_tools. Otherwise a network outage would route
            # every tool call into safe_uses and execute it unverified.
            # `is_clean()`: an ALLOW whose fabrication channel
            # never reported has not been cleared, so it does not join the safe
            # list — it joins `blocked`, where the caller already handles it.
            # And the pass rule every adapter applies (see _common): an
            # ALLOW joins `safe_uses` only on a pass naming this tool_use, or
            # with no pass because there was no session.
            if (cert.allow and not cert.degraded and cert.is_clean()
                    and pass_hold_reason(cert, call_of(
                        b_name, domain, _describe_tool_use(b_name, b_input or {}),
                        scalar_params(b_input or {}))) is None):
                safe_uses.append(block)
            else:
                blocked.append((block, cert))

        return safe_uses, blocked

    def run_tools(
        self,
        content: list,
        tool_dispatch: Callable[[str, dict], Any],
    ) -> list[dict]:
        """
        Verify and execute all tool_use blocks in a Claude message.

        Args:
            content:       message.content from the Anthropic client
            tool_dispatch: callable(tool_name, tool_input) → tool result

        Returns list of result dicts:
            {"tool_use_id": ..., "tool_name": ..., "result": ..., "cert": cert}

        Blocked tools raise ArceziaBlockError if raise_on_block=True, or are
        included with result=None and the blocking cert otherwise.
        """
        results = []
        for block in content:
            # Accept both shapes: SDK content objects (block.type) and plain
            # dicts (block["type"]). A message that has been JSON round-tripped
            # — logged, queued, replayed — arrives as dicts, and silently
            # skipping those would mean the caller's tools never run at all and
            # they get an empty result list with no error to explain it.
            if isinstance(block, dict):
                b_type = block.get("type")
                b_name, b_input, b_id = block.get("name"), block.get("input"), block.get("id")
            else:
                b_type = getattr(block, "type", None)
                b_name, b_input, b_id = (getattr(block, "name", None),
                                         getattr(block, "input", None),
                                         getattr(block, "id", None))
            if b_type != "tool_use":
                continue

            cert = self.verify_tool_use(b_name, b_input or {})

            if cert.allow:
                tool_result = tool_dispatch(b_name, b_input or {})
                results.append({
                    "tool_use_id": b_id,
                    "tool_name": b_name,
                    "result": tool_result,
                    "cert": cert,
                })
            else:
                results.append({
                    "tool_use_id": b_id,
                    "tool_name": b_name,
                    "result": None,
                    "cert": cert,
                    "blocked": True,
                    "summary": cert.summary,
                    "needs_review": cert.review,
                })

        return results
