"""
arcezia — The official Arcezia Python SDK.

Thin HTTP client (~300 lines). Makes HTTPS calls to api.arcezia.com.
The proprietary verification engine runs in Arcezia's secure cloud.

Quick start:
    import arcezia

    az = arcezia.Arcezia(api_key="ar_live_...", task="clean up test records")

    cert = az.verify(
        action_type="execute_sql",
        action_description="DELETE FROM analytics_staging WHERE ...",
        domain="database_ops",
    )
    if cert.block:
        raise SafetyViolation(cert.summary)

    db.execute(sql)  # only reached if cert.allow

Decorator pattern:
    @az.gate(domain="database_ops", action_type="execute_sql")
    def run_query(sql: str):
        db.execute(sql)


THE FOUR LEVELS
---------------
Levels stack: each is useful alone, and each assumes the one below it.
The framework adapters implement Level 1 for you. Levels 2-4 are calls on
the client, reachable from any adapter through its ``.az`` property.

Level 1 — Drop-in gating (five minutes)
    Every tool call is verified before it executes.

        toolkit = ArceziaToolkit(api_key="ar_live_...", task="...")
        safe_tools = toolkit.wrap(tools)

Level 2 — Chain verification (verify the plan, not just the step)
    Catches plans that are unsafe as a sequence even when every individual
    step looks fine. State propagates between steps.

        result = toolkit.az.verify_chain({
            "steps": [
                {"step_id": "s1", "action_type": "execute_sql",
                 "domain": "database_ops",
                 "action_description": "SELECT email, name FROM customers"},
                {"step_id": "s2", "action_type": "send_email",
                 "domain": "agent_action",
                 "action_description": "email the list to an external address"},
            ]
        }, stop_on_block=True)

        # An ArceziaChainResult: .overall_verdict, .blocked_at, .steps,
        # .semantic_triggers, .human_summary, .degraded — plus .raw for
        # anything else the server sent (release, reason, ...).
        # No top-level "verdict" — per-step verdicts are under .steps.
        if not result.safe:
            abort(result.blocked_at)          # the step_id that failed

        # Dict indexing (result["overall_verdict"]) still works and is
        # deprecated; .safe is stricter — it is False on a degraded result,
        # whose overall_verdict reads "SAFE" under on_error="fail_open".

    Post-execution audit — did reality match the prediction?

        toolkit.az.verify_outcome(
            action_type="execute_sql",
            action_description="DELETE FROM orders WHERE test = true",
            outcome={"rows_affected": 50000},   # what ACTUALLY happened
            expected={"rows_affected": 1},      # what you intended
        )

Level 3 — Let your systems answer (stop trusting the agent's claims)
    Connect a check so your system answers instead of the agent:

        POST /v1/probes   {"domain": ..., "constraint_name": ...,
                           "webhook_url": ..., "secret": ...}

    A person's approval cannot be produced by a model — attach it explicitly:

        toolkit.az.authorize(token=request.headers["X-Arcezia-Token"])

Level 4 — Custom & compliance domains
    Define your own rules (Level 4 needs Level 3 to be useful).

        POST /v1/domains  {"name": "payment_ops_strict", ...}

Full guide: https://arcezia.com/docs


Integrations — all implement Level 1 and expose ``.az`` for Levels 2-4:
    from arcezia.integrations.langchain   import ArceziaToolkit
    from arcezia.integrations.openai      import ArceziaGuard, ArceziaCrewTool
    from arcezia.integrations.anthropic   import ArceziaAnthropicGuard
    from arcezia.integrations.autogen     import ArceziaAutoGenGuard
    from arcezia.integrations.llamaindex  import ArceziaLlamaToolkit
    from arcezia.integrations.openclaw    import DispatchGuard
    from arcezia.integrations.universal   import guard, guard_callable
    # Claude Code:  arcezia-hook install
    # n8n:          arcezia.integrations.n8n.workflow_template()
"""
from arcezia.client import (  # noqa: F401
    _SDK_VERSION,
    Arcezia,
    ArceziaCertificate,
    ArceziaChainResult,
    ArceziaOutcomeResult,
    ArceziaBlockError,
    ArceziaReviewError,
    ArceziaUpgradeRequired,
    ArceziaRateLimitError,
    ArceziaUnavailableError,
    ArceziaTransportError,
    ArceziaAPIError,
    ArceziaAuthError,
    ContractRefused,
    DeclarationsRetired,
    SigningKeyConflict,
)
from arcezia.integrations.universal import guard, guard_callable  # noqa: F401

__version__ = _SDK_VERSION
__all__ = [
    "Arcezia", "ArceziaCertificate", "ArceziaChainResult",
    "ArceziaOutcomeResult", "ArceziaBlockError", "ArceziaReviewError",
    "ArceziaUpgradeRequired", "ArceziaRateLimitError", "ArceziaUnavailableError",
    "ArceziaTransportError", "ArceziaAPIError", "ArceziaAuthError",
    "ContractRefused", "DeclarationsRetired", "SigningKeyConflict",
    "guard", "guard_callable",
]
