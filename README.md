# arcezia

Runtime safety verification for autonomous AI agents — official Python SDK.

All verification runs in Arcezia's secure cloud. The SDK makes HTTPS calls to
`api.arcezia.com` and returns typed result objects. Zero inference on the client.

## Install

```bash
pip install arcezia
```

Framework extras:

```bash
pip install "arcezia[langchain]"    # LangChain + LangGraph
pip install "arcezia[openai]"       # OpenAI Agents SDK
pip install "arcezia[anthropic]"    # Anthropic (Claude) SDK
pip install "arcezia[autogen]"      # AutoGen (legacy + modern)
pip install "arcezia[llamaindex]"   # LlamaIndex
pip install "arcezia[all]"          # everything
```

## Quick start

```python
import arcezia

az = arcezia.Arcezia(api_key="ar_live_...", task="clean up test records")

cert = az.verify(
    action_type="execute_sql",
    action_description="DELETE FROM analytics_staging WHERE date < '2024-01-01'",
    domain="database_ops",
)

if cert.degraded:
    # Arcezia could not be reached, so nothing was actually verified.
    # The default on_error="fail_closed" raises before you get here; check this
    # explicitly if you set on_error="review" or "fail_open".
    raise RuntimeError("Not verified — Arcezia unreachable")

# Gate on ALLOW positively — never on "not blocked". A verdict can be
# review (insufficient evidence, human confirmation required), which is
# neither allow nor block; treating it as runnable executes an action the
# engine explicitly declined to clear. cert.allow is True only for a
# grounded ALLOW.
if not cert.allow:
    raise RuntimeError(f"Not allowed ({'review' if cert.review else 'blocked'}): {cert.summary}")

db.execute(sql)  # only reached when the verdict is ALLOW
```

The framework adapters below do this for you: a degraded certificate always
raises `ArceziaUnavailableError` and the tool never executes.

## Framework integrations

**LangChain / LangGraph**
```python
from arcezia.integrations.langchain import ArceziaToolkit

toolkit = ArceziaToolkit(az)
safe_tools = toolkit.wrap(tools)                    # classic AgentExecutor
safe_tools = toolkit.wrap_for_langgraph(tools)      # LangGraph / tool-calling
```

**OpenAI function calling**
```python
from arcezia.integrations.openai import ArceziaGuard

guard = ArceziaGuard(az)
result = guard.execute_tool_call(
    tool_call=response.choices[0].message.tool_calls[0],
    tool_implementations={"execute_sql": db.execute},
)
# or wrap a single function:
safe_execute = guard.wrap_function("execute_sql", db.execute)
```

**CrewAI**
```python
from arcezia.integrations.openai import ArceziaCrewTool

class SafeSQLTool(ArceziaCrewTool):
    az = your_arcezia_client
    domain = "database_ops"
    name = "execute_sql"
    description = "Execute SQL"

    def _run(self, sql: str) -> str:
        return db.execute(sql)
```

**Anthropic (Claude tool_use)**
```python
from arcezia.integrations.anthropic import ArceziaAnthropicGuard

guard = ArceziaAnthropicGuard(az)
safe_uses, blocked = guard.filter_tool_uses(message.content)
```

**AutoGen**
```python
from arcezia.integrations.autogen import ArceziaAutoGenGuard

guard = ArceziaAutoGenGuard(az)
safe_fn = guard.wrap("execute_sql", db.execute, "database_ops")   # name first
safe_map = guard.wrap_many([                                      # list of tuples
    ("execute_sql", db.execute, "database_ops"),
    ("send_data", exporter.send, "agent_action"),
])
```

**LlamaIndex**
```python
from arcezia.integrations.llamaindex import ArceziaLlamaToolkit
safe_tools = ArceziaLlamaToolkit(az).wrap(tools)
```

**Any framework** (Pydantic AI, smolagents, Google ADK, Strands, …)
```python
from arcezia import guard_callable
safe_fn = guard_callable(run_sql, az)
```

**Claude Code CLI hook** (gated at the harness level — every tool call)
```bash
arcezia-hook install      # writes PreToolUse hook to ~/.claude/settings.json
export ARCEZIA_API_KEY=ar_live_...
export TASK="refactor auth module"
```

**Generic dispatch-loop agents (OpenCLAW, AutoAgent, …)**
```python
from arcezia.integrations.openclaw import DispatchGuard
guard = DispatchGuard(api_key="ar_live_...", task="...")
result = guard.dispatch("write_file", {"path": "/etc/app.conf", "content": "..."})
```

**n8n workflows**
```python
from arcezia.integrations.n8n import workflow_template, save_template
save_template("arcezia_gate.json")  # import into n8n
```

## Verdicts

| Verdict | Meaning |
|---|---|
| `cert.allow` | Safe to execute — all required evidence is grounded |
| `cert.block` | Execution blocked — violated constraint or fabrication detected |
| `cert.review` | Insufficient evidence — human confirmation required |

Two scores travel with every certificate — they measure different things:

| Field | Meaning |
|---|---|
| `cert.precondition_score` | `[0,1]` severity-weighted fraction of required preconditions **satisfied** |
| `cert.trust_score` | `[0,1]` fraction of evidence that is **externally grounded**, not agent-claimed |

When a verdict is not `ALLOW`, two more fields tell you why — and they answer
different questions:

| Field | Meaning |
|---|---|
| `cert.missing` | facts **you can act on**. Ground these and re-verify. Legitimately empty when nothing is caller-groundable. |
| `cert.unresolved` | **every** ungrounded fact, including ones held by a rule rather than directly required. Read this when `missing` is empty but the verdict still is not `ALLOW`. |
| `cert.denied_authority_axes` | axes you declared `False` in the capability envelope. An action that crosses one **cannot** reach `ALLOW`, and no token lifts it — widening means signing a new envelope. |
| `cert.semantic_block` | a **cross-step** danger pattern fired for this session — e.g. a sensitive read earlier and an outbound send now. `cert.chain_patterns` names which. |

`denied_authority_axes` is the most common reason a correctly-wired integration
stays stuck: declaring `"irreversible": False` and then verifying a `DELETE`
denies the very axis the action needs. If every fact is grounded and the verdict
still is not `ALLOW`, read it first.

### A dangerous *sequence* can have a safe-looking step

`cert.verdict` describes **this action**. A sequence can be dangerous while every
step in it is unobjectionable alone — read customer records, then send data to an
external host. When that happens the verdict stays `ALLOW` and
`cert.semantic_block` is `True`.

**`cert.allow` accounts for this**, so the gate below is correct as written and
you do not need a second check:

```python
if not cert.allow:              # False on a cross-step block, even when verdict == "ALLOW"
    raise RuntimeError(cert.summary)
run_tool(...)
```

If you gate on `cert.verdict == "ALLOW"` instead, you will miss it. Gate on
`cert.allow`.

## Declaring authority — how an action reaches `ALLOW`

Arcezia never infers what you permit; a principal declares it. Without that
declaration the scope of an action is unresolved, and an unresolved action is
never allowed — so a fresh session returns `REVIEW` even for a harmless read.
That is the design, not a misconfiguration: **Arcezia does not allow what it
cannot positively verify.**

Declare authority once, when the session opens:

```python
az = arcezia.Arcezia(task="read analytics for the weekly report")
az.start_session(capability_envelope={
    "max_scope": "batch",              # single_record | batch | limited | mass
    "structural_authority": {
        "sensitive_data":          True,   # may touch credentials/PII
        "outbound":                False,  # may send data out
        "persistent_mutation":     False,  # may change stored state
        "mass_scope":              False,  # may act on many records at once
        "trust_boundary_crossing": False,  # may call external principals
        "irreversible":            False,  # may take unrecoverable actions
    },
})

cert = az.verify(action_type="execute_sql",
                 action_description="SELECT COUNT(*) FROM events",
                 domain="database_ops")
# → ALLOW, with a signed credential
```

Those six axes are the complete set, and the names are exact. The SDK rejects
an unrecognised axis at `start_session` with a `ValueError` (v1.0.1+), because
a silently dropped axis would leave you believing you had granted or denied
something you had not. Over raw HTTP the server accepts the session but grants
nothing for the unknown axis and reports it back as `ignored_authority_keys`
in the response — never a silent grant either way. Two are easy to get wrong:
it is `persistent_mutation` (not `mutation`) and `trust_boundary_crossing`
(not `trust_crossing`).

The envelope is a *ceiling*, not a permission slip. Declaring
`outbound: False` and then attempting an outbound action does not produce
`ALLOW` — the action contradicts the authority you signed, so it is **blocked**,
and no runtime approval token can lift it. Widening authority is your act: sign
a new envelope. Declaring an axis `True` does not force `ALLOW` either; it only
removes that axis as a blocker, and every other check still applies.

**Declare all six axes.** An axis you *omit* is not a ceiling — it is an open
question, and a signed human token (`az.authorize(...)`) can answer it for the
session. That is the intended escalation path for work nobody pre-authorized,
but it means one `authorize()` call covers every axis you left unspecified. Only
an axis you declared `False` is a hard limit.

## The four levels

Each level is useful on its own and assumes the one below it. Every framework
adapter implements **Level 1** for you; Levels 2–4 are reached through the
adapter's `.az` property — the same client, no private access.

| Level | What you get | How |
|---|---|---|
| **1 — Drop-in gating** | Every tool call verified before it runs | `toolkit.wrap(tools)` |
| **2 — Chain verification** | Verify the whole *plan*, not just each step | `toolkit.az.verify_chain(...)` |
| **3 — Grounded evidence** | Arcezia asks *your* systems for facts instead of trusting the agent | register a probe webhook |
| **4 — Custom domains** | Your own constraint domains and compliance packs | `POST /v1/domains` |

**Level 2 — verify the plan before running any of it**
```python
result = toolkit.az.verify_chain({
    "steps": [
        {"id": "s1", "action_type": "execute_sql", "domain": "database_ops",
         "action_description": "SELECT ssn, name FROM customers"},
        {"id": "s2", "action_type": "send_email", "domain": "email_ops",
         "action_description": "email the list to external-analytics@gmail.com"},
    ]
}, stop_on_block=True)
# → overall_verdict "SEMANTIC_BLOCK", blocked_at "s2",
#   semantic_triggers [{"pattern_name": "structural_exfiltration", ...}]

# Response: {overall_verdict, blocked_at, steps[], semantic_triggers,
#            final_state, session_state_updated}
# There is no top-level "verdict" — per-step verdicts live under steps[].
if result["overall_verdict"] != "SAFE":
    # blocked_at names the step only when execution was actually stopped.
    # On REVIEW_REQUIRED nothing was blocked, so it is null — find the step
    # that needs attention in steps[] instead.
    step = result["blocked_at"] or next(
        (s["id"] for s in result["steps"] if s["verdict"] != "ALLOW"), None
    )
    abort(step)
```

`overall_verdict` is one of:

| Value | Meaning | `blocked_at` |
|---|---|---|
| `SAFE` | every step cleared | `null` |
| `BLOCKED` | a single step was blocked on its own merits | the step id |
| `SEMANTIC_BLOCK` | the steps are individually fine but **compose** into harm — check `semantic_triggers` (e.g. `structural_exfiltration`, `credential_exfiltration`, `recon_then_exfil`) | the step id |
| `REVIEW_REQUIRED` | a step needs evidence or human approval | `null` — nothing was blocked |

> **Describe the artefact, not just the operation.** Arcezia grounds its
> verdicts on concrete referents in the description — file paths, URLs,
> recipient addresses, credential and PII field names. `"SELECT ssn, name FROM
> customers"` names PII, so the read grounds as sensitive access and the chain
> above composes into `SEMANTIC_BLOCK`. `"SELECT email, name FROM customers"`
> names only column identifiers, so the same chain returns `REVIEW_REQUIRED`
> instead: still not `SAFE`, still not executable, but held for a human rather
> than positively identified as exfiltration.
>
> The rule this reflects: **a vague description degrades a verdict toward
> review — never toward approval.** Arcezia never allows what it could not
> verify, so imprecision costs you review latency, not safety. The framework
> adapters get this right automatically because they pass the real tool
> arguments; it is worth attention only when you hand-build chain manifests.

Chain steps do **not** inherit the session's capability envelope, so
`action_within_task_scope` stays unresolved and a chain will not reach `SAFE`
on the envelope alone. Ground it per step with an `evidence` dict (the key is
`evidence` — `agent_evidence` is ignored on chain steps):

```python
{"id": "s1", "action_type": "execute_sql", "domain": "database_ops",
 "action_description": "SELECT ssn, name FROM customers",
 "evidence": {"action_within_task_scope": True}}
```

`id` and `step_id` are accepted interchangeably. Note that `state_mutations`
may only *add* danger, never remove it: asserting a danger flag `True` is
accepted, asserting it `False` is rejected, and flags the engine derives for
itself (the `g_*` world-state namespace) are not caller-writable at all.

Audit after execution — did reality match the prediction?
```python
toolkit.az.verify_outcome(
    action_type="execute_sql",
    action_description="DELETE FROM orders WHERE test = true",
    outcome={"rows_affected": 50000},      # what ACTUALLY happened
    expected={"rows_affected": 1},         # what you intended
)
```

**Level 3 — ground the evidence.** Register a probe webhook so evidence is
`GROUNDED` rather than `CLAIMED`. Human intent can never be produced by a model,
so ground it explicitly:
```python
toolkit.az.authorize(user_token)              # user_explicit_authorization
toolkit.az.authorize_production(prod_token)   # production_explicit_authorization
```

These ground **different** constraints. Actions touching production generally
need both — `authorize()` alone will leave `production_explicit_authorization`
unresolved and the action stays in `REVIEW`.

> **Integrating over raw HTTP** (n8n, curl, another language)? Two things the
> SDK handles for you: the API is behind a WAF that rejects the default
> library agent strings (e.g. `Python-urllib/*`), so send an explicit
> `User-Agent` of your own; and the precondition score is on the wire as
> `precondition_score` (with `dc_score` kept as a legacy alias for older
> consumers) — the SDK exposes it as `cert.precondition_score`.

Full guide: [arcezia.com/docs](https://arcezia.com/developer-docs)

## Development mode

Use an `ar_test_` key for local development — infrastructure constraints
(backup APIs, capability envelopes, CI gates) are relaxed so you are not blocked
by production infra that does not exist on your laptop:

```python
az = arcezia.Arcezia(api_key="ar_test_...", task="...")   # dev mode by default
```

Development mode is only available on `ar_test_` keys and is re-checked
server-side. Live `ar_live_` keys are always pinned to production and cannot
point at `localhost`.

## Links

- [Developer documentation](https://arcezia.com/developer-docs)
- [Dashboard](https://app.arcezia.com)
