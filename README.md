# arcezia

Runtime safety verification for autonomous AI agents — official Python SDK.

All verification runs in Arcezia's secure cloud. The SDK makes HTTPS calls to
`api.arcezia.com` and returns typed result objects. Zero inference on the client.

## Docs and integrations

- [Developer docs](https://arcezia.com/developer-docs/): setup, every call, and what each answer means.
- [Integrations](https://arcezia.com/integrations/): step-by-step guides for Claude Code, LangChain and LangGraph, OpenAI, Anthropic, n8n, CrewAI, AutoGen and LlamaIndex.
- [Glossary](https://arcezia.com/glossary/): the terms used in the docs, in plain words.
- [Independent review](https://arcezia.com/security/independent-review/): an outside review of the live service, published in full and unchanged.

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
# service explicitly declined to clear. cert.allow is True only for a
# real ALLOW.
if not cert.allow:
    raise RuntimeError(f"Not allowed ({'review' if cert.review else 'blocked'}): {cert.summary}")

db.execute(sql)  # only reached when the verdict is ALLOW
```

### Reaching ALLOW on a fresh key

A read is held until two things are settled: what the call itself cannot show,
and where its target came from. A write additionally needs a person's approval.

1. **What a tool never does** goes in a **policy contract**, uploaded once per
   key with the admin role. (Absence declarations — `declare_absent`,
   `POST /v1/declarations` — are retired: a key created on or after
   24 September 2026 gets `DeclarationsRetired`.)
2. **What the job acts on** goes in the session's `resource_scope`: the exact
   tables, records, files, folders, addresses and hosts this job may touch.
   The task's words never clear a call: "last year's events" names the
   `events` table in English but not in Spanish, so a verdict read from the
   words would depend on the language. The scope you sign does not. It is a
   grant, so it counts **only from a signed envelope**: give the client your
   signing key and it signs every envelope it opens.

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Your principal key: keep it in your backend, never where the agent can read it.
private_key = Ed25519PrivateKey.generate()
az = arcezia.Arcezia(api_key="ar_live_...", task="report on last year's events",
                     signing_key=private_key)   # envelopes this client opens are signed
az.register_token_key(private_key.public_key())  # once per account; owner or admin role

# Step 0, once per key: what execute_sql never does, per tool, never "*".
# `pack` keeps the built-in domain's rules for the tool's calls.
contract = az.register_contract({
    "tools": {"execute_sql": {"pack": "database_ops",
                              "not_present": ["outbound", "trust_boundary_crossing",
                                              "sensitive_data"]}},
}, name="reports")
sql_domain = contract["domains"]["execute_sql"]   # "c_reports__execute_sql"

az.start_session(capability_envelope={          # what this agent may do at most
    "allowed_domains": [sql_domain],
    "allowed_action_types": ["execute_sql"],
    "resource_scope": ["events"],               # what this job acts on (signed)
})
cert = az.verify(action_type="execute_sql", domain=sql_domain,
                 action_description="SELECT COUNT(*) FROM events")
cert.verdict     # ALLOW — cert.credential is set.
                 # Without "resource_scope" (or with an unsigned envelope) the
                 # same read is REVIEW, and cert.next_steps names the scope.

cert = az.verify(action_type="execute_sql", domain=sql_domain,
                 action_description="UPDATE customers SET tier='pro' WHERE id = 42")
cert.verdict     # REVIEW — a write needs an approval the agent cannot give itself
cert.release     # ["approval:production", "approval:user", "check:verified_recent_backup"]

# Attach the approvals your backend minted after a person approved (signed
# with your registered key — see "Registering your signing key"):
az.authorize(signed_user_token).authorize_production(signed_production_token)
# ...and let your own system confirm the backup: connect a check named
# verified_recent_backup for sql_domain (POST /v1/probes, see Level 3).
cert = az.verify(action_type="execute_sql", domain=sql_domain,
                 action_description="UPDATE customers SET tier='pro' WHERE id = 42")
cert.verdict     # ALLOW
```

A made-up string is not an approval: `authorize("approved")` is refused.
`signed_user_token` comes from `arcezia.signing.mint_token(private_key,
api_key_id=..., token_type="user", session_id=az.session_id)`, and
`signed_production_token` the same with `token_type="production"`.

Once a contract covers a tool, verify that tool **only** under the domain the
contract compiled for it (`contract["domains"][tool]`). A call to it under any
other domain is refused, so a covered tool can never skip its contract's rules.
Tools the contract does not name keep their built-in domains.

What `not_present` can and cannot do: what the statement itself shows always
counts, whatever the contract says. What no statement can show (how many rows a
real WHERE touches, whose rows they are) is your database's answer: connect a
check so your system answers instead of the agent. And an agent that claims an
approval it does not have is `BLOCK` with `cert.fabrication_detected == True`.

`register_contract` raises `ContractRefused` (with `.problems`) when the service
refuses the contract, for example a rule that can never hold or refuse any
call. Both `ContractRefused` and `DeclarationsRetired` are importable from
`arcezia`.

The framework adapters below do this for you: a degraded certificate always
raises `ArceziaUnavailableError` and the tool never executes.

Which built-in domains a key can use depends on its plan. `database_ops`,
`filesystem_ops` and `agent_action` are on every plan, `email_ops` needs Hobby,
`payment_ops` needs Business, and `legal_ops` needs Enterprise. A call to a
domain your plan does not include raises `ArceziaUpgradeRequired`.

## When Arcezia is unreachable

One setting, `on_error`, decides this — and it applies to **every** method that
makes a network call, not only `verify()`.

| method | `fail_closed` (default) | `review` | `fail_open` |
| --- | --- | --- | --- |
| `verify` | raises `ArceziaUnavailableError` | synthetic REVIEW cert | synthetic ALLOW cert |
| `verify_chain` | raises | `ArceziaChainResult(overall_verdict="REVIEW_REQUIRED", degraded=True)` | `overall_verdict="SAFE"`, `degraded=True` |
| `verify_outcome` | raises | synthetic REVIEW result | synthetic ALLOW result |
| `start_session` | raises | pending, retried on next call | pending, retried on next call |
| `authorize`, `authorize_production` | raises **and** keeps the token pending | pending, retried | pending, retried |
| `usage` | raises | raises | raises |
| `audit_subject` | raises | raises | raises |

Three properties worth quoting in a security review:

1. **Under the default, an outage never becomes an ALLOW.** There is exactly one
   place in the client that chooses between raising and returning a degraded
   value, and under `fail_closed` it always raises.
2. **A degraded verdict is identifiable and carries no credential.**
   `cert.degraded` — and `result.degraded` on a chain, the same field name on
   all three result types — is set only by local construction; it is stripped
   from anything parsed off the wire, so a response cannot claim it and a
   synthetic ALLOW cannot be replayed as a verified one. Note that a degraded
   chain result's `overall_verdict` is the string `"SAFE"` under `fail_open`:
   use `result.safe`, which is False on a degraded result, rather than
   comparing the string.
3. **A human approval is never silently dropped.** A failed
   `POST /v1/authorize` leaves the token pending and re-sends it before the next
   verdict is asked for; under the default it also raises, so the person who
   clicked Approve finds out.

A deterministic `4xx` — including an HTML `403` from the edge — is an *answer*, not an
outage. It raises `ArceziaAPIError` under all three settings, `fail_open`
included: an edge-blocked deployment fails loudly rather than running every
tool unverified while looking healthy.

`on_error` belongs to the client. Adapters that take it (`DispatchGuard`) build
their client with it; passing it alongside an `az` that disagrees raises rather
than being ignored.

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

def execute_sql(query: str) -> str:   # parameter names = your tool schema's
    return db.execute(query)

guard = ArceziaGuard(az)
result = guard.execute_tool_call(
    tool_call=response.choices[0].message.tool_calls[0],
    tool_implementations={"execute_sql": execute_sql},
)
# or wrap a single function:
safe_execute = guard.wrap_function("execute_sql", execute_sql, domain="database_ops")
```
The guard calls each implementation with the tool call's arguments as
keywords, so its parameter names must match the tool schema (`query` here).
Passing a method whose parameters are named differently raises `TypeError`.

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

Every adapter that raises on a hold raises `ArceziaBlockError` (BLOCK) or
`ArceziaReviewError` (REVIEW). Both subclass `RuntimeError` and carry the full
certificate as `err.cert`: `err.cert.summary` says why, `err.cert.release`
says what would release a hold, and `err.cert.reason` why a call was refused. (LangChain raises its own `ToolException`.)

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
arcezia-hook install      # merges a PreToolUse hook into ~/.claude/settings.json
export ARCEZIA_API_KEY=ar_live_...
export TASK="refactor auth module"
```
`install` never overwrites your settings: a file that does not parse as a JSON
object raises and names the path, and every write copies the original to
`settings.json.bak-<timestamp>` first. The hook always exits 0 and always prints
a decision — a crash denies rather than passing the tool through, because the
harness reads a non-zero exit as a *non-blocking* error. `WebFetch` and
`WebSearch` are verified as outbound actions, not treated as reads.

What the hook does in the next release:
- **Every tool is verified, reads included.** `Read`, `Grep`, `Glob`, `LS` and
  `NotebookRead` are verified as the shell read each one performs (`cat`,
  `grep`, `find`, `ls`), because what they return reaches the model and every
  later call. Only the harness's own to-do tools are not verified.
- **One session per Claude Code session.** It keeps one Arcezia session for each
  Claude Code session and API key, stored under `~/.claude/arcezia-sessions/`. A
  sensitive read is remembered when the next step is checked.
- **Your envelope and session rules.** `~/.claude/arcezia.json` may hold a
  `capability_envelope` and `principal_rules` (your own restrictions, in the
  form `start_session(principal_rules=...)` takes). Every session the hook opens
  carries both, and a stored session opened under different ones is not
  re-attached. When a session that carried them expires, the service refuses
  to re-open it bare (409 `session_expired`) and the hook opens a new one with
  them; see "Continuing a session from another process".
- **The task.** If `TASK` is not set, the task is your first prompt in the
  Claude Code session (up to 2,000 characters), sent to Arcezia with each
  check. Harness records (command wrappers, IDE context, compaction summaries)
  are skipped. Set `ARCEZIA_TASK_FROM_TRANSCRIPT=0` to send no task instead.
- **Shell commands by program.** A shell command is checked under its program's
  own name, such as `git_status`, `pip_install`, `run_tests`, `terraform_plan` or
  `aws_s3_ls`, only when the program is named bare (`git`, not `./git` or
  `/tmp/x/git`).
- **Commands the hook cannot read safely.** Unknown programs, redirections,
  substitutions, a `#` starting a word, and options that delete, write a file or
  run another program (`find -delete`/`-exec`, `curl -o`, `wget -O`,
  `terraform apply -destroy`, `git branch -D`, `git remote set-url`,
  `git stash drop`) stay `run_shell`.
- **Compound commands.** `a && b` is checked one part at a time, and the strictest
  verdict wins.
- **A deadline.** The hook decides within 45 seconds and denies if no verdict
  arrived by then. `install` sets the harness `timeout` for the hook to 60
  seconds, so the harness never stops it undecided.
- **Your contracts.** A contract entry for `run_shell` does not cover the
  typed names. Name the typed tools you rely on.

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
The template's human-approval path needs two things from you before it enforces
anything: a signing key registered at `POST /v1/account/token_key`, and an n8n
HTTP-header credential named "Arcezia Approval Resume Auth" for the Wait node's
resume URL. The approval token is minted by *your* backend after a person
approves; the workflow supplies no default for it and stops the run when the
resume carries none.

## Verdicts

| Verdict | Meaning |
|---|---|
| `cert.allow` | Safe to execute — everything the action needs is answered |
| `cert.block` | Execution blocked — a rule was broken or fabrication detected |
| `cert.review` | Insufficient evidence — human confirmation required |

When a verdict is not `ALLOW`, the certificate says what to do next:

| Field | Meaning |
|---|---|
| `cert.release` | on a `REVIEW`: what would let the call proceed. Each item is `approval:user`, `approval:production`, `check:<name>` (have your registered check answer), `contract:<fact>`, `scope:<envelope field>`, `declare:<effect>` (state in your contract that the tool never has that effect), or `person`. `cert.missing` lists the same items. |
| `cert.reason` | on a `BLOCK`: why it was refused: `fabrication`, `contract:<your rule>`, `scope:<envelope field>`, `ceiling:<effect>` (your envelope forbids it), or `safety:<effect>` / `safety` (a built-in rule). `cert.violated` lists the same items. |
| `cert.next_steps` | the same items, one plain sentence each. `cert.summary` is built from them. |
| `cert.denied_authority_axes` | axes you declared `False` in the capability envelope. An action that crosses one **cannot** reach `ALLOW`, and no token lifts it — widening means signing a new envelope. Three-state: a list is what the server reported; `None` means the server did **not** report it, which is never the same as "nothing was denied". Read it with `cert.denied_axes_or_unknown()`, which returns `(axes, reported)`. |
| `cert.fabrication_detected` | three-state as well: `True` (the agent claimed something that is not true), `False` (none found), `None` (not reported). `cert.is_clean()` is the fail-closed reading — it is False on `None`, because an absent accusation is not a clearance. `cert.allow` / `.block` / `.review` gate on `verdict`, which is the decision and is always present. |
| `cert.semantic_block` | a **cross-step** risk formed in this session — e.g. a sensitive read earlier and an outbound send now. `cert.chain_patterns` describes it in plain words. |
| `cert.chain_status` | three-state: `"SEMANTIC_BLOCK"` (the cross-step check ran and fired), `"CLEAR"` (it ran and found nothing), or `None` (it **did not run** — there was no session, or the action was already held or refused on its own). `cert.chain_status_reported` answers "did it run"; `cert.is_clean()` does **not** require it. If your deployment always runs sessions and a missing check should stop the action, write `if not (cert.is_clean() and cert.chain_status_reported): halt()`. |
| `cert.reduced_mode` | `True` when the service answered in reduced mode (the verdict is still fail-safe); `cert.incident` is a code to quote to support. |
| `cert.raw["unrequested_arguments"]` | on a `REVIEW`, when you passed `principal_request=`: the arguments whose value the user's request never gave. |

`held_by`, `blocked_by` and `to_reach_allow` are deprecated (they now map from
`release` / `reason` and warn once). `trust_score` and `precondition_score` are
`None`: the service no longer reports scores.

`verify(..., principal_request="the user's request as typed")` supplies that
request. It is read as values only, decides nothing and is not stored.
`start_session(principal_rules={...})` adds the user's own restrictions for the
session, in the policy-contract rule form (`never` / `require` rules over your
facts). They can only tighten; a malformed document is refused (HTTP 422) and
is not kept for later sessions; `principal_rules=None` clears them.

`denied_authority_axes` is the most common reason a correctly-wired integration
stays stuck: declaring `"irreversible": False` and then verifying a `DELETE`
denies the very axis the action needs. If nothing is left open and the verdict
still is not `ALLOW`, read it first.

### A dangerous *sequence* can have a safe-looking step

A sequence can be dangerous while every step in it is unobjectionable alone —
read customer records, then send data to an external host. Within a session,
an action that would otherwise be cleared is checked against what earlier
cleared steps did. When a pattern fires, `cert.semantic_block` is `True`, the
action is held (`REVIEW`) or refused (`BLOCK`), and no credential is issued.

**`cert.allow` accounts for this**, so the gate below is correct as written and
you do not need a second check:

```python
if not cert.allow:              # False on a cross-step finding
    raise RuntimeError(cert.summary)
run_tool(...)
```

Gate on `cert.allow`, not on `cert.verdict == "ALLOW"`. To check a whole plan
before any of it runs, use `verify_chain` (Level 2 below).

## Declaring authority — how an action reaches `ALLOW`

Two things you say decide what can be cleared, and until you say them actions
are held — so a fresh key returns `REVIEW` even for a harmless read. That is the
design, not a misconfiguration.

- **What the session may do** — the capability envelope, given when the
  session opens.
- **What each tool never does** — a policy contract, uploaded once per key.
  Some effects cannot be seen in the call itself: whether a query sends data
  anywhere, reaches outside your organisation, or touches sensitive data. When
  nothing settles one of these it is left unresolved and the action is held,
  never assumed safe. `not_present` settles it. State an effect absent only if
  it is true of every call of that tool; it never overrides what the call
  itself shows.

```python
az = arcezia.Arcezia(task="count the rows in the events table for the weekly report",
                     signing_key=private_key)   # signs the envelope (resource_scope is a grant)

contract = az.register_contract({            # once per key; admin role
    "tools": {"execute_sql": {"pack": "database_ops",
                              "not_present": ["outbound", "trust_boundary_crossing"]}},
}, name="analytics")
sql_domain = contract["domains"]["execute_sql"]

az.start_session(capability_envelope={
    "allowed_domains": [sql_domain],
    "allowed_action_types": ["execute_sql"],
    "max_scope": "batch",              # single_record | batch | limited | mass
    "structural_authority": {
        "sensitive_data":          True,   # may touch credentials/PII
        "outbound":                False,  # may send data out
        "persistent_mutation":     False,  # may change stored state
        "mass_scope":              False,  # may act on many records at once
        "trust_boundary_crossing": False,  # may call external principals
        "irreversible":            False,  # may take unrecoverable actions
    },
    "resource_scope": ["events"],      # the tables/records/files/hosts this job acts on
})

cert = az.verify(action_type="execute_sql",
                 action_description="SELECT COUNT(*) FROM events",
                 domain=sql_domain)
# → ALLOW, with a signed credential. If it comes back REVIEW,
#   cert.release names what is still open.
```

What the job acts on is the principal's signed statement, `resource_scope`:
exact tables (`"events"`, or `"analytics.events"`), record identities, files
and folders (absolute paths; a folder covers what is under it), addresses
(`"ana@example.com"`, or `"@example.com"` for a domain) and hosts. A pattern
(`*`) is refused. It counts only from a signed envelope (pass `signing_key=` to
the client, as above, or sign it yourself with
`arcezia.signing.mint_envelope_token`). The task's words can only hold a call,
never clear one: a call on a table the task never names and the scope does not
list is held for a person. The envelope alone does not clear the
read: without the contract the same call is `REVIEW`, with `cert.release`
naming `declare:trust_boundary_crossing` (state it in your contract). Absence declarations (`declare_absent`,
`POST /v1/declarations`) are retired; a key created on or after 24 September
2026 gets `DeclarationsRetired`.

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
a new envelope. Declaring an axis `True` does not guarantee `ALLOW` either; it only
removes that axis as a blocker, and every other check still applies.

**Declare all six axes.** An axis you *omit* is not a ceiling — it is an open
question, and a signed human token (`az.authorize(...)`) can answer it for the
session. That is the intended escalation path for work nobody pre-authorized,
but it means one `authorize()` call covers every axis you left unspecified. Only
an axis you declared `False` is a hard limit.

The tool and domain lists are hard limits too. A tool missing from
`allowed_action_types`, or a domain missing from `allowed_domains`, is blocked in
every domain, custom domains included. A token for one call does not lift that.

Two more envelope fields narrow or widen authority per tool:

```python
az.start_session(capability_envelope={
    "allowed_action_types": ["lookup_order", "issue_refund"],
    # effects granted to ONE tool, not the whole session
    "tool_authority": {"issue_refund": ["outbound", "persistent_mutation"]},
    # call caps; the call past a cap is blocked
    "session_limits": {"max_calls": 50, "max_calls_per_tool": {"issue_refund": 5}},
})
```

- A session axis you set to `False` still beats a tool grant.
- Sending sensitive data out in one call needs `"sensitive_outbound"` granted to
  that tool by name. Granting `sensitive_data` and `outbound` separately is not
  enough.
- Limits count the calls Arcezia allowed in the session, including chain steps.

In production, sign the envelope with `arcezia.signing.mint_envelope_token` and pass
it to the first `verify()` as `capability_envelope_token`.

### Registering your signing key

Approvals and signed envelopes are checked against one Ed25519 public key per
account. Register it once; a setup script can run this safely more than once:

```python
from arcezia.signing import public_key_fingerprint

status = az.token_key_status()      # {"registered", "fingerprint", "api_key_id"}
KEY_ID = status["api_key_id"]        # the `acct` value for mint_token / mint_envelope_token
az.register_token_key(public_key)   # no-op if this key is already registered
```

`register_token_key` raises `SigningKeyConflict` (with `.fingerprint`) and
changes nothing when a *different* key is registered, because approvals signed
with that key would stop working. Pass `replace=True` to replace it, or
`register_token_key(None, replace=True)` to remove it. Compare
`status["fingerprint"]` with `public_key_fingerprint(your_public_key)` to see
which key is on record. Both calls need the owner or admin role.

### Approval for one exact call

A token from `authorize()` normally approves for the whole session. Payments in
`payment_ops` need more. There, a token counts only when it is bound to the exact
call: the same tool, payee, amount and currency. Policy contracts with
`approval_must_bind` work the same way.

`payment_ops` is included from the Business plan. Before a payment can be
cleared, your own systems answer the payments pack's four checks:
`aml_check_passed`, `duplicate_transaction_absent`, `fraud_review_cleared` and
`sanctioned_entity_check_passed`. Connect a check for each once
(`POST /v1/probes` with `"domain": "payment_ops"` and the check's name; see
Level 3). Until all four answer, every payment is held, approval or not. With
them connected, the snippet below goes `REVIEW` → `ALLOW`.

```python
from arcezia.signing import mint_token

az.start_session(capability_envelope={       # name the tool and its domain
    "allowed_domains": ["payment_ops"],
    "allowed_action_types": ["send_payment"],
})
cert = az.verify(action_type="send_payment", domain="payment_ops",
                 action_description="pay invoice 4471: $1,240 to Acme Ltd")
if cert.review:                              # release: ["approval:user"]
    # after the person approves, in your backend:
    token = mint_token(private_key, api_key_id=KEY_ID, token_type="user",
                       session_id=az.session_id,
                       action=cert.action_binding)
    az.authorize(token)
    cert = az.verify(action_type="send_payment", domain="payment_ops",
                     action_description="pay invoice 4471: $1,240 to Acme Ltd")
# → ALLOW
```

If the amount or payee changes, it is a different call and needs a new approval.

### When the agent's own statement is wrong

`agent_evidence` can never clear an action, but it can get one blocked.
Suppose your system answers a fact differently from what the agent stated. The
verdict is then `BLOCK` and `cert.fabrication_detected` is `True`. Your system
can answer through a probe webhook, including a `__fields__` webhook. The same
happens when Arcezia's own reading of the action contradicts the statement.
`cert.summary` names the statement. Drop the false statement and verify again.

## The four levels

Each level is useful on its own and assumes the one below it. Every framework
adapter implements **Level 1** for you; Levels 2–4 are reached through the
adapter's `.az` property — the same client, no private access.

| Level | What you get | How |
|---|---|---|
| **1 — Drop-in gating** | Every tool call verified before it runs | `toolkit.wrap(tools)` |
| **2 — Chain verification** | Verify the whole *plan*, not just each step | `verify_chain(...)` on a client of its own |
| **3 — Your systems answer** | Arcezia asks *your* systems instead of trusting the agent | connect a check (`POST /v1/probes`) |
| **4 — Custom domains** | Your own rules and compliance packs | `POST /v1/domains` |

**Level 2 — verify the plan before running any of it**
```python
# A plan is a dry run, so give it its own client and session: its steps must
# not leave marks on the live session.
plan_az = arcezia.Arcezia(task="send the weekly report to the analytics partner")
plan_az.start_session(capability_envelope={
    "allowed_domains": ["database_ops", "agent_action"],
    "allowed_action_types": ["execute_sql", "send_data"],
    "max_scope": "limited",
    "structural_authority": {"sensitive_data": True, "outbound": True,
                             "trust_boundary_crossing": True,
                             "persistent_mutation": False, "mass_scope": False,
                             "irreversible": False},
})
result = plan_az.verify_chain({
    "steps": [
        {"step_id": "s1", "action_type": "execute_sql", "domain": "database_ops",
         "action_description": "SELECT ssn, name FROM customers WHERE id = 42"},
        {"step_id": "s2", "action_type": "send_data", "domain": "agent_action",
         "action_description": "send the result to https://analytics-partner.example.com/ingest"},
    ]
}, stop_on_block=True)
# → overall_verdict "SEMANTIC_BLOCK", blocked_at "s2",
#   reason ["safety:outbound", "safety:trust_boundary_crossing", "safety:sensitive_data"]
#   and semantic_triggers [{plain, severity}]   (in plain words)
# This session may send data out, and neither step is refused alone; the
# sequence — personal data read, then sent to an outside host — is.

# An ArceziaChainResult: .overall_verdict, .blocked_at, .steps,
# .semantic_triggers, .human_summary, .degraded, .safe — plus .raw for
# anything else the server sent (release, reason).
# There is no top-level "verdict" — per-step verdicts live under .steps.
if not result.safe:
    # blocked_at names the step only when execution was actually stopped.
    # On REVIEW_REQUIRED nothing was blocked, so it is None — find the step
    # that needs attention in .steps instead.
    step = result.blocked_at or next(
        (s["id"] for s in result.steps if s["verdict"] != "ALLOW"), None
    )
    abort(step)
```

The request field is `step_id`; the response's `steps[]` echo it as `id`.

A step that needs approval of that exact call (a payment, for example) is not
cleared by a session-wide token. Check such steps with `verify()` and a bound
token (see "Approval for one exact call"). Per-step approvals inside
`verify_chain` are planned.

**Continuing a session from another process.** `az.session_id` is the session a
client runs under. `az.attach_session(session_id)` makes a new client continue it:
same task, same envelope, same session rules, same history of earlier steps. No
network call is made until the next request. If the service no longer has that
session (it expired):

- if it carried a capability envelope or session rules, the request is refused
  with **409 `session_expired`** — it is never silently re-opened without the
  restrictions it had. Open a new session with `start_session(...)`;
- if it carried neither, the service opens a new session under the same id with
  the request's task only (no earlier history carries over).

`verify_chain` returned a plain `dict` before 1.0.5. Indexing still works for
every documented key — `result["overall_verdict"]`, `result["blocked_at"]`,
`result["steps"]`, `result["summary"]` — and is
**deprecated**. Prefer `result.safe` over `result["overall_verdict"] != "SAFE"`:
the string reads `"SAFE"` on a degraded result too, and `.safe` does not.

**Other behaviour changes in 1.0.5** (the fail-closed direction, deliberately):

- A response that omits `fabrication_detected` now parses as `None` — *not reported*
  — rather than `False`. `cert.allow` / `cert.block` / `cert.review` are unchanged; they
  read `verdict`, which is always present. But every framework adapter now gates on
  `cert.is_clean()`, which treats *not reported* as not clean. No current server omits
  the field, so no live deployment is affected; a much older self-built server would
  now be refused at the adapter rather than executed against.
- Constructing an adapter with a client set to `on_error="fail_open"` emits one warning
  explaining that the adapter still refuses a degraded (synthetic) certificate. The
  behaviour is unchanged; the warning exists so the contradiction cannot be hit silently.

`overall_verdict` is one of:

| Value | Meaning | `blocked_at` |
|---|---|---|
| `SAFE` | every step cleared | `null` |
| `BLOCKED` | a single step was blocked on its own merits | the step id |
| `SEMANTIC_BLOCK` | the steps are individually fine but **together** do harm — `reason` and `semantic_triggers` say which effects | the step id |
| `REVIEW_REQUIRED` | a step needs evidence or human approval | `null` — nothing was blocked |

> **Describe the real action.** A plan that reads personal data and then sends
> data out is refused or held. A vague description moves a verdict toward
> review, never toward approval, so imprecision costs you review time, not
> safety. The framework adapters pass the real tool arguments for you; this is
> worth attention only when you hand-build chain manifests.

Chain steps run under the session's capability envelope when you pass the
`session_id` of a session opened with one: that is what sets each step's
scope, so open the session with its envelope
first (`start_session(capability_envelope=...)`), then run the chain in it. A
chain without a session has no envelope and will not reach `SAFE` on scope.

A step's `evidence` dict is the agent's own statement. It cannot settle a fact
only your systems or you can confirm (scope, approvals, backups, scans): stating
one of those is treated as the agent asserting what it cannot know. Confirm such
facts through the envelope, a signed approval, or a check you connect.

```python
{"id": "s1", "action_type": "execute_sql", "domain": "database_ops",
 "action_description": "SELECT name FROM customers WHERE id = 42"}
```

`id` and `step_id` are accepted interchangeably. Note that `state_mutations`
may only *add* danger, never remove it: asserting a danger flag `True` is
accepted, asserting it `False` is rejected, and some session flags are set
only by the service and cannot be sent.

Audit after execution — did reality match the prediction?
```python
toolkit.az.verify_outcome(
    action_type="execute_sql",
    action_description="DELETE FROM orders WHERE test = true",
    outcome={"rows_affected": 50000},      # what ACTUALLY happened
    expected={"rows_affected": 1},         # what you intended
)
```

**Level 3 — let your systems answer.** Connect a check (`POST /v1/probes`) so
your system answers instead of the agent. A person's approval can never be
produced by a model, so attach it explicitly:
```python
toolkit.az.authorize(user_token)              # release item approval:user
toolkit.az.authorize_production(prod_token)   # release item approval:production
```

These are **different** approvals. Actions touching production generally
need both — with `authorize()` alone, `cert.release` still names
`approval:production` and the action stays in `REVIEW`.

> **Integrating over raw HTTP** (n8n, curl, another language)? Two things the
> SDK handles for you: the API rejects the default library agent strings
> (e.g. `Python-urllib/*`), so send an explicit
> `User-Agent` of your own; and read `release` (REVIEW) / `reason` (BLOCK) from
> the JSON body for what to do next.

Full guide: [arcezia.com/docs](https://arcezia.com/developer-docs)

## Enforcing at the resource

An `ALLOW` carries a single-use credential (`cert.credential`). The strongest
pattern is an endpoint that refuses work without one: a gate that was skipped
then has nothing to present, so the action cannot succeed. Placement of a check
can be forgotten; a missing token cannot be.

Validate it from the resource *before* executing:

```python
answer = az.validate_credential(cert)          # pass the certificate, not the token
if not answer["ok"]:
    refuse(answer["error"])                     # e.g. "action_digest_mismatch"
```

Passing the certificate is what makes the check strict. It sends
`cert.action_digest` — the sha256 of the action the verdict was actually about —
alongside the token, so the answer is "this credential was issued for **this**
action". With only `action_type`, a credential minted for a single-row `SELECT`
authorises a table-dropping statement of the same type in the same session.

A refusal comes back as `{"ok": False, "error": …}`; only a transport failure
raises, and a raise means *not validated* — there is no degraded fallback here.
Over raw HTTP the same call is `POST /v1/validate_credential` with `token` and
`action_digest`; the n8n template forwards both as `X-Arcezia-Credential` and
`X-Arcezia-Action-Digest`.

### Refusing without a pass: `require_pass`

The framework adapters check the verdict inside the agent's process, and run an
`ALLOW` only when its single-use pass names the call about to run (or when no
pass was issued because there was no session). That is a consistency check, not
a lock: an agent that can reach your service directly never meets it. The lock
is your service refusing to act unless it is handed a valid pass for exactly
the call it is about to perform:

```python
from arcezia.actuator import require_pass, PassRefused

def handle_query(request):
    try:
        require_pass(request.headers.get("X-Arcezia-Pass"),
                     "execute_sql", "database_ops", request.sql,
                     api_key=ARCEZIA_API_KEY, resource_id="orders-db")
    except PassRefused as refused:
        return 403, str(refused)          # refused.reason says which check failed
    return run(request.sql)
```

The service names the call from its own request — tool, rules, description and
typed arguments, exactly as they were sent for verification — and never copies
them from the agent's certificate. The check spends the pass, so call it once,
right before acting. Every failure refuses: no pass, a pass for another call,
a spent or expired pass, an unreachable verifier, or an answer that does not
confirm the pass was bound to this call. Online (the default), use the API key
the verifications ran under.

To check without calling home, have the agent name your service when it
verifies (`az.verify(..., audience="orders-db")`), pin the service's pass key
fingerprint (from `GET /v1/account/pass_keys`, compared out of band), and keep
one `UsedPasses` register for the life of your service:

```python
from arcezia.actuator import fetch_pass_keys, require_pass, UsedPasses

KEYS = fetch_pass_keys([PINNED_FINGERPRINT], api_key=ARCEZIA_API_KEY)
USED = UsedPasses()

require_pass(request.headers.get("X-Arcezia-Pass"), "execute_sql", "database_ops",
             request.sql, mode="offline", pass_keys=KEYS,
             resource_id="orders-db", used=USED)
```

A pass that names one service is valid at that service only (online too), so
the local register is complete for it. `mode="both"` checks offline first and
then spends the pass online. A JavaScript twin with the same rules is in
`examples/actuator-node/require-pass.mjs`.

## Development mode

Use an `ar_test_` key for local development — checks that need production
infrastructure are relaxed so you are not blocked by infrastructure that does
not exist on your laptop:

```python
az = arcezia.Arcezia(api_key="ar_test_...", task="...")   # dev mode by default
```

Development mode is only available on `ar_test_` keys and is re-checked
server-side. Live `ar_live_` keys are always pinned to production and cannot
point at `localhost`.

## Links

- [Developer documentation](https://arcezia.com/developer-docs)
- [Dashboard](https://app.arcezia.com)
