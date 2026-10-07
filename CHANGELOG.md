# Changelog

All notable changes to the `arcezia` Python SDK.

This file starts at 1.0.6. Earlier releases are described by their git history.

## 1.0.7 — unreleased

Needs a server released on or after this SDK; publish the server first.

### An ALLOW runs only on a pass for the call about to run
- Every framework adapter (universal guard, LangChain/LangGraph, OpenAI,
  CrewAI, Anthropic dispatch and filter, AutoGen, OpenCLAW dispatch and CLI
  hook, LlamaIndex, Claude Code hook) now runs an `ALLOW` only when its
  single-use pass names the call about to run — the binding recomputed from
  the arguments that will execute (`arcezia.signing.action_binding`) — or
  when no pass was issued because there was no session (`no_session`). An
  `ALLOW` whose pass was withheld for any other reason, or with no pass and
  no reason, or with a pass for a different call, is held with a plain
  reason. A pass from a service that signs only the description digest is
  matched through the digest and the reply's `action_binding`.
- `cert.credential_withheld`: why an `ALLOW` came without its pass.
- `arcezia.actuator.require_pass(...)`: for the service that acts. Checks the
  pass for exactly the call it is about to perform and raises `PassRefused`
  on anything but a bound yes; the pass is spent once. `mode="online"`
  (default), `"offline"` (Ed25519 signature against pinned keys, the pass must
  name this service, local `UsedPasses` register) or `"both"`.
  `fetch_pass_keys(...)` returns only the keys whose fingerprint you pinned.
- `verify(..., audience=...)`: name the one service that will perform the
  action; its pass is valid there only. `pass_keys()` reads the published
  pass keys.
- `validate_credential(..., action_binding=...)`: binds the whole call (the
  answer's `call_bound` says whether it was checked).

### Contract registration: `session_grants`
- `register_contract()` returns the grants to sign into a session envelope as
  `session_grants`. `envelope_fragment` is the same object under its old name,
  deprecated: the service sends both for one release, then only
  `session_grants`. The SDK reads both, so `session_grants` is present against
  an older service too.

### Signed envelopes and the agent's workspace
- `Arcezia(signing_key=..., account_id=...)`: with the principal's Ed25519
  private key configured, every capability envelope the client opens a
  session with is sent signed (`arcezia.signing.mint_envelope_token`, a fresh
  single-use token per opening). Configure it where the principal's backend
  opens sessions, never in the agent's process. `account_id` is looked up
  once through `token_key_status()` when not given.
- `start_session(workspace_roots=[...])`: the absolute folders the agent
  works in, added to the envelope. A grant, so it counts only when the
  envelope is signed; unsigned, the service ignores it and reports the
  envelope in `unverified_approvals`. `/` and relative paths are refused.
- Claude Code hook: forwards the real path of its working directory
  (`action_parameters.cwd`, symlinks resolved) with every act, and sends a
  whole command line under `COMMAND_LINE_ACTION_TYPE` (`run_shell`), the type
  the hosted service reads as a command line. Decisions are unchanged.

### Response format: what to do next, and nothing else
The service now answers with the verdict and what your next action needs:

- `cert.release` (on REVIEW): what would let the call proceed. Each item is
  `approval:user`, `approval:production`, `check:<name>` (have your registered
  check answer), `contract:<fact>`, `scope:<envelope field>`,
  `declare:<effect>` (state in your contract that the tool never has that
  effect), or `person`.
- `cert.reason` (on BLOCK): why it was refused: `fabrication`,
  `contract:<your rule>`, `scope:<envelope field>`, `ceiling:<effect>` (your
  envelope forbids it), or `safety:<effect>` / `safety` (a built-in rule).
- `cert.next_steps`: the same, one plain sentence per item.
- `cert.summary` is built from those items only.
- `cert.reduced_mode` / `cert.incident`: the service answered in reduced mode
  (the verdict is still fail-safe); quote the incident code to support.
- `cert.contract_coverage`: `covered`, `none` or `unavailable`.
- `credential_withheld` takes one of `not_allowed`, `plan_not_cleared`,
  `fabrication`, `no_session`, `unavailable`.

Deprecated for one release, mapped from the new fields and warning once:
`held_by`, `blocked_by`, `to_reach_allow` (+ `_reachable`, `_reported`,
`_plain`). `cert.missing` now lists the release items and `cert.violated` the
reason items. `trust_score` and `precondition_score` are `None` (the service
no longer reports them); `cert.constraints` and `cert.unresolved` are empty.
Adapters (Claude Code hook, LangChain, OpenAI, AutoGen, CrewAI, n8n, ...) show
the new summary and items; every gate still reads only `verdict`,
`fabrication_detected`, `chain_status` and `credential`. Against an older
service the SDK reads its `missing` / `violated` fields into the same lists.

### Added
- Policy contracts: `register_contract()`, `delete_contract()`,
  `declarations_as_contract()`; `DeclarationsRetired` / `ContractRefused` exported.
- `start_session(principal_rules=...)`: the user's own restrictions for a
  session (they only ever tighten); re-sent when a session is re-opened.
- `verify(principal_request=...)`: a hold names the arguments the user's own
  request never gave (`cert.raw["unrequested_arguments"]`).
- `cert.action_binding`: the value for an approval token's `act` claim
  (`action_digest` is a different hash and is refused as `act`).
- `token_key_status()`: whether a signing key is registered, its fingerprint,
  and the `api_key_id` an approval token's `acct` needs.
- `register_token_key(public_key, replace=False)`: registers the approval
  signing key. It raises `SigningKeyConflict` and changes nothing when a
  different key is already registered (or when the service cannot say which
  key is registered); pass `replace=True` to replace or clear it. Registering
  the same key again is a no-op. `arcezia.signing.public_key_fingerprint()`
  computes the fingerprint locally.

### Behaviour changes (these can change what a working integration sees)
- AutoGen, CrewAI (`ArceziaCrewTool`) and `ArceziaGuard.wrap_function` raise
  `ArceziaBlockError` on BLOCK and `ArceziaReviewError` on REVIEW, carrying the
  certificate as `err.cert`. Both subclass `RuntimeError`, so an existing
  `except RuntimeError` still catches them, and the message text is unchanged.
- Claude Code hook: reads (Read, Grep, Glob, LS, NotebookRead) inside the
  working directory run without a call; reads that reach outside it are
  verified. Shell commands are verified per program with finer action types;
  an existing envelope that allows `run_shell` keeps working unchanged.
- Absence declarations are retired for keys created after the server's
  cutover (`DeclarationsRetired`, HTTP 410); use a policy contract.
- A second `start_session()` drops approvals attached to the session it
  replaces (they are bound to that session and would be refused).
- An envelope or session rules the service refuses (4xx) are not kept for
  later sessions.

### Documentation
- The README and the examples read `release`, `reason` and `next_steps`, and a
  plan's `reason` and plain `semantic_triggers`, in place of the deprecated
  fields. Webhook examples check `X-Arcezia-Signature-V2` with the
  `signing_key_v2` shown once at registration, and approval examples attach
  tokens signed with a registered key; a made-up string is refused.

### Fixed
- Shell typing: a `#` mid-word no longer hides a second command; `wget`
  (saves a file), `less +cmd` and `git diff --ext-diff/--textconv` are
  verified as the shell act they are.
- The hook recognises the service's 409 `session_expired` and opens a new
  session with the envelope and rules.

## 1.0.6 — released

Security release. Each change below closes a path on which something could
execute without a verdict that was about it, or on which an absent answer read
as a permissive one.

**Read this first if you are upgrading:** several behaviours that used to let a
call through now refuse it. That is the point of the release. Each one is listed
under *Behaviour changes* with what will now fail and what to do about it.

### Added

- **`az.declarations()` / `az.declare_absent({...})`.** Read and replace this
  key's `declared_absent` document from the SDK — the step that turns a fresh
  key's held reads into ALLOW. `declare_absent` REPLACES the whole document
  (send every fact you rely on each time), refuses a non-dict before any
  request, and raises `ValueError` with the server's reason when a fact name
  is not declarable or a wildcard is not accepted. Admin role required.
  Every framework example now performs this as its step 0, and reaches ALLOW
  on a fresh free-tier key (validated live, 2026-09-16).

### Behaviour changes (these can break a working integration)

- **Adapters refuse an unrecognised verdict.** Every framework adapter used to
  reach "execute" by elimination: not block, not review, not degraded. A verdict
  that was none of the three — an empty string, a lowercase `"allow"`,
  `"SEMANTIC_BLOCK"`, or a value renamed in a future server — satisfied no test
  and the tool ran. Execution now requires `cert.allow is True` positively (or
  `cert.review is True`, reachable only through the declared `block_on_review=False`
  / `review_handler` channels). Anything else raises with a reason. Affects
  `guard_callable`, `guard`, `az.gate()`, and the LangChain, LangGraph, OpenAI /
  CrewAI, Anthropic, AutoGen, LlamaIndex and OpenCLAW toolkits.
  *If this starts raising for you, the server is returning something this SDK
  does not recognise — read `cert.raw["verdict"]`; do not catch and continue.*

- **An ALLOW whose fabrication result was never reported is not a clearance.** The
  adapters refuse it. `cert.fabrication_status` is three-state and prints in
  words, so "the server did not say" no longer reads as "checked, clean".

- **Both CLI hooks require a positive ALLOW.** `arcezia-hook` (Claude Code) and
  the OpenCLAW hook used to end in a bare `return allow`.

- **`https` is required for a live key.** A base URL of `http://…` is refused at
  construction for any key that is not `ar_test_`. Loopback is decided by
  resolved IP address (`ipaddress`), not by four hostname spellings, so
  `127.0.0.2`, `[::ffff:127.0.0.1]`, `2130706433`, `0x7f000001` and
  `localtest.me` are all recognised, and `169.254.169.254` and the private
  ranges are refused outright. An unresolvable host is refused rather than
  assumed safe, so a DNS outage now fails client construction — the same
  direction as `on_error="fail_closed"`.

- **`WebFetch` and `WebSearch` are gated as outbound actions.** They were
  declared read-only and passed through ungated. They now verify as
  `fetch_url` / `web_search` in domain `agent_action`, with the URL or the query
  as the action. *A Claude Code session that fetches URLs will now see verdicts
  it did not see before.*

- **`arcezia-hook install` never overwrites `settings.json`.** A file that does
  not parse as a JSON object now raises and names the path instead of being
  replaced with a fresh hook-only settings file. Every real write copies the
  original to `settings.json.bak-<timestamp>` first. The installed command is
  the `arcezia-hook` console script (falling back to `sys.executable`), and the
  older spelling is still recognised so re-running install stays idempotent.

- **The hook always exits 0 and always emits a decision.** A hook that crashed
  used to exit non-zero with nothing on stdout, and the harness reads a
  non-zero, non-2 exit as a *non-blocking* error — so a crashed gate let the
  tool run. Verifier construction, payload parsing and the verification itself
  are inside one handler; any failure, `BaseException` included, prints a
  `deny` decision and returns 0, with a literal-JSON fallback if serialising the
  decision itself fails. A payload that is not a JSON object denies rather than
  raising `AttributeError`. An unreadable `~/.claude/arcezia.json` capability
  envelope is a deny, not an absent envelope — its `False` axes are denials, and
  dropping them widens authority.

- **The n8n workflow template no longer approves itself.** `workflow_template()`
  used to emit `{{ $json.approval_token || 'n8n-human-approved' }}`, so resuming
  the human-approval Wait node with an empty body authorised the run with a
  constant printed in a public template. There is no default any more; the Wait
  node's resume is authenticated with an operator HTTP-header credential and has
  no fixed webhook id (n8n mints a random one per workflow); and a new
  "Approval Token Present?" node stops the run when the resume carries no token.
  *Two operator steps are now required: register a signing key at
  `POST /v1/account/token_key`, and create the n8n credential "Arcezia Approval
  Resume Auth". Re-import the template; an existing imported copy keeps the old
  behaviour.*

### Added

- **`Arcezia.validate_credential(token, action_type=None, action_digest=None,
  resource_id=None)`** — the resource-side half of the gate. Pass the
  certificate rather than the raw token and the binding is complete by default:
  `action_type` and `action_digest` are read off it, so the server answers "was
  this credential issued for THIS action" instead of "for some action of this
  type in this session". A refusal (HTTP 403) is returned as
  `{"ok": False, "error": …}` — an answer, not an exception; transport failures
  raise, and a raise means "not validated". There is no degraded fallback.

- **`cert.action_digest`** — `action_identity.digest`, the sha256 of the action
  this verdict was about, or `None` on a server that does not send it. Never
  recomputed locally: a digest computed here would compare the SDK against
  itself.

- The n8n workflow template forwards `X-Arcezia-Action-Digest` alongside
  `X-Arcezia-Credential`, so an endpoint that consumes the credential can make
  the bound check.

### Changed

- **Actions are described in full, with a visible marker when clipped.** Every
  adapter used to truncate the description and then execute the complete
  arguments — the authorised text and the executed text were different things,
  and the clip was invisible, so a long benign prefix authorised whatever
  followed. There is now one shared `describe()` across all adapters with a
  32 768-character budget, a fair share across arguments so a huge one cannot
  crowd out a small one, and ` [TRUNCATED n]` appended when it clips, so a
  clipped description is never read as a clean short action.

- Typed arguments (`action_parameters`) are forwarded by every adapter that
  holds them, including the classic LangChain path, which used to stringify and
  drop them.

- **CrewAI tools are gated on `_arun` as well as `_run`**, and at attribute
  *access* time rather than only at class-definition time, so a subclass that
  defines its entry point after the class body — or an instance that assigns one
  — is still gated. The documented co-inheritance pattern in the docstring now
  uses the annotated `ClassVar` form, which is what current CrewAI accepts.

- `DispatchGuard.wrap` over an async dispatch awaits the upstream (it returned
  an un-awaited coroutine), and `wrap_function` over a coroutine function
  returns an async wrapper rather than a coroutine nobody awaited.

- The OpenCLAW hook blocks — with a distinct reason for each — on unparseable
  input, non-object JSON, a missing tool name, a verifier that could not be
  constructed, and a missing API key. It used to answer `"review"` on three of
  those; a missing key is not a held action, it is an ungated one. `"review"` is
  now reachable only from a REVIEW verdict.

### Fixed

- `install()` recognising the older hook command spelling, so the settings merge
  stays idempotent across the command change.
- The `n8n` module docstring's approval section, which described a flow the
  template did not implement.

