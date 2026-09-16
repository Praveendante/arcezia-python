# Changelog

All notable changes to the `arcezia` Python SDK.

This file starts at 1.0.6. Earlier releases are described by their git history.

## 1.0.6 — unreleased

Security release. Every change below came out of the 2026-09-10 audit and its
fix derivation (`docs/security/FIX-DERIVATION-2026-09-11.md`); each one closes a
path on which something could execute without a verdict that was about it, or on
which an absent answer read as a permissive one.

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

- **An ALLOW whose fabrication channel never reported is not a clearance.** The
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
  type in this session". `action_digest` has been on the wire since server v31
  and stayed opt-in because nothing sent it. A refusal (HTTP 403) is returned as
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
  32 768-character budget (the same constant and marker the engine uses), a
  max-min fair share across arguments so a huge sibling cannot starve the small
  argument holding the target, and ` [TRUNCATED n]` appended when it clips. The
  engine treats that marker as unresolved, never as a clean short action.

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
  now reachable only from an engine REVIEW.

### Fixed

- `install()` recognising the older hook command spelling, so the settings merge
  stays idempotent across the command change.
- The `n8n` module docstring's approval section, which described a flow the
  template did not implement.

---

### Not published

1.0.6 has not been uploaded to PyPI. This entry describes the tree.
