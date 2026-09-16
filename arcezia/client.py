"""
Arcezia thin HTTP client.

All verification runs in Arcezia's secure cloud via the proprietary engine.
This client makes HTTPS calls to the API and returns typed result objects.

The API surface:
    cert = az.verify(action_type=..., action_description=..., domain=...)
    cert.allow / cert.block / cert.review
    @az.gate(domain=..., action_type=...)
    az.authorize(token)
"""
from __future__ import annotations

import functools
import http.client as _http_client
import ipaddress as _ipaddress
import os as _os
import json
import os
import socket as _socket
import time
import urllib.error as _urllib_error
import urllib.request as _urllib_request
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlparse

# urllib is imported unconditionally, not only as a fallback. Two reasons:
# (1) the fallback path was previously unreachable — and therefore untestable —
# on any machine with httpx installed, which is every developer machine and no
# fraction of the `pip install arcezia` installs that skip the optional extra;
# (2) `_NET_ERRORS` has to name the same failure classes whichever transport is
# selected, so the outage policy below is one policy and not two.
try:
    import httpx
    _TRANSPORT = "httpx"
except ImportError:                                        # pragma: no cover
    httpx = None                                           # type: ignore[assignment]
    _TRANSPORT = "urllib"


# Single source of truth for the package version — __init__.__version__ and
# pyproject.toml must match this (the wheel build reads pyproject).
_SDK_VERSION = "1.0.6"
_USER_AGENT = f"arcezia-python/{_SDK_VERSION}"


def _backoff(attempt: int) -> float:
    """Exponential backoff, capped — 0.25s, 0.5s, 1s, … up to 2s."""
    return min(2.0, 0.25 * (2 ** attempt))


# ── Exceptions ────────────────────────────────────────────────────────────────

class ArceziaBlockError(RuntimeError):
    """Raised by @az.gate() when an action is blocked."""
    def __init__(self, cert: "ArceziaCertificate"):
        self.cert = cert
        super().__init__(str(cert))


class ArceziaReviewError(RuntimeError):
    """
    Raised by a guard when an action is REVIEW (human confirmation required) and
    the guard is configured to halt on review (the default). REVIEW means the
    action is not yet authorized to execute — surfacing it as an exception
    prevents a tool from running before a human approves.
    """
    def __init__(self, cert: "ArceziaCertificate"):
        self.cert = cert
        super().__init__(str(cert))


class ArceziaUpgradeRequired(RuntimeError):
    """Raised when the current tier doesn't include the requested domain."""
    def __init__(self, detail: dict):
        self.detail = detail
        msg = detail.get("message", "Upgrade required")
        self.upgrade_url = detail.get("upgrade_url", "https://arcezia.com/billing")
        super().__init__(f"{msg} — {self.upgrade_url}")


class ArceziaAPIError(RuntimeError):
    """Unexpected API error."""
    def __init__(self, status_code: int, body: str):
        self.status_code = status_code
        super().__init__(f"Arcezia API error {status_code}: {body}")


class ArceziaAuthError(ArceziaAPIError):
    """Raised on HTTP 401 — the API key is missing, invalid, or revoked.

    Distinct from the generic API error so callers can catch an auth failure
    specifically ("go get / rotate a key") rather than by string-matching a
    bare RuntimeError. Subclasses ArceziaAPIError, so existing
    `except ArceziaAPIError` handlers still catch it.
    """
    def __init__(self, body: str):
        super().__init__(401, body)


class ArceziaRateLimitError(RuntimeError):
    """Raised on HTTP 429. `retry_after` is the server's suggested wait (seconds)."""
    def __init__(self, detail: dict, retry_after: Optional[int] = None):
        self.detail = detail
        self.retry_after = retry_after
        msg = detail.get("message", "Rate limit exceeded") if isinstance(detail, dict) else str(detail)
        super().__init__(msg + (f" (retry after {retry_after}s)" if retry_after else ""))


class ArceziaTransportError(RuntimeError):
    """
    The HTTP exchange completed but produced nothing this client can read: a
    body that is not JSON (a WAF's HTML 403 page, a proxy error page), a body
    truncated by a connection closed mid-response, or a success status whose
    payload is missing the fields the endpoint is defined to return.

    It is classed with the network errors on purpose. From the caller's side it
    is the same fact — *no verdict was obtained* — so it must be retried and
    then degraded by the same `on_error` policy, never leaked as a raw
    ``json.JSONDecodeError`` or ``KeyError`` into an agent's tool loop.
    """


class ArceziaUnavailableError(RuntimeError):
    """
    Raised when Arcezia cannot be reached after retries and the client is in the
    default fail-closed mode. The action is blocked because safety could not be
    verified — never silently allowed.
    """
    def __init__(self, cause: Exception):
        self.cause = cause
        super().__init__(f"Arcezia unreachable; action blocked (fail-closed): {cause}")


# Failures that mean "no answer was obtained": worth retrying, and — when the
# retries are exhausted — subject to the client's `on_error` policy. Deterministic
# 4xx responses are deliberately absent: they are answers, just not the one the
# caller wanted. Both transports contribute, whichever one is selected, so the
# policy below has a single definition of "unreachable".
_NET_ERRORS: tuple = (
    ArceziaTransportError,
    _urllib_error.URLError,          # covers urllib connect/DNS/refused
    _socket.timeout,
    _http_client.HTTPException,      # IncompleteRead, BadStatusLine, …
    ConnectionError,                 # reset/aborted/refused, either transport
) + ((httpx.TransportError,) if httpx is not None else ())


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class ArceziaConstraintDetail:
    name: str
    value: Optional[bool]
    quality: str    # GROUNDED | INFERRED | CLAIMED | UNVERIFIED | UNRESOLVED | FABRICATED
    # UNVERIFIED = an approval token accepted on presence alone (the account
    # has no registered signing key). The fact still counts for the verdict,
    # but nothing proved a human produced the token — register a key via
    # POST /v1/account/token_key to upgrade these to GROUNDED.
    detail: str
    # Plain-words provenance for the same fact `quality` states as an enum —
    # what a person filing this certificate reads ("a probe measured it",
    # "the agent asserted it"). The server has emitted it on every constraint
    # since the plain-language pass; the typed surface dropped it on parse, so
    # a field the API published was invisible to every SDK user. `quality`
    # stays the machine field; this is additive and defaults to "" against a
    # server that predates it.
    quality_plain: str = ""


@dataclass
class ArceziaOutcomeResult:
    """
    The return value of az.verify_outcome().

    Use result.allow / result.block / result.review for control flow.
    Use result.violations for specific divergence details.
    """
    verdict: str             # "ALLOW" | "BLOCK" | "REVIEW"
    status: str              # "OUTCOME_VERIFIED" | "OUTCOME_DIVERGED" | "OUTCOME_DIVERGED_CRITICAL"
    summary: str
    violations: list         # list of {check, expected, actual, severity}
    warnings: list           # list of {check, expected, actual, severity}
    outcome_recorded: dict   # what was recorded in the session
    signature: str

    # True only on a result this SDK synthesised because Arcezia could not be
    # reached (see `_degrade_outcome`). Never set from a parsed response, so a
    # server cannot forge it and a caller cannot mistake one for the other.
    _synthetic: bool = False

    @property
    def degraded(self) -> bool:
        """True if this result is a synthetic fallback — nothing was audited.

        The outcome was never compared against the authorized intent; this
        object exists only because the caller's ``on_error`` policy asked for a
        value instead of an exception.
        """
        return self._synthetic

    @property
    def allow(self) -> bool:
        return self.verdict == "ALLOW"

    @property
    def block(self) -> bool:
        return self.verdict == "BLOCK"

    @property
    def review(self) -> bool:
        return self.verdict == "REVIEW"

    def __str__(self) -> str:
        icon = {"ALLOW": "✅", "BLOCK": "❌", "REVIEW": "⚠️"}.get(self.verdict, "?")
        v_count = len(self.violations)
        return f"{icon} {self.verdict} | {v_count} violations | {self.summary}"


@dataclass
class ArceziaChainResult:
    """
    The return value of az.verify_chain() — a typed result, not a bare dict.

    Why it exists (T8): the "was this made up locally?" marker had three
    spellings across this SDK's surface — ``ArceziaCertificate._synthetic``,
    ``ArceziaOutcomeResult._synthetic``, and the string key ``"_synthetic"`` in
    the chain result's dict. One property, three surfaces, and the dict was the
    root cause: an untyped return value cannot be kept in step with the two
    dataclasses beside it. Now all three are the same field on the same kind of
    object, and ``.degraded`` reads it on all three.

    Use the properties::

        result = az.verify_chain(manifest)
        if not result.safe:
            abort(result.blocked_at)        # the step_id that failed

    Dict access still works and is DEPRECATED::

        if result["overall_verdict"] != "SAFE":   # still supported
            abort(result["blocked_at"])

    Every documented key resolves: ``overall_verdict``, ``blocked_at``,
    ``steps``, ``semantic_triggers``, ``summary``, ``_synthetic``, plus
    anything else the server sent (``final_state``, ``session_state_updated``,
    …) which is read straight from the response. Two rules are kept exactly as
    the dict had them, because tests and callers depend on them:

      * ``"_synthetic"`` is *present* only when it is True. A parsed server
        response never has the key, so ``"_synthetic" in result`` still
        answers "did this SDK make it up?" and a server cannot claim it.
      * an unknown key raises ``KeyError``, as it did.
    """
    overall_verdict: str          # "SAFE" | "BLOCKED" | "REVIEW_REQUIRED" | "SEMANTIC_BLOCK"
    blocked_at: Optional[str] = None      # the step_id execution stopped at, if any
    steps: list = field(default_factory=list)
    semantic_triggers: list = field(default_factory=list)

    # The server's one-line explanation. Named `human_summary` on the typed
    # surface and reachable as `result["summary"]` for dict callers — the wire
    # key is `summary`, and renaming a wire key is not something a client gets
    # to do.
    human_summary: str = ""

    # The complete server response, so a field the server adds is visible
    # without an SDK release. Empty on a synthetic result: nothing answered.
    raw: dict = field(default_factory=dict)

    # True only on a result this SDK synthesised because Arcezia could not be
    # reached (see `_degrade_chain`). Never set from a parsed response — the
    # key is stripped on the way in — so a server cannot forge it. Same name,
    # same meaning, same `.degraded` reader as on the other two result types.
    _synthetic: bool = False

    @property
    def degraded(self) -> bool:
        """True if this result is a synthetic fallback — no step was verified."""
        return self._synthetic

    @property
    def safe(self) -> bool:
        """True only for a real SAFE verdict.

        A degraded result is never safe, whatever its ``overall_verdict`` says:
        under ``on_error="fail_open"`` that string is "SAFE" and nothing in the
        chain was checked. The dict gate callers were taught to write —
        ``result["overall_verdict"] != "SAFE"`` — cannot see that difference,
        which is precisely why this property is the one to move to.
        """
        return self.overall_verdict == "SAFE" and not self._synthetic

    # ── dict compatibility (deprecated) ──────────────────────────────────────

    def _mapping(self) -> dict:
        m = dict(self.raw)
        m.update({
            "overall_verdict": self.overall_verdict,
            "blocked_at": self.blocked_at,
            "steps": self.steps,
            "semantic_triggers": self.semantic_triggers,
            "human_summary": self.human_summary,
        })
        # `summary` is an ALIAS, not a wire key: the chain response carries
        # `human_summary`, while the degraded dict this class replaces carried
        # `summary`. Set only when the response did not send one of its own, so
        # the alias can never shadow something the server actually said.
        m.setdefault("summary", self.human_summary)
        # Present only when true — mirroring the dict this replaced, so
        # `"_synthetic" in result` stays the un-forgeable local-origin test.
        m.pop("_synthetic", None)
        if self._synthetic:
            m["_synthetic"] = True
        return m

    def __getitem__(self, key: str):
        try:
            return self._mapping()[key]
        except KeyError:
            raise KeyError(key) from None

    def __contains__(self, key: object) -> bool:
        return key in self._mapping()

    # Without these, defining `__getitem__` alone would make `for k in result`
    # fall back to the old integer-indexing protocol — `result[0]` — and raise
    # KeyError instead of yielding the keys the dict used to yield. A silent
    # behaviour change in the compatibility layer is the one thing this layer
    # exists to prevent.
    def __iter__(self):
        return iter(self._mapping())

    def __len__(self) -> int:
        return len(self._mapping())

    def get(self, key: str, default: Any = None) -> Any:
        return self._mapping().get(key, default)

    def keys(self):
        return self._mapping().keys()

    def items(self):
        return self._mapping().items()

    def values(self):
        return self._mapping().values()

    def to_dict(self) -> dict:
        """The result as a plain dict — for logging, or JSON serialisation."""
        return self._mapping()

    def __str__(self) -> str:
        icon = {"SAFE": "✅"}.get(self.overall_verdict, "❌")
        at = f" at {self.blocked_at}" if self.blocked_at else ""
        deg = " (degraded — nothing was verified)" if self._synthetic else ""
        return f"{icon} {self.overall_verdict}{at}{deg} | {self.human_summary}"


@dataclass
class ArceziaCertificate:
    """
    The return value of az.verify().

    Use cert.allow / cert.block / cert.review for control flow.
    Use cert.summary for a one-line explanation.
    Use cert.credential to get the single-use token to pass to your tool.
    """
    verdict: str                           # "ALLOW" | "BLOCK" | "REVIEW"
    status: str                            # "ALLOWED" | "BLOCKED" | "INSUFFICIENT_EVIDENCE"
    precondition_score: float              # [0,1] severity-weighted fraction of
                                           # required preconditions satisfied
    trust_score: float                     # [0,1] fraction of evidence that is
                                           # externally grounded, not agent-claimed
    summary: str
    violated: list[str]
    missing: list[str]

    # THREE-STATE, not two. True = the server detected fabricated evidence.
    # False = the server looked and found none. None = THE SERVER DID NOT
    # REPORT — an older deployment, or a response that lost the field on the
    # way here. None is an absence, never a clearance.
    #
    # This used to default to False on parse, so a response that omitted the
    # field read as "no fabrication" — absence converted into a permissive
    # fact, the defect class this SDK has already closed at five probe sites
    # and in the outage policy. The verdict-level gates (`allow`/`block`/
    # `review`) are unchanged, because `verdict` is the decision and is always
    # present: a server that detects fabrication returns BLOCK in `verdict`
    # too. Use `is_clean()` when you need the flag itself to have positively
    # cleared the action rather than merely not have accused it.
    fabrication_detected: Optional[bool]
    fabricated_constraints: list[str]
    constraints: list[ArceziaConstraintDetail]
    signature: str
    credential: Optional[dict] = None     # set on ALLOW — pass to your tool

    # Axes the principal declared False in the capability envelope. An action
    # that crosses one cannot reach ALLOW, and no token lifts it — widening is a
    # new signed envelope. This is the principal's own declaration echoed back,
    # not an explanation of which rule acted on it.
    #
    # THREE-STATE. `[]` = the server reported the list and it is empty (nothing
    # was denied). `None` = THE SERVER DID NOT REPORT the list — an older
    # deployment. `None` never means "none denied": an envelope's denials are
    # the operator's own ceiling, and reading a silent server as "no ceiling"
    # would widen authority exactly where it must not be widened.
    #
    # Because `None` is now reachable, do not iterate this field unguarded.
    # Either check `denied_authority_axes_reported` first, or use
    # `denied_axes_or_unknown()`, which returns a tuple and a flag together.
    denied_authority_axes: Optional[list[str]] = None

    # Every constraint still ungrounded, including those held by a rule rather
    # than directly required. `missing` lists only what the caller can act on, so
    # it can legitimately be empty while this is not.
    unresolved: list[str] = field(default_factory=list)

    # Cross-step danger detected across this session, e.g. a sensitive read
    # earlier and an outbound send now. The per-action verdict can still be
    # ALLOW — this action is fine in isolation; the SEQUENCE is not — so
    # `allow` accounts for it below.
    #
    # THREE STATES, and they are now separable:
    #
    #   "SEMANTIC_BLOCK" — the scan ran and a cross-step pattern fired.
    #   "CLEAR"          — the scan ran and found nothing. An explicit
    #                      negative, so a quiet channel is no longer
    #                      indistinguishable from a silent one.
    #   None (key absent)— the scan DID NOT RUN: there was no session to scan
    #                      across, or it raised.
    #
    # This field used to be positive-only: the key appeared only on a
    # SEMANTIC_BLOCK, so absence meant either "nothing fired" or "this
    # deployment computes no patterns", and the client could not tell. The
    # server now emits "CLEAR", which closes that. `chain_status_reported`
    # is the accessor for "did the scan run at all".
    #
    # Note what absence still conflates, because the client cannot separate it
    # either: "no session, so there was nothing to scan across" (expected, and
    # the reason `is_clean()` does not refuse on it) and "the scan raised"
    # (a lost report). A caller who needs the distinction should require
    # `chain_status_reported` explicitly — see `is_clean()`.
    chain_status: Optional[str] = None

    # Which cross-step patterns fired, e.g. ["structural_exfiltration"].
    chain_patterns: list[str] = field(default_factory=list)

    # ── Evidence-channel observability (server v30+) ─────────────────────────
    # Which probe-backed facts were consulted for THIS verdict, and how each
    # resolved: "answered" (grounded), "declined" (your probe said it could not
    # determine the fact — an honest unknown), or "unreachable" / "rejected" /
    # "malformed" / "unsignable" (your endpoint was not reached or answered
    # unusably). Empty when no probes were consulted.
    #
    # The check worth building in: compare these keys against the probes you
    # registered (GET /v1/probes). A probe you registered that is ABSENT here
    # was never consulted — a lost or stale registration, not a cautious
    # engine. That distinction is invisible from the verdict alone.
    probe_outcomes: dict[str, str] = field(default_factory=dict)

    # Set only when the evidence channel itself failed: "degraded" (some probes
    # did not answer) or "unavailable" (the probe registry could not be read).
    # None means healthy. A REVIEW with this set is a broken evidence path;
    # a REVIEW without it is the engine correctly asking for evidence.
    evidence_channel: Optional[str] = None

    # Which facts failed and how, when evidence_channel is set.
    evidence_channel_failures: dict[str, str] = field(default_factory=dict)

    # Health of the pre-execution simulation channel (Level 4): "ok", or a
    # degradation — "webhook_status_<code>", "malformed_response",
    # "no_verdict_field", "malformed_outcome", "unreachable",
    # "signing_key_unavailable".
    #
    # None means Level 4 did not run for this response: either no simulation
    # webhook is registered for this domain, the verdict was not an ALLOW, or
    # the verdict was served from the server's cache (simulation runs only on
    # the solve path). None is an absence, never a pass.
    #
    # An ALLOW carrying a degraded value here was NOT simulated, and is
    # indistinguishable from a simulated ALLOW in every other field — which is
    # exactly why this one exists.
    simulation_channel: Optional[str] = None
    simulation_channel_detail: Optional[str] = None

    # Defenses that ran in reduced mode for this verdict, e.g.
    # "probe_evidence_channel" or "description_canonicalization". The verdict is
    # still fail-safe; this exists so an auditor can tell a full-coverage
    # verdict from a degraded one.
    degraded_defenses: list[str] = field(default_factory=list)

    # Approval tokens accepted on presence alone because this account has no
    # registered signing key ("user" and/or "production"). Register an Ed25519
    # public key via POST /v1/account/token_key to make signatures mandatory.
    unverified_approvals: list[str] = field(default_factory=list)

    # Operator absence channel state for this verdict (server v35+):
    # "declared" (the account declared which facts may be read as absent for
    # this action type), "undeclared" (nothing declared — every probe that saw
    # nothing stays unresolved, so ordinary actions hold at REVIEW until the
    # operator declares), or "unavailable" (the declaration store could not be
    # read; the gate ran at full strength). None: server predates the field.
    absence_channel: Optional[str] = None

    # False when the capability envelope this verdict used was supplied
    # unsigned by the caller (the key holder is the principal, so this is the
    # normal case unless the account requires signed envelopes). None: no
    # envelope was involved, or the server predates the field.
    envelope_signed: Optional[bool] = None

    # ── Decision identity + provenance (server v31+) ─────────────────────────
    # The stored audit row this decision was written to. Cite log_id to
    # retrieve/verify the record later (GET /v1/audit/record/{log_id}), or
    # request_id to correlate with the X-Request-ID response header and your
    # own logs. None on older servers, or when the audit store could not
    # report a row identity (an honest absence — never a synthesized id).
    log_id: Optional[int] = None
    created_at: Optional[str] = None      # the stored row's timestamp (ISO-8601)
    request_id: Optional[str] = None
    session_id: Optional[str] = None      # the session this decision ran under

    # What the decision was ABOUT: {"type", "domain", "digest"} where digest is
    # sha256(action_description) — verifiable by anyone holding the
    # description; the description itself is never stored server-side.
    action_identity: Optional[dict] = None

    # Which rulebook produced the verdict: "builtin", or sha256 of the custom
    # domain YAML (resolvable via GET /v1/audit/ruleset/{hash}); and which
    # deployed engine build decided it.
    ruleset_hash: Optional[str] = None
    engine_version: Optional[str] = None

    # Ed25519 signature over the STORED record (verdict, scores, constraint
    # table, action identity, signed_at) when the deployment configures a
    # signing key — verify against GET /v1/audit/public_key. {"scheme":
    # "unsigned"} when not configured. This, plus the server-side hash chain,
    # is the tamper evidence; the session-keyed `signature` field is only a
    # correlation digest.
    record_signature: Optional[dict] = None
    signed_at: Optional[str] = None       # the timestamp the signature covers

    # Personal-data categories the server resolved for this action (dict with
    # "resolved" etc.), or None when none were declared or the server predates
    # the field. Categories are add-only: declaring one can only tighten the
    # verdict, never loosen it.
    data_categories: Optional[dict] = None

    # The complete server response. Any field the server adds is visible here
    # without waiting for an SDK release — new observability should never be
    # gated behind a client upgrade.
    raw: dict = field(default_factory=dict)

    # True only on a certificate this SDK synthesised because the engine could
    # not be reached (see `_degraded_cert`). Never set on a parsed response, so
    # it cannot be confused with a genuine verdict. Backs `.degraded`.
    _synthetic: bool = False

    @property
    def degraded(self) -> bool:
        """True if this certificate is a synthetic fallback (unverified).
        A degraded cert was not verified by the engine — its credential is None
        and its verdict is not grounded in a proof. This is a synthetic
        fallback that must never be treated as a verified result.

        Read from the flag the fallback constructor sets, not inferred. The
        previous test — `credential is None and trust_score == 0.0` — is a
        property of every genuine BLOCK that ran with no grounded evidence,
        which is the normal state of a fresh integration. It reported those
        real, engine-produced verdicts as outages. It never missed a synthetic
        cert (both proxies always hold for one), so the error was one-sided and
        fail-safe; it was still a wrong answer to 'did the engine verify this?'
        """
        return self._synthetic

    @property
    def action_digest(self) -> Optional[str]:
        """sha256 of the action this verdict is ABOUT, or None.

        Law P — the verdict in ∂≺(E) must be about E. The credential the server
        mints is bound to this digest (`adg`), so a resource that presents the
        credential together with the digest gets "this token was issued for THIS
        action", not merely "for an action of this type in this session".
        Without it, a credential minted for one `send_email` authorises any
        other `send_email` in the same session.

        None when the server predates `action_identity` (an honest absence — a
        digest is never recomputed here, because recomputing it locally would
        make the check compare the SDK against itself).
        """
        ident = self.action_identity
        if not isinstance(ident, dict):
            return None
        digest = ident.get("digest")
        return digest if isinstance(digest, str) and digest else None

    @property
    def evidence_channel_healthy(self) -> bool:
        """False when this verdict ran with a broken evidence path.

        A REVIEW with a healthy channel is the engine asking for evidence —
        expected, no action needed. A REVIEW with an unhealthy channel means
        probes did not answer: the verdict is still safe (it can never become
        ALLOW), but something in your integration needs a human. Use this to
        decide whether to page someone.
        """
        return self.evidence_channel is None

    def probes_not_consulted(self, registered: "list[str] | set[str]") -> list[str]:
        """Registered probe constraints that this verdict never consulted.

        Pass the constraint names you registered (from GET /v1/probes). Anything
        returned here was not asked — a lost or stale registration. The server
        cannot detect this itself: from inside, a registration it cannot see is
        indistinguishable from one that was never made.
        """
        return sorted(set(registered) - set(self.probe_outcomes))

    @property
    def semantic_block(self) -> bool:
        """A cross-step danger pattern fired for this session.

        The per-action verdict may still be ALLOW: this action is unobjectionable
        on its own, and the SEQUENCE is what is dangerous — a sensitive read
        earlier plus an outbound send now. The server withholds the credential
        when this happens; `allow` is False for the same reason.
        """
        return self.chain_status == "SEMANTIC_BLOCK"

    # ── Was it reported at all? ──────────────────────────────────────────────
    # Three of this certificate's fields have an honest third state, "the
    # server did not say". These name it, so no caller has to rediscover that
    # `None` and `False` are different facts.

    @property
    def fabrication_reported(self) -> bool:
        """True when the server stated a fabrication finding, either way."""
        return self.fabrication_detected is not None

    @property
    def fabrication_status(self) -> str:
        """Plain words for the three states: what to put in a message.

        "detected" · "none detected" · "not reported by this server".
        Use this instead of interpolating the raw field, where printing
        ``None`` reads to a human as a value rather than as a silence.
        """
        if self.fabrication_detected is True:
            return "detected"
        if self.fabrication_detected is False:
            return "none detected"
        return "not reported by this server"

    @property
    def denied_authority_axes_reported(self) -> bool:
        """True when the server reported the denied-axis list, empty or not."""
        return self.denied_authority_axes is not None

    def denied_axes_or_unknown(self) -> "tuple[tuple[str, ...], bool]":
        """``(axes, reported)`` — the safe way to read the denied axes.

        ``axes`` is always iterable, so no caller crashes on ``None``; but
        ``reported`` is False when the tuple is empty *because the server said
        nothing*, which is a different fact from an empty declaration. Branch
        on ``reported`` before telling anyone "nothing was denied".
        """
        if self.denied_authority_axes is None:
            return (), False
        return tuple(self.denied_authority_axes), True

    @property
    def chain_status_reported(self) -> bool:
        """Did the cross-step scan RUN for this verdict?

        True when the server reported a `chain_status` either way —
        "SEMANTIC_BLOCK" (it ran, a pattern fired) or "CLEAR" (it ran, nothing
        fired). False when the key is absent, which means the scan did not run:
        there was no session to scan across, or it raised.

        This is the lever for a caller who wants to require the scan rather
        than merely benefit from it. `is_clean()` deliberately does NOT require
        it — see there for why — so if your deployment always runs sessions and
        a missing scan should stop the action, write::

            if not (cert.is_clean() and cert.chain_status_reported):
                halt()

        It used to be equivalent to `semantic_block`, back when the server
        wrote the key only on a block. It is not any more: "CLEAR" is an
        explicit negative, and the two are now different questions.
        """
        return "chain_status" in self.raw

    @property
    def chain_status_plain(self) -> str:
        """Plain words for the three states — what to put in a message.

        "cross-step pattern fired" · "cross-step scan clear" ·
        "cross-step scan did not run". As with `fabrication_status`, printing
        the raw ``None`` reads to a human as a value rather than as a silence.
        """
        if self.chain_status == "SEMANTIC_BLOCK":
            return "cross-step pattern fired"
        if self.chain_status_reported:
            return "cross-step scan clear"
        return "cross-step scan did not run"

    # ── Where the door is ────────────────────────────────────────────────
    # `violated` and `missing` say what went wrong. These say what would put
    # it right: the checks nobody could make whose confirmation, by the
    # system entitled to answer each one, would turn this verdict into ALLOW.
    #
    # Read from `raw` rather than parsed into a field, so a server that
    # predates them degrades to "not reported" instead of raising.

    @property
    def to_reach_allow(self) -> list:
        """The checks that would reach ALLOW, as the server reported them.

        Each item is ``{"name", "value", "source", "channel", "minimised"}``:

          name      the exact string to register a probe webhook under
          value     what that check has to come back with (True / False)
          source    which channel the domain says answers it
          channel   one plain sentence naming who can answer
          minimised whether this is the SMALLEST such set; False means it is
                    every check still open, because there were too many to
                    narrow down

        Empty on an ALLOW, on a verdict that rests on facts already
        established, and on a server that does not report the field. Use
        ``to_reach_allow_reported`` / ``to_reach_allow_reachable`` to tell
        those three apart — an empty list is not by itself an answer.
        """
        items = self.raw.get("to_reach_allow")
        if not isinstance(items, list):
            return []
        out = []
        for i in items:
            if not isinstance(i, dict) or not i.get("name"):
                continue
            out.append({
                "name": str(i.get("name")),
                # Defaults are the least useful, never the most permissive:
                # an item with no stated value asks for True, which is what a
                # grant needs, and an item with no channel says nothing rather
                # than inventing one.
                "value": i.get("value") if isinstance(i.get("value"), bool)
                         else True,
                "source": str(i.get("source") or ""),
                "channel": str(i.get("channel") or ""),
                "minimised": bool(i.get("minimised", True)),
            })
        return out

    @property
    def to_reach_allow_reachable(self):
        """Three states, and the third is not False.

        ``True``  — the list above is a set that would reach ALLOW.
        ``False`` — the server established that NO confirmation of an
                    unchecked fact changes this decision. It rests on facts
                    already established; act on ``violated`` instead.
        ``None``  — not reported: an ALLOW (nothing to reach), or a server
                    that does not compute this. Never read as "no".
        """
        got = self.raw.get("to_reach_allow_reachable")
        return got if isinstance(got, bool) else None

    @property
    def to_reach_allow_reported(self) -> bool:
        """True when the server answered the question, either way."""
        return "to_reach_allow_reachable" in self.raw

    @property
    def to_reach_allow_plain(self) -> list:
        """The same answer as sentences, for a log line or a ticket.

        One sentence per check: what to confirm, what it has to come back
        with, and who can answer it. Empty when there is nothing to say, so a
        caller can print the list unconditionally.
        """
        if self.to_reach_allow_reachable is False:
            return ["No unchecked fact would change this decision."]
        out = []
        for i in self.to_reach_allow:
            words = i["name"].replace("_", " ").strip() or i["name"]
            needs = "true" if i["value"] else "false"
            line = f"Confirm '{words}' — it has to come back {needs}."
            if i["channel"]:
                line += f" Who can answer: {i['channel']}."
            out.append(line)
        if out and not all(i["minimised"] for i in self.to_reach_allow):
            out.append(
                "This is every check still open, not the shortest set."
            )
        return out

    def is_clean(self) -> bool:
        """True only when the auxiliary danger channels POSITIVELY cleared this
        action. Unknown is not clean.

        This is the fail-closed reading of the flags that sit beside the
        verdict:

          * ``fabrication_detected is False`` — the server looked and found
            none. ``None`` (not reported) returns False here. Absence of an
            accusation is not a finding of innocence.
          * ``not semantic_block`` — the cross-step scan did not fire.

        WHY THE TWO ABSENCES ARE TREATED DIFFERENTLY. This looks inconsistent
        and is not; the asymmetry is derived, not chosen for convenience.

        The fabrication check is PER-ACTION and always runs. So an absent
        ``fabrication_detected`` can only be a report that was lost — an older
        deployment, a proxy that dropped the key, a truncated body. There is no
        legitimate reason for it to be missing, and a lost report must not read
        as a clearance. Hence: absent → not clean.

        The cross-step scan is PER-SESSION. ``chain_status`` is absent exactly
        when the scan did not run, and its commonest cause is that there was no
        session to scan across — a single sessionless ``verify`` has no earlier
        step to compose with, so there is nothing for the scan to say. That is
        a correct state, not a lost report. Requiring the scan here would refuse
        every sessionless call, and would also refuse every response from a
        server that predates the explicit ``"CLEAR"`` — a compatibility break
        with no safety gain. Hence: absent → does not by itself make the
        certificate unclean.

        What that leaves open, stated rather than hidden: absence also covers
        "the scan RAISED", which *is* a lost report, and nothing in the
        response separates the two. A caller who needs the scan to have run
        should say so explicitly — ``cert.is_clean() and
        cert.chain_status_reported`` — which is what that accessor is for. The
        adapters do not require it, because doing so would break sessionless
        use for everyone to close a case only some deployments have.

        It deliberately does NOT look at ``verdict``: the verdict is the
        decision, it is always present, and ``allow`` / ``block`` / ``review``
        remain the gate. ``is_clean()`` answers the different question "did the
        evidence behind that decision actually get reported?", which is what
        you want before treating an ALLOW as fully accounted for. A synthetic
        (degraded) certificate is never clean, because nothing reported
        anything about it.

        It also does not look at ``denied_authority_axes``: a non-empty denial
        list is the operator's own declared ceiling and is entirely normal on
        an ALLOW, so it is not evidence of danger. Read that field through
        ``denied_axes_or_unknown()``.
        """
        return self.fabrication_detected is False and not self.semantic_block

    @property
    def allow(self) -> bool:
        # A cross-step block is a refusal even when the step's own verdict is
        # ALLOW. Before this was accounted for, `if not cert.allow: raise` — the
        # gate this SDK's own documentation tells you to write — let a detected
        # exfiltration through, because the detection lives in chain_status and
        # nothing read it.
        #
        # `is not True` rather than `not ...`: identical truth table over
        # {True, False, None}, but it says out loud that an unreported
        # fabrication flag does not change this gate. It cannot: `verdict` is
        # the decision and is always present, and a server that finds
        # fabrication returns BLOCK there as well. The stricter reading — an
        # unreported flag is not a clearance — lives in `is_clean()`, which is
        # additive and so cannot silently un-ALLOW an older server.
        return (
            self.verdict == "ALLOW"
            and self.fabrication_detected is not True
            and not self.semantic_block
        )

    @property
    def block(self) -> bool:
        return (
            self.verdict == "BLOCK"
            or self.fabrication_detected is True
            or self.semantic_block
        )

    @property
    def review(self) -> bool:
        return (
            self.verdict == "REVIEW"
            and self.fabrication_detected is not True
            and not self.semantic_block
        )

    def __str__(self) -> str:
        icon = {"ALLOW": "✅", "BLOCK": "❌", "REVIEW": "⚠️"}.get(self.verdict, "?")
        fab = " 🚨 FABRICATION DETECTED" if self.fabrication_detected is True else ""
        if self.fabrication_detected is None:
            fab = " (fabrication: not reported by this server)"
        if self.semantic_block:
            fab += " ⛓️ CROSS-STEP BLOCK: " + ", ".join(self.chain_patterns or ["pattern"])
        return (
            f"{icon} {self.verdict}{fab} | "
            f"trust={self.trust_score:.0%} | "
            f"preconditions={self.precondition_score:.2f} | "
            f"{self.summary}"
        )


# ── Transport helpers ─────────────────────────────────────────────────────────

# An error body is echoed into an exception message, so it is bounded: a WAF
# block page is tens of kilobytes of HTML and none of it helps a reader.
_MAX_ERROR_BODY_CHARS = 2000


def _decode_body(status: int, text: str) -> dict:
    """Turn a raw response body into a dict — the ONE decoding rule.

    Both transports funnel through this. They used to decode separately: httpx
    fell back to ``{"detail": resp.text}`` on unparseable JSON while urllib
    called ``json.loads`` unguarded, so the identical WAF HTML 403 was a typed
    API error on one transport and a raw ``JSONDecodeError`` on the other. That
    is one behaviour with two implementations, which is the shape most of this
    codebase's real defects have had.

    The rule:
      * empty body        → ``{}``  (a 204, or an error whose status says it all)
      * unparseable, 4xx/5xx → ``{"detail": <truncated text>}`` — the status is
        the answer; the body is only context for the message.
      * unparseable, 2xx  → ``ArceziaTransportError``. A success status with no
        readable payload is NOT a success: continuing would hand the caller a
        certificate parsed out of nothing.
      * JSON that is not an object (a bare list/string/number) → same split.
    """
    stripped = (text or "").strip()
    if not stripped:
        if status >= 400 or status == 204:
            return {}
        raise ArceziaTransportError(
            f"HTTP {status} from Arcezia carried an empty body; no verdict was returned."
        )
    try:
        data = json.loads(stripped)
    except ValueError as exc:
        if status >= 400:
            return {"detail": stripped[:_MAX_ERROR_BODY_CHARS]}
        raise ArceziaTransportError(
            f"HTTP {status} from Arcezia was not JSON "
            f"({stripped[:120]!r}…); no verdict was returned."
        ) from exc
    if isinstance(data, dict):
        return data
    if status >= 400:
        return {"detail": data}
    raise ArceziaTransportError(
        f"HTTP {status} from Arcezia was JSON but not an object "
        f"({type(data).__name__}); no verdict was returned."
    )


def _read_text(read: Callable[[], Any], what: str) -> str:
    """Read a response body, converting a mid-stream failure into a typed error.

    A connection closed mid-body raises inside ``read()``, not at connect time —
    ``IncompleteRead``/``ConnectionResetError`` on urllib, ``RemoteProtocolError``
    on httpx. Left alone, urllib's version escaped as a bare OSError.
    """
    try:
        raw = read()
    except _NET_ERRORS:
        raise
    except Exception as exc:                                # pragma: no cover
        raise ArceziaTransportError(f"could not read the {what}: {exc!r}") from exc
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return raw if isinstance(raw, str) else str(raw)


_HTTPX_CLIENT = None


def _httpx_client():
    """A process-wide httpx.Client so connections are kept between calls."""
    global _HTTPX_CLIENT
    if _HTTPX_CLIENT is None:
        _HTTPX_CLIENT = httpx.Client()
    return _HTTPX_CLIENT


# Kept connections on the stdlib transport (default on). ARCEZIA_NO_KEEPALIVE=1
# restores one connection per call — the escape hatch for a proxy that
# mishandles persistent connections. The httpx transport keeps its own pool.
_KEEPALIVE = _os.environ.get("ARCEZIA_NO_KEEPALIVE", "").strip().lower() not in ("1", "true", "yes", "on")


def _once_post(url: str, headers: dict, body: dict, timeout: float) -> tuple[int, dict]:
    if _TRANSPORT == "httpx":
        resp = _httpx_client().post(url, headers=headers, json=body, timeout=timeout)
        return resp.status_code, _decode_body(
            resp.status_code, _read_text(lambda: resp.text, "response body"))
    data_bytes = json.dumps(body).encode()
    if _KEEPALIVE:
        # One kept connection per host: no TCP + TLS handshake per verdict.
        # Status handling is uniform — a 4xx/5xx is a status and a body here,
        # exactly what the urlopen branch below produces via HTTPError.
        from . import _keepalive
        status, raw = _keepalive.request(
            "POST", url, {**headers, "Content-Type": "application/json"}, data_bytes, timeout)
        return status, _decode_body(status, _read_text(lambda: raw, "response body"))
    req = _urllib_request.Request(
        url, data=data_bytes,
        headers={**headers, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _urllib_request.urlopen(req, timeout=timeout) as resp:
            return resp.status, _decode_body(
                resp.status, _read_text(resp.read, "response body"))
    except _urllib_error.HTTPError as e:
        return e.code, _decode_body(e.code, _read_text(e.read, "error body"))


def _once_get(url: str, headers: dict, timeout: float) -> tuple[int, dict]:
    if _TRANSPORT == "httpx":
        resp = _httpx_client().get(url, headers=headers, timeout=timeout)
        return resp.status_code, _decode_body(
            resp.status_code, _read_text(lambda: resp.text, "response body"))
    if _KEEPALIVE:
        from . import _keepalive
        status, raw = _keepalive.request("GET", url, dict(headers), None, timeout)
        return status, _decode_body(status, _read_text(lambda: raw, "response body"))
    req = _urllib_request.Request(url, headers=headers, method="GET")
    try:
        with _urllib_request.urlopen(req, timeout=timeout) as resp:
            return resp.status, _decode_body(
                resp.status, _read_text(resp.read, "response body"))
    except _urllib_error.HTTPError as e:
        return e.code, _decode_body(e.code, _read_text(e.read, "error body"))


def _with_retry(fn, retries: int) -> tuple[int, dict]:
    """
    Run a single-shot request with retry + backoff on transient failures only:
    network/timeout errors and 5xx responses. Deterministic 4xx responses are
    returned immediately — retrying them is pointless. `verify()` is idempotent,
    so retrying it is safe.
    """
    attempt = 0
    while True:
        try:
            status, data = fn()
        except _NET_ERRORS:
            if attempt < retries:
                time.sleep(_backoff(attempt))
                attempt += 1
                continue
            raise
        if status >= 500 and attempt < retries:
            time.sleep(_backoff(attempt))
            attempt += 1
            continue
        return status, data


def _post(url: str, headers: dict, body: dict, *, retries: int = 2, timeout: float = 30.0) -> tuple[int, dict]:
    return _with_retry(lambda: _once_post(url, headers, body, timeout), retries)


def _get(url: str, headers: dict, *, retries: int = 2, timeout: float = 30.0) -> tuple[int, dict]:
    return _with_retry(lambda: _once_get(url, headers, timeout), retries)


def _raise_for_status(status: int, body: dict) -> None:
    if status == 402:
        detail = body.get("detail", body)
        # A 402 that came through a proxy carries a string (or an HTML page)
        # rather than the API's dict. ArceziaUpgradeRequired reads it with
        # .get(), so an unwrapped string raised AttributeError from inside the
        # error handler — the failure mode replaced by a different crash.
        if not isinstance(detail, dict):
            detail = {"message": str(detail)[:_MAX_ERROR_BODY_CHARS]}
        raise ArceziaUpgradeRequired(detail)
    if status == 429:
        detail = body.get("detail", {})
        if not isinstance(detail, dict):
            detail = {"message": str(detail)}
        # Only the per-minute limiter clears by waiting. A monthly quota and a
        # spend ceiling also carry a "window", so keying on that reported a
        # 60-second wait that never helps: key on the error name instead.
        retry_after = 60 if detail.get("error") == "rate_limit_exceeded" else None
        raise ArceziaRateLimitError(detail, retry_after=retry_after)
    if status == 401:
        raise ArceziaAuthError(str(body.get("detail", body)))
    if status >= 400:
        raise ArceziaAPIError(status, str(body))


# ── SSRF: the verifier's address, decided on the value not the spelling ───────

def _unwrap(addr):
    """IPv4 hidden inside an IPv6 address, if there is one.

    ``::ffff:127.0.0.1`` is loopback to every network stack and NOT loopback to
    ``IPv6Address.is_loopback`` — the property is about the v6 address, and the
    v4 address is a passenger inside it. The same is true of 6to4. Unwrap
    first, judge second, or the wrapper is a way to spell an address the guard
    has been told to refuse.
    """
    for attr in ("ipv4_mapped", "sixtofour"):
        inner = getattr(addr, attr, None)
        if inner is not None:
            return inner
    return addr


def _is_local_address(addr) -> bool:
    """True for anything that is not a public internet address."""
    addr = _unwrap(addr)
    return bool(
        addr.is_loopback or addr.is_private or addr.is_link_local
        or addr.is_reserved or addr.is_multicast or addr.is_unspecified
    )


def _refuse_local_address(host: str, raw_url: str) -> None:
    """Raise unless ``host`` resolves to public addresses only.

    Law Ω applies to the resolution too: a host that CANNOT be resolved is not
    a host that resolved to something safe. It is refused, and the message says
    which of the two it was, because "unreadable" and "clean" must not arrive
    as the same outcome.
    """
    literal = host.strip("[]")
    try:
        addresses = [_ipaddress.ip_address(literal)]
    except ValueError:
        try:
            infos = _socket.getaddrinfo(host, None, proto=_socket.IPPROTO_TCP)
        except OSError as exc:
            raise ValueError(
                f"ARCEZIA_API_URL host {host!r} could not be resolved ({exc}), so "
                f"it cannot be checked against the private address ranges. A "
                f"verifier whose address is unknown is not a verified address; "
                f"fix DNS or set ARCEZIA_API_URL to a reachable host."
            ) from exc
        addresses = []
        for info in infos:
            try:
                addresses.append(_ipaddress.ip_address(info[4][0].split("%")[0]))
            except ValueError:
                continue
        if not addresses:
            raise ValueError(
                f"ARCEZIA_API_URL host {host!r} resolved to no usable address."
            )
    for addr in addresses:
        if _is_local_address(addr):
            where = "localhost" if _unwrap(addr).is_loopback else "a private or link-local address"
            raise ValueError(
                f"ARCEZIA_API_URL cannot point to {where} for live API keys: "
                f"{host!r} resolves to {addr}. A verification call aimed at an "
                f"internal service is a verification call that can be answered "
                f"by the thing being verified. Use ar_test_... keys for local "
                f"development. (url={raw_url!r})"
            )


# ── Main client ───────────────────────────────────────────────────────────────

class Arcezia:
    """
    Arcezia safety enforcement client.

    One instance per agent session. Maintains session_id and auth tokens.

        az = Arcezia(api_key="ar_live_...", task="clean up test records")
        cert = az.verify(action_type="execute_sql", action_description="...", domain="database_ops")
        if cert.block:
            raise SafetyViolation(cert.summary)

    WHAT HAPPENS WHEN ARCEZIA IS UNREACHABLE
    ----------------------------------------
    Every method below that touches the network states its own answer in its
    docstring. They differ, because the methods differ — a gating call has a
    safe degraded verdict, a billing lookup does not — but they all come from
    one implementation (`_guarded`) and one setting (`on_error`). The summary:

        method                       fail_closed (default)   review        fail_open
        ---------------------------  ----------------------  ------------  ---------
        verify                       raise Unavailable       REVIEW cert   ALLOW cert
        verify_chain                 raise Unavailable       REVIEW_REQD   SAFE
        verify_outcome               raise Unavailable       REVIEW        ALLOW
        start_session                raise Unavailable       retry later   retry later
        authorize/_production        raise Unavailable       retry later   retry later
        usage                        raise Unavailable       raise         raise
        audit_subject                raise Unavailable       raise         raise

    Under the default, NO method returns a permissive value during an outage.
    Every degraded verdict is `_synthetic` — ``cert.degraded`` /
    ``result["_synthetic"]`` — and carries no credential, so a degraded ALLOW
    cannot be replayed as a verified one.
    """

    _DEFAULT_API_URL = "https://api.arcezia.com"

    def __init__(
        self,
        api_key: Optional[str] = None,
        task: str = "",
        api_url: Optional[str] = None,
        on_error: str = "fail_closed",
        max_retries: int = 2,
        timeout: float = 30.0,
        mode: Optional[str] = None,
        data_subject_reference: Optional[str] = None,
    ):
        """
        on_error — behaviour when Arcezia is unreachable after retries. Applies
          to EVERY method that makes a network call, not only verify(); see the
          table in this class's docstring, and each method's own docstring.
          "fail_closed" (default) → raise ArceziaUnavailableError; the action is
              blocked because safety could not be verified.
          "review" → return a synthetic REVIEW verdict; the action halts pending
              human confirmation (safe degradation).
          "fail_open" → return a synthetic ALLOW verdict; the action proceeds
              unverified. Only for non-critical actions — use deliberately.
          The non-gating reads (usage, audit_subject) raise under all three:
          there is no safe degraded value for "how much have I used" or "which
          decisions are on file about this person", and a fabricated empty
          answer to either would be a false statement, not a cautious one.

        mode — "production" (default) or "development".
          In development mode, infrastructure constraints (backup APIs,
          capability envelopes, CI gates) are relaxed so developers can
          experiment without external infrastructure. Structural safety
          constraints (fabrication, exfiltration, authorization) remain
          strict in both modes. Can also be set via ARCEZIA_ENV env var.

        data_subject_reference — optional identifier for the person the
          following verifications are about (e.g. your own customer id).
          Included in every verify/verify_chain/verify_outcome request while
          set; change or clear it later with set_data_subject(). Record-only:
          it never changes a verdict. The server stores only a salted one-way
          fingerprint of it, never the raw value.
        """
        self._api_key = api_key or os.environ.get("ARCEZIA_API_KEY", "")
        if not self._api_key:
            raise RuntimeError(
                "No API key provided. Pass api_key= or set ARCEZIA_API_KEY."
            )
        if on_error not in ("fail_closed", "review", "fail_open"):
            raise ValueError(
                "on_error must be 'fail_closed', 'review', or 'fail_open'."
            )
        self._task = task
        self._on_error = on_error
        self._max_retries = max_retries
        self._timeout = timeout
        # Mode gating: dev mode only available on test keys (ar_test_*).
        # Live keys (ar_live_*) always run production — no bypass possible.
        _is_test_key = self._api_key.startswith("ar_test_")
        if mode:
            # Explicit mode: respect for test keys, ignore for live keys
            self._mode = mode if _is_test_key else "production"
        elif _is_test_key:
            # Test key with no explicit mode: default to development
            self._mode = os.environ.get("ARCEZIA_ENV", "development")
        else:
            # Live key: always production
            self._mode = "production"

        raw_url = (
            api_url or os.environ.get("ARCEZIA_API_URL", self._DEFAULT_API_URL)
        ).rstrip("/")
        # SSRF guard: only https (or http for test keys) with a real hostname.
        _parsed = urlparse(raw_url)
        if _parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"ARCEZIA_API_URL must use http or https, got {_parsed.scheme!r}."
            )
        # Anything that is not a declared TEST key is treated as LIVE. It used
        # to be `startswith("ar_live_")`, so a key of any other shape — a new
        # prefix, a typo, a truncated value — skipped the guard entirely. The
        # question the guard asks is "may this deployment aim its verifier at a
        # local address?", and only an ar_test_ key answers yes.
        _is_live = not _is_test_key
        _host = _parsed.hostname
        if not _host:
            raise ValueError(f"ARCEZIA_API_URL has no hostname: {raw_url!r}")
        # In production (live key), refuse localhost/loopback/private/link-local
        # to prevent SSRF where a compromised config redirects verification
        # calls to an internal service that always returns ALLOW.
        #
        # The refusal is decided on the RESOLVED ADDRESS, not on the spelling.
        # It used to compare the hostname against four literal strings, so every
        # other spelling of the same address walked through: 127.0.0.2,
        # [::ffff:127.0.0.1], 2130706433, 0x7f000001, a DNS name that resolves
        # to loopback, and 169.254.169.254 (cloud metadata). An address has one
        # value and unboundedly many spellings; only the value can be checked.
        if _is_live:
            _refuse_local_address(_host, raw_url)
            if _parsed.scheme != "https":
                # The comment on this guard always said "only https (or http
                # for test keys)"; the code accepted http for every key, which
                # put the bearer key on the wire in the clear and let a
                # compromised config aim verification at a plaintext service
                # that always answers ALLOW (A5-10). Checked after the address
                # so the more specific refusal is the one reported.
                raise ValueError(
                    "ARCEZIA_API_URL must use https for live API keys, got "
                    f"{_parsed.scheme!r}. Use an ar_test_... key for local "
                    "development over http."
                )
        self._api_url = raw_url
        self._session_id: Optional[str] = None
        self._user_token: Optional[str] = None
        self._prod_token: Optional[str] = None
        # Approvals handed to us that the server has NOT yet acknowledged.
        # Emptied only by a successful POST /v1/authorize; refilled from the
        # known tokens whenever a new session is created. Anything left here is
        # retried before the next verdict is asked for, so a failed attach
        # degrades into a delay, never into a discarded human approval.
        self._pending_tokens: dict[str, str] = {}
        # The last capability envelope the caller declared. Remembered because
        # session creation can fail and be retried implicitly: without this, the
        # retry would open a session with NO envelope, and an envelope's axes
        # set False are DENIALS — dropping them would widen authority during an
        # outage. Absence must not become permission.
        self._capability_envelope: Optional[dict] = None
        self._data_subject_reference: Optional[str] = data_subject_reference

    # ------------------------------------------------------------------
    # Outage policy — ONE implementation, used by every network call
    # ------------------------------------------------------------------

    def _guarded(self, degrade, fn, *args, **kwargs):
        """Run ``fn``; on an outage apply this client's ``on_error`` policy.

        Every public method that talks to the network goes through here. What
        differs per method is only ``degrade`` — the callable that builds the
        degraded return value — never the policy itself. Before this existed
        the policy was consulted at exactly one call site inside ``verify()``,
        so ``verify_chain``, ``verify_outcome``, ``start_session``,
        ``authorize``, ``usage`` and ``audit_subject`` all leaked a raw
        ``httpx.ConnectError``: the documented ``except ArceziaUnavailableError``
        did not catch them.

        ``degrade=None`` means "no safe degraded value exists" — always raise.
        """
        try:
            return fn(*args, **kwargs)
        except _NET_ERRORS as exc:
            return self._apply_on_error(exc, degrade)
        except ArceziaAPIError as exc:
            # 5xx = the service failed to answer → an outage. 4xx = it answered,
            # deterministically, and retrying or degrading would be wrong.
            if exc.status_code >= 500:
                return self._apply_on_error(exc, degrade)
            raise

    def _apply_on_error(self, exc: Exception, degrade):
        """The single decision point between 'raise' and 'degrade'.

        THE load-bearing line of this class: under ``fail_closed`` — the
        default — this raises unconditionally. There is no other route to a
        synthetic verdict, so no outage can produce an ALLOW unless the
        operator explicitly selected ``fail_open``.
        """
        if degrade is None or self._on_error == "fail_closed":
            raise ArceziaUnavailableError(exc) from exc
        return degrade(self._on_error, exc)

    def set_data_subject(self, reference: Optional[str]) -> None:
        """Set (or clear, with None) the data-subject reference attached to
        subsequent verifications.

        The reference names the person the following actions are about — use
        the same identifier your own systems use for them. Record-only: it
        never changes a verdict; it exists so decisions can later be looked up
        per person (audit_subject). Stored server-side only as a salted
        one-way fingerprint; the raw value is sent with the request but is
        never persisted.
        """
        self._data_subject_reference = reference

    def _subject_ref(self, override: Optional[str]) -> Optional[str]:
        """One rule for all endpoints: an explicit per-call value wins;
        otherwise the client-level reference (if any) applies."""
        return override if override is not None else self._data_subject_reference

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "X-Arcezia-SDK": f"python/{_SDK_VERSION}",
            # REQUIRED. The API sits behind a WAF that rejects the stdlib
            # default agent ("Python-urllib/3.x") with 403 before the request
            # reaches the API. httpx sends its own agent, but httpx is an
            # optional dependency — without this header a plain
            # `pip install arcezia` fails every call on the urllib fallback.
            "User-Agent": _USER_AGENT,
        }

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    # The complete set of structural_authority axes — closed by design. This
    # SDK version documents exactly these six; validation below makes a typo
    # fail HERE, loudly and locally, instead of surfacing days later as an
    # unexplained REVIEW from a different endpoint. (The server deliberately
    # does NOT hard-reject unknown axes — an unknown key grants nothing, and a
    # raw-HTTP caller on a newer API version must not break — it reports them
    # in the session response as `ignored_authority_keys`.)
    STRUCTURAL_AUTHORITY_AXES = frozenset({
        "sensitive_data",
        "outbound",
        "persistent_mutation",       # NOT "mutation"
        "mass_scope",
        "trust_boundary_crossing",   # NOT "trust_crossing"
        "irreversible",
    })

    def start_session(
        self,
        capability_envelope: Optional[dict] = None,
    ) -> dict:
        """
        Create a session and sign the task manifest.

        Call this at the start of each agent interaction. Returns the signed
        task manifest T — the immutable consent boundary for this session.

        Args:
            capability_envelope: Optional human-signed scope authorization dict.
                When provided, grounds action_within_task_scope for all verify()
                calls in this session. Fields: allowed_domains (list[str]),
                allowed_action_types (list[str]),
                max_scope ("single_record"|"batch"|"limited"|"mass"),
                expires_at (ISO-8601 str), routine_action_types (list[str]),
                and structural_authority (dict) —
                the six yes/no axes an action may cross, which is what unlocks
                ALLOW: sensitive_data, outbound, persistent_mutation,
                mass_scope, trust_boundary_crossing, irreversible. The envelope
                is a ceiling, not a permission slip: an axis set True only
                removes that axis as a blocker; every other check still
                applies. In production, this dict should be signed by your
                backend after the user confirms scope.

                expires_at is ENFORCED at use time: after the declared
                instant, the envelope's grants lapse (allowed lists,
                max_scope, structural_authority axes set True, and
                routine_action_types stop grounding anything — consequential
                actions fall back to REVIEW), while its explicit denials
                (denied_action_types, axes set False) persist. An
                unparseable expires_at counts as expired (fail closed).

                routine_action_types declares which action types are ROUTINE
                (low stakes) for this session — the operator-authored stakes
                channel. Without it, an action that is neither provably inert
                nor otherwise classified holds at REVIEW on unresolved
                stakes. The declaration can never mask observed escalation: a
                classified high-stakes type, keyword, or a typed amount at or
                above the threshold always wins (the stricter reading is kept).

        Raises:
            ValueError: if structural_authority contains an unrecognised axis
                name. An unknown axis grants nothing server-side, so a typo
                ("mutation", "trust_crossing") would silently leave that axis
                unresolved — rejected here instead, where it is actionable.

        When Arcezia is unreachable:
            fail_closed (default) — raises ArceziaUnavailableError. No session
                exists, so nothing has been authorized and nothing can run.
            review / fail_open — returns a synthetic dict with
                ``session_id: None`` and ``_synthetic: True``. The session is
                NOT abandoned: it stays pending and is retried by the next
                verify()/verify_chain()/verify_outcome(), which then applies
                its own on_error policy. The envelope you passed is remembered
                and re-sent on that retry — dropping it would drop its DENIALS,
                and an outage must not widen authority.
        """
        if capability_envelope:
            sa = capability_envelope.get("structural_authority")
            if isinstance(sa, dict):
                unknown = sorted(set(sa) - self.STRUCTURAL_AUTHORITY_AXES)
                if unknown:
                    raise ValueError(
                        f"Unrecognised structural_authority ax"
                        f"{'is' if len(unknown) == 1 else 'es'} {unknown}: an "
                        f"unknown axis grants nothing and would leave it "
                        f"unresolved (REVIEW). Valid axes: "
                        f"{sorted(self.STRUCTURAL_AUTHORITY_AXES)}. Note it is "
                        f"'persistent_mutation' (not 'mutation') and "
                        f"'trust_boundary_crossing' (not 'trust_crossing')."
                    )
            # Validated before it is stored, so a rejected envelope is never
            # carried into a later implicit retry.
            self._capability_envelope = capability_envelope
        return self._guarded(self._degrade_session, self._open_session)

    def _open_session(self) -> dict:
        """Create the session on the wire. Unguarded on purpose.

        The implicit bootstrap inside verify()/verify_chain()/verify_outcome()
        calls THIS, not the public start_session(), so a session failure is
        degraded by the CALLER's policy rather than twice — once here and once
        there. Two policy applications on one failure is how the fail_open
        contract would quietly become fail_closed.
        """
        payload: dict = {"task": self._task}
        if self._capability_envelope:
            payload["capability_envelope"] = self._capability_envelope
        status, body = _post(
            f"{self._api_url}/v1/session",
            self._headers(),
            payload,
            retries=self._max_retries,
            timeout=self._timeout,
        )
        _raise_for_status(status, body)
        session_id = body.get("session_id")
        if not session_id:
            raise ArceziaTransportError(
                "POST /v1/session returned no session_id; no session was created."
            )
        self._session_id = session_id
        # A new session inherits nothing server-side, so every approval the
        # caller has ever handed us is pending again for THIS session.
        self._pending_tokens = {
            t: v for t, v in (("user", self._user_token),
                              ("production", self._prod_token)) if v
        }
        # Flush any approval handed to us BEFORE a session existed. Without
        # this, authorize() stored the token, start_session() (called
        # explicitly, or implicitly by the first verify()) never sent it, and
        # POST /v1/authorize was never called at all — the human's approval was
        # silently discarded and every verdict ran as if nobody had approved.
        # That is the order the SDK's own docs teach in six places, so it was
        # the DEFAULT path, not an edge case. Fail-safe in direction but wrong:
        # a person clicked Approve and the system did not record it.
        self._flush_pending_tokens()
        return body

    @staticmethod
    def _degrade_session(mode: str, exc: Exception) -> dict:
        return {
            "session_id": None,
            "task": None,
            "summary": (
                f"Arcezia unreachable ({exc}); no session was created. It will be "
                f"retried on the next verification, per on_error={mode!r}."
            ),
            "_synthetic": True,
        }

    def _ensure_session(self) -> None:
        """Session + pending approvals, in that order, before any verdict.

        Called at the top of every verification. The approval flush lives here
        and not only in _open_session because an attach can fail while a
        session already exists — and a token left unattached with nothing that
        ever retries it is the silent-discard bug in a new place.
        """
        if not self._session_id:
            self._open_session()
        elif self._pending_tokens:
            self._flush_pending_tokens()

    # ------------------------------------------------------------------
    # Authorization (human-in-the-loop)
    # ------------------------------------------------------------------

    def _flush_pending_tokens(self) -> None:
        """Attach every approval the server has not yet acknowledged.

        Not best-effort: if /v1/authorize refuses the token, that raises out to
        the caller's guard. A rejected approval must be visible; swallowing it
        would recreate the silent discard this fixes. A token whose attach
        fails on the NETWORK stays pending and is retried — also not swallowed,
        just deferred.
        """
        for token_type in list(self._pending_tokens):
            token = self._pending_tokens.get(token_type)
            if token:
                self._attach_token(token_type, token)

    def authorize(self, token: str) -> "Arcezia":
        """
        Provide a signed user intent token.
        Grounds user_explicit_authorization as GROUNDED.

        Order-independent: call it before or after start_session(). Called
        before, the token is buffered and attached the moment the session is
        created (including the implicit start_session() inside the first
        verify()).

        In production: token = JWT signed by your UI backend after the user
        clicks "Approve" on the action confirmation dialog.
        In development: any non-empty string works.

        When Arcezia is unreachable:
            The token is never discarded — it stays pending and is re-sent
            before the next verdict is asked for. On top of that,
            fail_closed (default) raises ArceziaUnavailableError, because a
            person clicked Approve and is entitled to know it did not land;
            review / fail_open return normally and let the retry carry it.

            Buffer-and-retry rather than raise-only is deliberate: this SDK has
            already shipped one bug where authorize() before start_session()
            was a no-op and the approval vanished without a word. The rule that
            came out of it is that an approval is never dropped on the floor —
            so the failure is either loud (default) or deferred, never lost.
            A verdict is never computed as if the approval had been attached:
            the retry runs BEFORE the verification request, and if it fails
            again the verification degrades under the same policy.
        """
        self._user_token = token
        self._pending_tokens["user"] = token
        if self._session_id:
            self._guarded(self._degrade_authorize, self._attach_token, "user", token)
        return self

    def authorize_production(self, token: str) -> "Arcezia":
        """Grounds production_explicit_authorization as GROUNDED.

        Order-independent in the same way as authorize(), and unreachable-Arcezia
        behaviour is identical: the token is kept pending and retried, and the
        default policy additionally raises ArceziaUnavailableError.
        """
        self._prod_token = token
        self._pending_tokens["production"] = token
        if self._session_id:
            self._guarded(self._degrade_authorize, self._attach_token,
                          "production", token)
        return self

    @staticmethod
    def _degrade_authorize(mode: str, exc: Exception) -> None:
        """No value to synthesise — the token simply stays pending."""
        return None

    def _attach_token(self, token_type: str, token: str) -> None:
        if not self._session_id:
            return
        status, body = _post(
            f"{self._api_url}/v1/authorize",
            self._headers(),
            {
                "session_id": self._session_id,
                "token_type": token_type,
                "token": token,
            },
            retries=self._max_retries,
            timeout=self._timeout,
        )
        try:
            _raise_for_status(status, body)
        except ArceziaAPIError as exc:
            if exc.status_code < 500:
                # A deterministic refusal — this token will never be accepted.
                # Drop it from the pending set so it is not re-sent (and
                # re-raised) before every later verification; the caller has
                # already been told, loudly, once.
                self._pending_tokens.pop(token_type, None)
            raise
        # Acknowledged by the server — and only now is it no longer pending.
        self._pending_tokens.pop(token_type, None)

    # ------------------------------------------------------------------
    # Credential validation (the resource side of Law P)
    # ------------------------------------------------------------------

    def validate_credential(
        self,
        token,
        action_type: Optional[str] = None,
        action_digest: Optional[str] = None,
        resource_id: Optional[str] = None,
    ) -> dict:
        """Validate a single-use credential at the resource, before executing.

        This is the resource-side half of the gate: the tool that is about to
        act presents the token it was handed and is told whether the token
        actually authorises THIS action.

        `token` may be the raw ``arc_cred_...`` string or an `ArceziaCertificate`. Pass
        the certificate and the binding is complete by default — `action_type`
        and `action_digest` are read off it, so the check answers "was this
        credential issued for this exact action" rather than "for some action of
        this type in this session". That default is the point of the helper:
        `action_digest` has been on the wire since server v31 and stayed opt-in
        because nothing sent it.

        Passing a raw string keeps the old, weaker question unless you also pass
        `action_digest` yourself; the response's `action_digest_checked` says
        which question was answered, so a resource can refuse the weak one.

        Returns the server's answer dict, always carrying ``"ok"``:
        ``{"ok": True, ...}`` when the credential authorises this action, and
        ``{"ok": False, "error": "action_digest_mismatch" | "credential_expired"
        | ...}`` when it does not. The endpoint answers a refusal with HTTP 403
        and the same dict in `detail`; that is an ANSWER, not a transport
        failure, so it is returned rather than raised.

        Everything else raises, and a raise must be treated as "not validated":
        there is no degraded fallback here, because a synthesised ok=True would
        be exactly the unverified execution the credential exists to prevent.
        """
        cert_digest = None
        cert_type = None
        if isinstance(token, ArceziaCertificate):
            cert_digest = token.action_digest
            cert_type = (token.action_identity or {}).get("type") \
                if isinstance(token.action_identity, dict) else None
            raw_token = (token.credential or {}).get("token")
            if not raw_token:
                # No credential on this certificate. That is the server
                # declining to stand behind the verdict, not a validation
                # question, and it is refused here rather than sent as an
                # empty token for the server to reject.
                raise ValueError(
                    "this certificate carries no credential — the server withholds "
                    "one exactly when it will not stand behind the ALLOW, so there "
                    "is nothing to validate and nothing to execute"
                )
            token = raw_token
        if not isinstance(token, str) or not token:
            raise ValueError("token must be a non-empty credential string or an ArceziaCertificate")

        body: dict = {"token": token}
        # Explicit arguments win; the certificate fills what was not given.
        eff_type = action_type if action_type is not None else cert_type
        eff_digest = action_digest if action_digest is not None else cert_digest
        if eff_type is not None:
            body["action_type"] = eff_type
        if eff_digest is not None:
            body["action_digest"] = eff_digest
        if resource_id is not None:
            body["resource_id"] = resource_id

        status, resp = _post(
            f"{self._api_url}/v1/validate_credential",
            self._headers(),
            body,
            retries=self._max_retries,
            timeout=self._timeout,
        )
        if status == 403:
            # The endpoint's refusal shape: the same dict the success path
            # returns, under `detail`. Handing it back as `ok=False` keeps one
            # return type for one question.
            detail = resp.get("detail") if isinstance(resp, dict) else None
            if isinstance(detail, dict) and "ok" in detail:
                return detail
            return {"ok": False, "error": "refused", "detail": detail if detail is not None else resp}
        if status >= 400:
            _raise_for_status(status, resp)
        if not isinstance(resp, dict) or "ok" not in resp:
            # A 200 with no `ok` in it is not a validation.
            raise ArceziaTransportError(
                "POST /v1/validate_credential returned no 'ok' field; "
                "the credential was NOT validated."
            )
        return resp

    # ------------------------------------------------------------------
    # Core verify
    # ------------------------------------------------------------------

    def verify(
        self,
        action_type: str,
        action_description: str,
        domain: str = "agent_action",
        agent_evidence: Optional[dict] = None,
        state_mutations: Optional[dict] = None,
        action_parameters: Optional[dict] = None,
        data_subject_reference: Optional[str] = None,
        data_categories: Optional[list] = None,
        capability_envelope: Optional[dict] = None,
        capability_envelope_token: Optional[str] = None,
    ) -> ArceziaCertificate:
        """
        Verify whether an action is safe to execute.

        capability_envelope / capability_envelope_token: present the session's
        envelope WITH the first action, so opening the session and deciding
        that action is one round trip. Accepted only before a session exists;
        the server refuses (409) any envelope on an existing session. The
        token form is the envelope signed with your registered Ed25519 key
        (``arcezia.signing.mint_envelope_token``) — the server then records
        the envelope as signature-verified rather than unverified.

        On ALLOW: cert.credential contains a single-use token. Pass it to your
        tool so the tool can validate it at /v1/validate_credential before executing.

        Args:
            action_type:        Tool name ("execute_sql", "write_file", …)
            action_description: Human-readable description of the action.
            domain:             Constraint domain. Defaults to "agent_action".
            agent_evidence:     Optional LLM-supplied evidence (llm_inferred only).
            state_mutations:    Optional session state updates after this action executes
                                (e.g. {"file_contains_secrets": True} after a write).
            action_parameters:  Optional flat map of scalar identifiers naming what
                                the action touches (e.g. {"invoice_id": "402",
                                "amount": 129.5}). Forwarded to your registered
                                probe webhooks so they can answer by key lookup
                                instead of parsing the description. Bounded:
                                max 32 entries, string values max 512 chars.
                                Populate it from your tool-call arguments, not
                                from model-generated prose.
            data_subject_reference: Optional per-call override of the
                                client-level data subject (an explicit value
                                here wins). Record-only — never changes the
                                verdict; enables per-person decision lookup
                                via audit_subject().
            data_categories:    Optional list of personal-data category names
                                this action touches (identity, contact,
                                government_id, financial, health, biometric,
                                location, behavioural, credentials, children).
                                Unlike the subject reference, this DOES affect
                                the verdict — declaring a category can only
                                tighten it, never loosen it.

        When Arcezia is unreachable (including a failure to open the session or
        to attach a pending approval, both of which happen inside this call):
            fail_closed (default) — raises ArceziaUnavailableError. The action
                is blocked; nothing was verified, so nothing may run.
            review — returns a synthetic REVIEW certificate (`cert.degraded`
                is True, `cert.credential` is None).
            fail_open — returns a synthetic ALLOW certificate, also
                `degraded` and credential-free. The framework adapters refuse
                a degraded certificate by default, so choosing fail_open at the
                client is not on its own enough to execute an unverified tool.
        """
        def _call() -> ArceziaCertificate:
            _first_action_envelope = bool(
                (capability_envelope is not None or capability_envelope_token)
                and not self._session_id
            )
            if capability_envelope is not None and capability_envelope_token:
                raise ValueError("pass capability_envelope or capability_envelope_token, not both")
            if (capability_envelope is not None or capability_envelope_token) and self._session_id:
                raise ValueError(
                    "this client already has a session; an envelope is fixed at session "
                    "creation — start a new client (or call start_session first)")
            if not _first_action_envelope:
                self._ensure_session()

            body: dict[str, Any] = {
                "task": self._task,
                "action_type": action_type,
                "action_description": action_description,
                "domain": domain,
                "session_id": self._session_id,
            }
            if _first_action_envelope:
                # One round trip opens the session AND decides the first action.
                if capability_envelope_token:
                    body["capability_envelope_token"] = capability_envelope_token
                else:
                    body["capability_envelope"] = capability_envelope
            if self._mode and self._mode.lower() in ("development", "dev"):
                body["mode"] = "development"
            if agent_evidence:
                body["agent_evidence"] = agent_evidence
            if state_mutations:
                body["state_mutations"] = state_mutations
            if action_parameters:
                body["action_parameters"] = action_parameters
            subject = self._subject_ref(data_subject_reference)
            if subject is not None:
                body["data_subject_reference"] = subject
            if data_categories is not None:
                body["data_categories"] = data_categories

            status, resp = _post(
                f"{self._api_url}/v1/verify", self._headers(), body,
                retries=self._max_retries, timeout=self._timeout,
            )
            _raise_for_status(status, resp)
            if _first_action_envelope and not self._session_id and resp.get("session_id"):
                # The session this verdict opened is now this client's session.
                self._session_id = resp.get("session_id")
                self._pending_tokens = {
                    t: v for t, v in (("user", self._user_token),
                                      ("production", self._prod_token)) if v
                }
                if self._pending_tokens:
                    self._flush_pending_tokens()
            return _parse_cert(resp)

        return self._guarded(self._degrade_cert, _call)

    # ------------------------------------------------------------------
    # Fail-mode (Arcezia unreachable) — the degraded VALUES.
    # The decision to use one at all lives in _apply_on_error, and only there.
    # ------------------------------------------------------------------

    def _on_transport_failure(self, exc: Exception) -> ArceziaCertificate:
        """Retained for callers that reached in and used it directly.

        Equivalent to routing `exc` through the one policy with a certificate
        as the degraded value.
        """
        return self._apply_on_error(exc, self._degrade_cert)

    @staticmethod
    def _degrade_cert(mode: str, exc: Exception) -> ArceziaCertificate:
        return Arcezia._degraded_cert(
            "ALLOW" if mode == "fail_open" else "REVIEW", exc)

    @staticmethod
    def _degrade_chain(mode: str, exc: Exception) -> "ArceziaChainResult":
        """A synthetic chain result.

        Shaped like a real one so the documented gate
        (``if result["overall_verdict"] != "SAFE": abort()``) keeps working, and
        marked ``_synthetic`` so a caller who wants to tell them apart can.
        A parsed server response can never carry that key — verify_chain strips
        it — so the marker cannot be forged from the wire.
        """
        return ArceziaChainResult(
            overall_verdict="SAFE" if mode == "fail_open" else "REVIEW_REQUIRED",
            blocked_at=None,
            steps=[],
            semantic_triggers=[],
            human_summary=(
                f"Arcezia unreachable ({exc}); no step in this chain was verified. "
                f"Degraded per on_error={mode!r}."
            ),
            # `final_state` was in the dict this replaces; kept so a caller
            # reading result["final_state"] during an outage still gets {} and
            # not a KeyError.
            raw={"final_state": {}},
            _synthetic=True,
        )

    @staticmethod
    def _degrade_outcome(mode: str, exc: Exception) -> "ArceziaOutcomeResult":
        return ArceziaOutcomeResult(
            verdict="ALLOW" if mode == "fail_open" else "REVIEW",
            status="OUTCOME_UNVERIFIED",
            summary=(
                f"Arcezia unreachable ({exc}); the outcome was not compared "
                f"against the authorized intent. Degraded per on_error={mode!r}."
            ),
            violations=[],
            warnings=[],
            outcome_recorded={},
            signature="",
            _synthetic=True,
        )

    @staticmethod
    def _degraded_cert(verdict: str, exc: Exception) -> ArceziaCertificate:
        status = {"ALLOW": "ALLOWED", "REVIEW": "INSUFFICIENT_EVIDENCE"}[verdict]
        return ArceziaCertificate(
            verdict=verdict,
            status=status,
            precondition_score=0.0,
            trust_score=0.0,
            summary=f"Arcezia unreachable ({exc}); degraded to {verdict} per on_error policy.",
            violated=[],
            missing=["arcezia_reachable"],
            # NOT False. The engine was never reached, so nothing looked for
            # fabricated evidence; claiming "none detected" here would be this
            # SDK asserting a finding it did not obtain. None = not reported,
            # which is what makes `is_clean()` False on every degraded
            # certificate — the correct answer to "was this cleared?".
            fabrication_detected=None,
            fabricated_constraints=[],
            constraints=[],
            signature="",
            credential=None,
            _synthetic=True,
        )

    # ------------------------------------------------------------------
    # Decorator pattern
    # ------------------------------------------------------------------

    def gate(
        self,
        domain: str = "agent_action",
        action_type: Optional[str] = None,
        block_on_review: bool = True,
    ):
        """
        Decorator. Verifies the action before the wrapped function runs.

            @az.gate(domain="database_ops", action_type="execute_sql")
            def run_query(sql: str):
                db.execute(sql)

            run_query("DROP TABLE users")  # raises ArceziaBlockError

        ALLOW runs the function; BLOCK raises ArceziaBlockError; REVIEW raises
        ArceziaReviewError (human confirmation required). Pass
        ``block_on_review=False`` to let REVIEW actions through — not recommended
        for consequential actions, since REVIEW means the action is not yet
        authorized to execute.

        ``gate()`` is the instance-bound form of the framework-agnostic
        ``arcezia.guard`` / ``arcezia.guard_callable`` primitive and shares its
        exact logic (sync + async, signature preserving).

        When Arcezia is unreachable: the wrapped function does not run, under
        every on_error setting. fail_closed raises ArceziaUnavailableError from
        the verify() beneath; review and fail_open produce a degraded
        certificate, and the guard refuses to execute on one — a synthetic
        verdict is not a verification, so choosing fail_open on the client is
        deliberately not enough on its own to run an unverified tool. Set
        on_error at the client AND handle ArceziaUnavailableError if you want
        an outage to be survivable here.
        """
        from arcezia.integrations.universal import guard_callable

        def decorator(fn: Callable):
            return guard_callable(
                fn, self,
                domain=domain,
                action_type=action_type,
                block_on_review=block_on_review,
            )
        return decorator

    # ------------------------------------------------------------------
    # Chain verification
    # ------------------------------------------------------------------

    def verify_chain(
        self,
        chain_manifest: dict,
        stop_on_block: bool = True,
        data_subject_reference: Optional[str] = None,
    ) -> "ArceziaChainResult":
        """
        Verify a multi-step chain. Pass a chain manifest dict.

        State from each step propagates to subsequent steps.
        Semantic danger patterns (credential exfiltration, mass-destroy, etc.)
        are detected across accumulated state.

        data_subject_reference: optional per-call override of the client-level
        data subject (explicit value wins). Record-only — never changes any
        verdict. Steps may declare their own data_categories inside the
        manifest.

        When Arcezia is unreachable:
            fail_closed (default) — raises ArceziaUnavailableError. No step in
                the chain was verified, so the plan does not run.
            review — returns a synthetic result with
                ``overall_verdict == "REVIEW_REQUIRED"``.
            fail_open — returns a synthetic result with
                ``overall_verdict == "SAFE"``.
            Both synthetic results carry ``_synthetic: True`` and an empty
            ``steps`` list. A real response can never carry that key: it is
            stripped from every parsed body below, so the marker is not
            forgeable by anything upstream.

        Returns:
            ArceziaChainResult — a typed result. ``result.safe`` /
            ``result.blocked_at`` / ``result.degraded`` are the current API.
            Dict indexing (``result["overall_verdict"]``) still works for every
            documented key and is DEPRECATED; it exists because six docstring
            examples and every framework adapter's comment teach it.
        """
        def _call() -> "ArceziaChainResult":
            self._ensure_session()

            body_out: dict = {
                "task": self._task,
                "chain_manifest": chain_manifest,
                "stop_on_block": stop_on_block,
                "session_id": self._session_id,
            }
            subject = self._subject_ref(data_subject_reference)
            if subject is not None:
                body_out["data_subject_reference"] = subject

            status, body = _post(
                f"{self._api_url}/v1/verify_chain",
                self._headers(),
                body_out,
                retries=self._max_retries,
                timeout=self._timeout,
            )
            _raise_for_status(status, body)
            # `_synthetic` means "this SDK made it up because the engine was
            # unreachable". Nothing on the wire is allowed to claim it — strip
            # it so the marker stays a property of local construction and can
            # never be asserted by a response.
            body.pop("_synthetic", None)
            if "overall_verdict" not in body:
                raise ArceziaTransportError(
                    "POST /v1/verify_chain returned no overall_verdict; "
                    "no chain verdict was obtained."
                )
            return _parse_chain(body)

        return self._guarded(self._degrade_chain, _call)

    def verify_outcome(
        self,
        action_type: str,
        action_description: str,
        outcome: dict,
        expected: Optional[dict] = None,
        data_subject_reference: Optional[str] = None,
    ) -> "ArceziaOutcomeResult":
        """
        Post-execution outcome verification (Level 3).

        After an action is ALLOWed and executed, call this with what
        ACTUALLY happened. The engine checks whether the outcome matches
        the authorized intent.

        Args:
            action_type:        The action that was executed (must match prior verify)
            action_description: What was intended
            outcome:            What actually happened:
                                  rows_affected: int
                                  new_value: Any
                                  status_code: int
                                  error: str
                                  side_effects: list[str]
            expected:           Optional — what you expected to happen:
                                  rows_affected: int
                                  new_value: Any
                                  status_code: int
            data_subject_reference: Optional per-call override of the
                                client-level data subject (explicit value
                                wins). Record-only — never changes the verdict.

        Returns:
            ArceziaOutcomeResult with .allow / .block / .review + .violations

        When Arcezia is unreachable:
            fail_closed (default) — raises ArceziaUnavailableError. The action
                has already run, so this is not a gate on execution; it is the
                audit refusing to record an unverified outcome as a verified
                one.
            review — returns a synthetic REVIEW result (`.degraded` is True).
            fail_open — returns a synthetic ALLOW result, also `.degraded`.
            Both carry ``status == "OUTCOME_UNVERIFIED"``: nothing was compared
            against the authorized intent.
        """
        def _call() -> "ArceziaOutcomeResult":
            self._ensure_session()

            body_out: dict = {
                "session_id": self._session_id,
                "action_type": action_type,
                "action_description": action_description,
                "outcome": outcome,
                "expected": expected,
            }
            subject = self._subject_ref(data_subject_reference)
            if subject is not None:
                body_out["data_subject_reference"] = subject

            status, body = _post(
                f"{self._api_url}/v1/verify_outcome",
                self._headers(),
                body_out,
                retries=self._max_retries,
                timeout=self._timeout,
            )
            _raise_for_status(status, body)
            missing = [k for k in ("verdict", "status", "summary") if k not in body]
            if missing:
                # A 200 whose payload lacks the fields the endpoint is defined
                # to return is not an outcome verdict. Reading it positionally
                # raised a bare KeyError into the caller's loop; now it is the
                # same typed absence as any other unobtained answer.
                raise ArceziaTransportError(
                    f"POST /v1/verify_outcome returned no {', '.join(missing)}; "
                    f"no outcome verdict was obtained."
                )
            return ArceziaOutcomeResult(
                verdict=body["verdict"],
                status=body["status"],
                summary=body["summary"],
                violations=body.get("violations", []),
                warnings=body.get("warnings", []),
                outcome_recorded=body.get("outcome_recorded", {}),
                signature=body.get("signature", ""),
            )

        return self._guarded(self._degrade_outcome, _call)

    # ------------------------------------------------------------------
    # Usage
    # ------------------------------------------------------------------

    def usage(self) -> dict:
        """Return current billing period usage stats.

        When Arcezia is unreachable: raises ArceziaUnavailableError under EVERY
        on_error setting, including fail_open. This call does not gate anything,
        so there is no action to let through and no safe degraded verdict to
        return — and the only value that could be synthesised, an empty or
        zeroed usage dict, is a false statement about the account rather than a
        cautious one. A caller who wants to continue past an outage can catch
        the error; a caller who is shown zeros cannot tell that anything failed.
        """
        def _call() -> dict:
            status, body = _get(
                f"{self._api_url}/v1/usage", self._headers(),
                retries=self._max_retries, timeout=self._timeout,
            )
            _raise_for_status(status, body)
            return body

        return self._guarded(None, _call)

    # ------------------------------------------------------------------
    # Declarations — what silence means for your tools
    # ------------------------------------------------------------------

    def declarations(self) -> dict:
        """Read this key's `declared_absent` document and the declarable set.

        Returns the server's `{"declared_absent": {...}, "declarable_constraints":
        [...], "absence_channel": "declared" | "undeclared" | "unavailable"}`.
        Raises ArceziaUnavailableError under every on_error setting when the
        service cannot be reached (nothing is gated here, so there is no safe
        degraded answer).
        """
        def _call() -> dict:
            status, body = _get(
                f"{self._api_url}/v1/declarations", self._headers(),
                retries=self._max_retries, timeout=self._timeout,
            )
            _raise_for_status(status, body)
            return body

        return self._guarded(None, _call)

    def declare_absent(self, declared_absent: dict) -> dict:
        """Replace this key's declarations: `{fact_name: [action_type, ...]}`.

        You, not the agent, say which facts a given action type never carries —
        e.g. that ``execute_sql`` never sends data outbound. A declaration only
        resolves what the engine could NOT see; anything it detects still
        stands. Admin role required. Never declare ``"*"``: the service refuses
        it for a tool's own contract facts and it is a lie for the rest.

        Returns ``{"status": "ok", "declared_absent": {...}}`` as stored.
        Raises ValueError with the server's reason on a refused document (an
        unknown fact name, a wildcard where none is accepted).
        """
        if not isinstance(declared_absent, dict):
            raise ValueError("declared_absent must be a dict of {fact_name: [action_type, ...]}")

        def _call() -> dict:
            status, body = _post(
                f"{self._api_url}/v1/declarations", self._headers(),
                {"declared_absent": declared_absent},
                retries=self._max_retries, timeout=self._timeout,
            )
            if status == 400:
                raise ValueError(str((body or {}).get("detail") or body))
            _raise_for_status(status, body)
            return body

        return self._guarded(None, _call)

    # ------------------------------------------------------------------
    # Per-person audit lookup
    # ------------------------------------------------------------------

    def audit_subject(
        self,
        reference: str,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        limit: int = 500,
    ) -> dict:
        """Return every stored decision about one person.

        This is the GDPR Art 15 / DPDP §11 lookup: post the same reference
        you supplied at verification time; it is hashed, matched against the
        stored fingerprints, and never stored. Decisions verified without a
        subject reference cannot be found this way — attach the reference at
        verification time or the record is not attributable to anyone.

        Args:
            reference:  The data-subject reference used at verification time.
            date_from:  Optional ISO-8601 lower bound.
            date_to:    Optional ISO-8601 upper bound.
            limit:      Maximum number of decisions to return (default 500).

        When Arcezia is unreachable: raises ArceziaUnavailableError under EVERY
        on_error setting, including fail_open. This is the answer to a data
        subject's access request. The only synthesisable value is an empty
        result, and an empty result here READS as "we hold no decisions about
        this person" — a substantive, wrong, and legally consequential claim.
        An outage must surface as an outage, not as a finding of nothing.
        """
        def _call() -> dict:
            body_out: dict = {"reference": reference, "limit": limit}
            if date_from is not None:
                body_out["date_from"] = date_from
            if date_to is not None:
                body_out["date_to"] = date_to
            status, body = _post(
                f"{self._api_url}/v1/audit/subject",
                self._headers(),
                body_out,
                retries=self._max_retries,
                timeout=self._timeout,
            )
            _raise_for_status(status, body)
            return body

        return self._guarded(None, _call)


# ── Parsing helpers ───────────────────────────────────────────────────────────

_CERT_REQUIRED_FIELDS = ("verdict", "status", "trust_score", "summary")


def _parse_chain(body: dict) -> ArceziaChainResult:
    """Turn a /v1/verify_chain response into the typed result.

    Called only after ``overall_verdict`` has been confirmed present — a body
    without it is a transport error, not a chain with an unknown verdict.

    ``_synthetic`` is never read from ``body``: verify_chain strips it before
    this runs, and this constructor does not accept it from the wire either, so
    the local-origin marker has exactly one producer.
    """
    return ArceziaChainResult(
        overall_verdict=body["overall_verdict"],
        blocked_at=body.get("blocked_at"),
        steps=body.get("steps") or [],
        semantic_triggers=body.get("semantic_triggers") or [],
        # `human_summary` is the wire key — the chain response has never had a
        # `summary`. (The dict this replaces built one locally on the degraded
        # path only, which is why `result["summary"]` still resolves below.)
        human_summary=body.get("human_summary") or "",
        raw=dict(body),
    )


def _parse_cert(resp: dict) -> ArceziaCertificate:
    # A 200 whose payload is missing these is not a certificate. Indexing it
    # raised a bare KeyError out of verify() — an untyped crash in an agent's
    # tool loop, and one that no `on_error` setting could degrade. It is the
    # same fact as a connection refused: no verdict was obtained.
    missing = [k for k in _CERT_REQUIRED_FIELDS if k not in resp]
    if missing:
        raise ArceziaTransportError(
            f"POST /v1/verify returned no {', '.join(missing)}; "
            f"no verdict was obtained."
        )

    # ── The three auxiliary flags with an honest "not reported" (T7) ─────────
    # Each of these was previously read with a permissive default — False, [],
    # None-as-clear — so a server that omitted the key was indistinguishable
    # from one that had checked and found nothing. That is absence converted
    # into a fact, and it is the defect class this codebase keeps finding.
    # Here, absence stays absence and travels as None.
    _fab = resp.get("fabrication_detected")
    _axes = resp.get("denied_authority_axes")

    return ArceziaCertificate(
        verdict=resp["verdict"],
        status=resp["status"],
        precondition_score=resp.get("precondition_score", resp.get("dc_score", 0.0)),
        trust_score=resp["trust_score"],
        summary=resp["summary"],
        violated=resp.get("violated", []),
        missing=resp.get("missing", []),
        fabrication_detected=None if _fab is None else bool(_fab),
        fabricated_constraints=resp.get("fabricated_constraints", []),
        # Copied, not aliased: `raw` is a shallow copy of the response, so
        # handing out the same list object would let a caller's append mutate
        # what `raw` reports the server said.
        denied_authority_axes=list(_axes) if isinstance(_axes, list) else None,
        unresolved=resp.get("unresolved", []),
        chain_status=resp.get("chain_status"),
        chain_patterns=[
            p.get("pattern_name", str(p)) if isinstance(p, dict) else str(p)
            for p in (resp.get("chain_patterns") or [])
        ],
        probe_outcomes=resp.get("probe_outcomes") or {},
        evidence_channel=resp.get("evidence_channel"),
        evidence_channel_failures=resp.get("evidence_channel_failures") or {},
        simulation_channel=resp.get("simulation_channel"),
        simulation_channel_detail=resp.get("simulation_channel_detail"),
        degraded_defenses=resp.get("degraded_defenses") or [],
        unverified_approvals=resp.get("unverified_approvals") or [],
        absence_channel=resp.get("absence_channel"),
        envelope_signed=(resp.get("envelope_signed")
                         if isinstance(resp.get("envelope_signed"), bool)
                         else None),
        log_id=resp.get("log_id"),
        created_at=resp.get("created_at"),
        request_id=resp.get("request_id"),
        session_id=resp.get("session_id"),
        action_identity=resp.get("action_identity"),
        ruleset_hash=resp.get("ruleset_hash"),
        engine_version=resp.get("engine_version"),
        record_signature=resp.get("record_signature"),
        signed_at=resp.get("signed_at"),
        data_categories=resp.get("data_categories"),
        raw=dict(resp),
        constraints=[
            # Read defensively: a truncated or partial constraint row must not
            # crash the parse, and every default here is the LEAST trusted
            # reading — value None (unresolved, never True) and quality
            # UNRESOLVED — so a missing field can only tighten, never loosen.
            ArceziaConstraintDetail(
                name=c.get("name", "unknown"),
                value=c.get("value"),
                quality=c.get("quality", "UNRESOLVED"),
                detail=c.get("detail", ""),
                quality_plain=c.get("quality_plain", ""),
            )
            for c in resp.get("constraints", [])
            if isinstance(c, dict)
        ],
        signature=resp.get("signature", ""),
        credential=resp.get("credential"),
    )
