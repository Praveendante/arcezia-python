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
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlparse

try:
    import httpx
    _TRANSPORT = "httpx"
    # Network/timeout errors worth retrying (not deterministic 4xx responses).
    _NET_ERRORS: tuple = (httpx.TransportError, httpx.TimeoutException)
except ImportError:
    import urllib.request as _urllib_request
    import urllib.error as _urllib_error
    import socket as _socket
    import json as _json
    _TRANSPORT = "urllib"
    _NET_ERRORS = (_urllib_error.URLError, _socket.timeout)


_SDK_VERSION = "1.0.0"
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


class ArceziaUnavailableError(RuntimeError):
    """
    Raised when Arcezia cannot be reached after retries and the client is in the
    default fail-closed mode. The action is blocked because safety could not be
    verified — never silently allowed.
    """
    def __init__(self, cause: Exception):
        self.cause = cause
        super().__init__(f"Arcezia unreachable; action blocked (fail-closed): {cause}")


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class ArceziaConstraintDetail:
    name: str
    value: Optional[bool]
    quality: str    # GROUNDED | CLAIMED | UNRESOLVED | FABRICATED
    detail: str


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
    fabrication_detected: bool
    fabricated_constraints: list[str]
    constraints: list[ArceziaConstraintDetail]
    signature: str
    credential: Optional[dict] = None     # set on ALLOW — pass to your tool

    @property
    def degraded(self) -> bool:
        """True if this certificate is a synthetic fallback (unverified).
        A degraded cert was not verified by the engine — its credential is None
        and its verdict is not grounded in a proof. This is a synthetic
        fallback that must never be treated as a verified result."""
        return self.credential is None and self.trust_score == 0.0

    @property
    def allow(self) -> bool:
        return self.verdict == "ALLOW" and not self.fabrication_detected

    @property
    def block(self) -> bool:
        return self.verdict == "BLOCK" or self.fabrication_detected

    @property
    def review(self) -> bool:
        return self.verdict == "REVIEW" and not self.fabrication_detected

    def __str__(self) -> str:
        icon = {"ALLOW": "✅", "BLOCK": "❌", "REVIEW": "⚠️"}.get(self.verdict, "?")
        fab = " 🚨 FABRICATION DETECTED" if self.fabrication_detected else ""
        return (
            f"{icon} {self.verdict}{fab} | "
            f"trust={self.trust_score:.0%} | "
            f"preconditions={self.precondition_score:.2f} | "
            f"{self.summary}"
        )


# ── Transport helpers ─────────────────────────────────────────────────────────

def _once_post(url: str, headers: dict, body: dict, timeout: float) -> tuple[int, dict]:
    import json
    if _TRANSPORT == "httpx":
        resp = httpx.post(url, headers=headers, json=body, timeout=timeout)
        try:
            data = resp.json()
        except Exception:
            data = {"detail": resp.text}
        return resp.status_code, data
    data_bytes = json.dumps(body).encode()
    req = _urllib_request.Request(
        url, data=data_bytes,
        headers={**headers, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _urllib_request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except _urllib_request.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _once_get(url: str, headers: dict, timeout: float) -> tuple[int, dict]:
    import json
    if _TRANSPORT == "httpx":
        resp = httpx.get(url, headers=headers, timeout=timeout)
        try:
            data = resp.json()
        except Exception:
            data = {"detail": resp.text}
        return resp.status_code, data
    req = _urllib_request.Request(url, headers=headers, method="GET")
    try:
        with _urllib_request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except _urllib_request.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


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
        raise ArceziaUpgradeRequired(body.get("detail", body))
    if status == 429:
        detail = body.get("detail", {})
        if not isinstance(detail, dict):
            detail = {"message": str(detail)}
        retry_after = detail.get("window") and 60  # per-minute window → 60s
        raise ArceziaRateLimitError(detail, retry_after=retry_after)
    if status == 401:
        raise ArceziaAuthError(str(body.get("detail", body)))
    if status >= 400:
        raise ArceziaAPIError(status, str(body))


# ── Main client ───────────────────────────────────────────────────────────────

class Arcezia:
    """
    Arcezia safety enforcement client.

    One instance per agent session. Maintains session_id and auth tokens.

        az = Arcezia(api_key="ar_live_...", task="clean up test records")
        cert = az.verify(action_type="execute_sql", action_description="...", domain="database_ops")
        if cert.block:
            raise SafetyViolation(cert.summary)
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
    ):
        """
        on_error — behaviour when Arcezia is unreachable after retries:
          "fail_closed" (default) → raise ArceziaUnavailableError; the action is
              blocked because safety could not be verified.
          "review" → return a synthetic REVIEW verdict; the action halts pending
              human confirmation (safe degradation).
          "fail_open" → return a synthetic ALLOW verdict; the action proceeds
              unverified. Only for non-critical actions — use deliberately.

        mode — "production" (default) or "development".
          In development mode, infrastructure constraints (backup APIs,
          capability envelopes, CI gates) are relaxed so developers can
          experiment without external infrastructure. Structural safety
          constraints (fabrication, exfiltration, authorization) remain
          strict in both modes. Can also be set via ARCEZIA_ENV env var.
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
        # In production (live key), refuse localhost/loopback to prevent SSRF
        # where a compromised config redirects verification calls to an internal
        # service that always returns ALLOW.
        _is_live = self._api_key.startswith("ar_live_")
        _loopback = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
        if _is_live and _parsed.hostname in _loopback:
            raise ValueError(
                "ARCEZIA_API_URL cannot point to localhost for live API keys. "
                "Use ar_test_... keys for local development."
            )
        self._api_url = raw_url
        self._session_id: Optional[str] = None
        self._user_token: Optional[str] = None
        self._prod_token: Optional[str] = None

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "X-Arcezia-SDK": "python/1.0.0",
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
                max_scope ("single_record"|"batch"|"mass"), allowed_action_types
                (list[str]), expires_at (ISO-8601 str). In production, this dict
                should be signed by your backend after the user confirms scope.
        """
        payload: dict = {"task": self._task}
        if capability_envelope:
            payload["capability_envelope"] = capability_envelope
        status, body = _post(
            f"{self._api_url}/v1/session",
            self._headers(),
            payload,
        )
        _raise_for_status(status, body)
        self._session_id = body["session_id"]
        return body

    # ------------------------------------------------------------------
    # Authorization (human-in-the-loop)
    # ------------------------------------------------------------------

    def authorize(self, token: str) -> "Arcezia":
        """
        Provide a signed user intent token.
        Grounds user_explicit_authorization as GROUNDED.

        In production: token = JWT signed by your UI backend after the user
        clicks "Approve" on the action confirmation dialog.
        In development: any non-empty string works.
        """
        self._user_token = token
        if self._session_id:
            self._attach_token("user", token)
        return self

    def authorize_production(self, token: str) -> "Arcezia":
        """Grounds production_explicit_authorization as GROUNDED."""
        self._prod_token = token
        if self._session_id:
            self._attach_token("production", token)
        return self

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
        )
        _raise_for_status(status, body)

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
    ) -> ArceziaCertificate:
        """
        Verify whether an action is safe to execute.

        On ALLOW: cert.credential contains a single-use token. Pass it to your
        tool so the tool can validate it at /v1/validate_credential before executing.

        Args:
            action_type:        Tool name ("execute_sql", "write_file", …)
            action_description: Human-readable description of the action.
            domain:             Constraint domain. Defaults to "agent_action".
            agent_evidence:     Optional LLM-supplied evidence (llm_inferred only).
            state_mutations:    Optional session state updates after this action executes
                                (e.g. {"file_contains_secrets": True} after a write).
        """
        try:
            if not self._session_id:
                self.start_session()

            body: dict[str, Any] = {
                "task": self._task,
                "action_type": action_type,
                "action_description": action_description,
                "domain": domain,
                "session_id": self._session_id,
            }
            if self._mode and self._mode.lower() in ("development", "dev"):
                body["mode"] = "development"
            if agent_evidence:
                body["agent_evidence"] = agent_evidence
            if state_mutations:
                body["state_mutations"] = state_mutations

            status, resp = _post(
                f"{self._api_url}/v1/verify", self._headers(), body,
                retries=self._max_retries, timeout=self._timeout,
            )
            _raise_for_status(status, resp)
            return _parse_cert(resp)
        except _NET_ERRORS as exc:
            return self._on_transport_failure(exc)
        except ArceziaAPIError as exc:
            # 5xx = transient server failure → fail-mode. 4xx = deterministic → raise.
            if exc.status_code >= 500:
                return self._on_transport_failure(exc)
            raise

    # ------------------------------------------------------------------
    # Fail-mode (Arcezia unreachable)
    # ------------------------------------------------------------------

    def _on_transport_failure(self, exc: Exception) -> ArceziaCertificate:
        if self._on_error == "fail_open":
            return self._degraded_cert("ALLOW", exc)
        if self._on_error == "review":
            return self._degraded_cert("REVIEW", exc)
        raise ArceziaUnavailableError(exc)   # fail_closed (default)

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
            fabrication_detected=False,
            fabricated_constraints=[],
            constraints=[],
            signature="",
            credential=None,
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

    def verify_chain(self, chain_manifest: dict, stop_on_block: bool = True) -> dict:
        """
        Verify a multi-step chain. Pass a chain manifest dict.

        State from each step propagates to subsequent steps.
        Semantic danger patterns (credential exfiltration, mass-destroy, etc.)
        are detected across accumulated state.
        """
        if not self._session_id:
            self.start_session()

        status, body = _post(
            f"{self._api_url}/v1/verify_chain",
            self._headers(),
            {
                "task": self._task,
                "chain_manifest": chain_manifest,
                "stop_on_block": stop_on_block,
                "session_id": self._session_id,
            },
        )
        _raise_for_status(status, body)
        return body

    def verify_outcome(
        self,
        action_type: str,
        action_description: str,
        outcome: dict,
        expected: Optional[dict] = None,
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

        Returns:
            ArceziaOutcomeResult with .allow / .block / .review + .violations
        """
        if not self._session_id:
            self.start_session()

        status, body = _post(
            f"{self._api_url}/v1/verify_outcome",
            self._headers(),
            {
                "session_id": self._session_id,
                "action_type": action_type,
                "action_description": action_description,
                "outcome": outcome,
                "expected": expected,
            },
        )
        _raise_for_status(status, body)
        return ArceziaOutcomeResult(
            verdict=body["verdict"],
            status=body["status"],
            summary=body["summary"],
            violations=body.get("violations", []),
            warnings=body.get("warnings", []),
            outcome_recorded=body.get("outcome_recorded", {}),
            signature=body.get("signature", ""),
        )

    # ------------------------------------------------------------------
    # Usage
    # ------------------------------------------------------------------

    def usage(self) -> dict:
        """Return current billing period usage stats."""
        status, body = _get(f"{self._api_url}/v1/usage", self._headers())
        _raise_for_status(status, body)
        return body


# ── Parsing helpers ───────────────────────────────────────────────────────────

def _parse_cert(resp: dict) -> ArceziaCertificate:
    return ArceziaCertificate(
        verdict=resp["verdict"],
        status=resp["status"],
        precondition_score=resp.get("precondition_score", resp.get("dc_score", 0.0)),
        trust_score=resp["trust_score"],
        summary=resp["summary"],
        violated=resp.get("violated", []),
        missing=resp.get("missing", []),
        fabrication_detected=resp.get("fabrication_detected", False),
        fabricated_constraints=resp.get("fabricated_constraints", []),
        constraints=[
            ArceziaConstraintDetail(
                name=c["name"],
                value=c["value"],
                quality=c["quality"],
                detail=c["detail"],
            )
            for c in resp.get("constraints", [])
        ],
        signature=resp.get("signature", ""),
        credential=resp.get("credential"),
    )
