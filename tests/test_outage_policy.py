#!/usr/bin/env python3
"""
What happens to a customer when Arcezia is unreachable.

Every assertion here runs against a REAL loopback HTTP server that can refuse
the connection, hang past the timeout, return 500, return a WAF's HTML, return
truncated JSON, or close the connection mid-body. Patched functions cannot
produce most of those: a mock cannot half-write a Content-Length, and the two
bugs this file pins (a raw JSONDecodeError from the urllib transport, and a raw
ConnectError from six of the seven network-calling methods) both live below the
level a patched `_post` replaces.

The acceptance property, asserted exhaustively in TestNoOutagePathYieldsAllow:

    under the default on_error="fail_closed", NO method × NO failure mode
    returns a permissive value. Every one raises ArceziaUnavailableError.

Both transports are exercised. httpx is installed on developer machines, so the
urllib fallback — the path a plain `pip install arcezia` actually uses — was
never executed by this suite before; it is the path that called json.loads()
unguarded.
"""
from __future__ import annotations

import json
import socket
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import arcezia.client as client_mod                                # noqa: E402
from arcezia.client import (                                       # noqa: E402
    Arcezia,
    ArceziaAPIError,
    ArceziaCertificate,
    ArceziaOutcomeResult,
    ArceziaTransportError,
    ArceziaUnavailableError,
)


# ── A loopback server that can fail in every way a real one does ─────────────

# path suffix -> failure mode; "*" is the default for any path not named.
_MODE: dict = {"*": "ok"}
_RECORDED: list = []


def _mode_for(path: str) -> str:
    for key, mode in _MODE.items():
        if key != "*" and path.endswith(key):
            return mode
    return _MODE["*"]


_OK_BODIES = {
    "/v1/session": {"session_id": "sess-outage-001", "task": "t"},
    "/v1/authorize": {"ok": True, "token_fingerprint": "abcd"},
    "/v1/verify": {
        "verdict": "ALLOW", "status": "ALLOWED", "precondition_score": 1.0,
        "trust_score": 1.0, "summary": "ok", "violated": [], "missing": [],
        "fabrication_detected": False, "fabricated_constraints": [],
        "constraints": [], "signature": "sig", "credential": {"token": "c"},
    },
    "/v1/verify_chain": {
        "overall_verdict": "SAFE", "blocked_at": None, "steps": [],
        "semantic_triggers": [], "final_state": {},
    },
    "/v1/verify_outcome": {
        "verdict": "ALLOW", "status": "OUTCOME_VERIFIED", "summary": "matched",
        "violations": [], "warnings": [], "outcome_recorded": {}, "signature": "s",
    },
    "/v1/usage": {"verifications_this_month": 42, "limit": 1000, "tier": "free"},
    "/v1/audit/subject": {"reference_matched": True, "decisions": [{"log_id": 1}]},
}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # -- the failure modes -------------------------------------------------
    def _raw(self, status: int, payload: bytes, ctype: str):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _mid_body_close(self):
        """Promise 500 bytes, send 19, hang up. The classic truncated read."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "500")
        self.end_headers()
        self.wfile.write(b'{"verdict": "ALLO')
        try:
            self.wfile.flush()
        except Exception:
            pass
        self.close_connection = True
        try:
            self.connection.close()
        except Exception:
            pass

    def _dispatch(self, path: str):
        mode = _mode_for(path)
        if mode == "hang":
            time.sleep(3.0)
            return self._raw(200, b"{}", "application/json")
        if mode == "500":
            return self._raw(500, b'{"detail": "internal error"}', "application/json")
        if mode == "html403":
            return self._raw(
                403,
                b"<html><head><title>403 Forbidden</title></head>"
                b"<body>Request blocked by security policy.</body></html>",
                "text/html",
            )
        if mode == "html200":
            return self._raw(200, b"<html><body>hello</body></html>", "text/html")
        if mode == "truncated":
            return self._raw(200, b'{"verdict": "ALL', "application/json")
        if mode == "empty200":
            return self._raw(200, b"", "application/json")
        if mode == "notobject":
            return self._raw(200, b"[1, 2, 3]", "application/json")
        if mode == "midbody":
            return self._mid_body_close()
        for suffix, body in _OK_BODIES.items():
            if path.endswith(suffix):
                return self._raw(200, json.dumps(body).encode(), "application/json")
        return self._raw(404, b'{"detail": "no route"}', "application/json")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}
        _RECORDED.append(("POST", self.path, body))
        self._dispatch(self.path)

    def do_GET(self):
        _RECORDED.append(("GET", self.path, {}))
        self._dispatch(self.path)


def _dead_port() -> int:
    """A port nothing is listening on — connection refused, not a timeout."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _Loopback(unittest.TestCase):
    """Base fixture: a live server, plus knobs for each failure mode."""

    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.httpd.daemon_threads = True
        cls.url = f"http://127.0.0.1:{cls.httpd.server_port}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.dead_url = f"http://127.0.0.1:{_dead_port()}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        _MODE.clear()
        _MODE["*"] = "ok"
        _RECORDED.clear()
        self.addCleanup(lambda: setattr(client_mod, "_TRANSPORT", self._transport0))
        self._transport0 = client_mod._TRANSPORT

    def _client(self, on_error: str = "fail_closed", *, url: str | None = None,
                timeout: float = 30.0) -> Arcezia:
        # ar_test_ key: the SSRF guard permits loopback only for test keys.
        return Arcezia(api_key="ar_test_local", task="settle invoice 402",
                       api_url=url or self.url, on_error=on_error,
                       max_retries=0, timeout=timeout)

    @staticmethod
    def _paths():
        return [p for _, p, _ in _RECORDED]

    def _armed(self, on_error: str, mode: str, needs_session: bool) -> Arcezia:
        """A client with a healthy session where one is required, then the
        chosen failure mode armed for the call under test.

        "refused" is staged rather than configured: the session is opened
        against the live server and the client is then pointed at a dead port —
        which is what an outage between two calls actually looks like.
        """
        _MODE.clear()
        _MODE["*"] = "ok"
        az = self._client(on_error, timeout=0.5 if mode == "hang" else 5.0,
                          url=self.url if (needs_session or mode != "refused")
                          else self.dead_url)
        if needs_session:
            az.start_session()
        if mode == "refused":
            az._api_url = self.dead_url
        else:
            _MODE["*"] = mode
        return az


# ── The seven network-calling methods, as callables ──────────────────────────
#
# `needs_session` marks the ones that open a session first: for those, the
# outage can strike at either request, and both must land on the same policy.

def _call_verify(az):
    return az.verify(action_type="issue_refund",
                     action_description="Refund invoice 402 for 129.50 USD",
                     domain="payment_ops")


def _call_verify_chain(az):
    return az.verify_chain({"steps": [
        {"step_id": "s1", "action_type": "read_file",
         "domain": "filesystem_ops", "action_description": "read config"},
    ]})


def _call_verify_outcome(az):
    return az.verify_outcome(action_type="execute_sql",
                             action_description="DELETE FROM t WHERE test",
                             outcome={"rows_affected": 1},
                             expected={"rows_affected": 1})


def _call_start_session(az):
    return az.start_session()


def _call_authorize(az):
    return az.authorize("user-jwt-abc")


def _call_authorize_production(az):
    return az.authorize_production("prod-jwt-xyz")


def _call_usage(az):
    return az.usage()


def _call_audit_subject(az):
    return az.audit_subject(reference="cust-402")


# name -> (callable, needs a live session opened first)
METHODS = {
    "verify":               (_call_verify, False),
    "verify_chain":         (_call_verify_chain, False),
    "verify_outcome":       (_call_verify_outcome, False),
    "start_session":        (_call_start_session, False),
    "authorize":            (_call_authorize, True),
    "authorize_production": (_call_authorize_production, True),
    "usage":                (_call_usage, False),
    "audit_subject":        (_call_audit_subject, False),
}

# Failure modes that mean "no answer was obtained". A 4xx is excluded on
# purpose — it IS an answer, and is asserted separately.
OUTAGE_MODES = ("refused", "hang", "500", "html200", "truncated", "empty200",
                "notobject", "midbody")

TRANSPORTS = ("httpx", "urllib")


# ── 1. THE ACCEPTANCE TEST ───────────────────────────────────────────────────

class TestNoOutagePathYieldsAllow(_Loopback):
    """Every method × every failure mode × both transports, under the default.

    The single most important property of this change: an outage never becomes
    an ALLOW unless the operator explicitly chose fail_open. Under fail_closed
    the only permitted result is ArceziaUnavailableError — not a permissive
    return value, and not an untyped crash either (a bare JSONDecodeError or
    KeyError would pass a naive "it raised" test while being uncatchable by the
    documented `except ArceziaUnavailableError`).
    """

    def test_fail_closed_raises_typed_unavailable_everywhere(self):
        for transport in TRANSPORTS:
            if transport == "httpx" and client_mod.httpx is None:
                continue
            for mode in OUTAGE_MODES:
                for name, (call, needs_session) in METHODS.items():
                    with self.subTest(transport=transport, mode=mode, method=name):
                        client_mod._TRANSPORT = transport
                        az = self._armed("fail_closed", mode, needs_session)
                        with self.assertRaises(ArceziaUnavailableError):
                            call(az)

    def test_no_method_returns_a_permissive_value_under_the_default(self):
        """Restates the above as the property a reviewer asks about.

        Not 'it raised' — 'nothing came back that an agent could act on'. If a
        future change made any of these return instead of raise, this fails
        with the value that leaked.
        """
        for mode in OUTAGE_MODES:
            for name, (call, needs_session) in METHODS.items():
                with self.subTest(mode=mode, method=name):
                    az = self._armed("fail_closed", mode, needs_session)
                    leaked = None
                    try:
                        leaked = call(az)
                    except ArceziaUnavailableError:
                        continue
                    self.fail(f"{name} under {mode} returned {leaked!r} "
                              f"instead of raising")

    def test_a_4xx_is_an_answer_and_is_never_degraded(self):
        """A WAF's HTML 403 must NOT be laundered into a verdict.

        Not even under fail_open. A deployment blocked at the edge fails
        loudly; the alternative is an agent that runs every tool unverified and
        looks healthy while doing it.
        """
        for on_error in ("fail_closed", "review", "fail_open"):
            for name, (call, needs_session) in METHODS.items():
                with self.subTest(on_error=on_error, method=name):
                    az = self._armed(on_error, "html403", needs_session)
                    with self.assertRaises(ArceziaAPIError) as ctx:
                        call(az)
                    self.assertEqual(ctx.exception.status_code, 403)


# ── 2. The per-method degraded values ────────────────────────────────────────

class TestDegradedValues(_Loopback):
    """review and fail_open return the documented shape — and only that."""

    def _unreachable(self, on_error: str, needs_session: bool = False) -> Arcezia:
        az = self._client(on_error, url=self.dead_url)
        return az

    def test_verify_fail_open_is_a_synthetic_allow(self):
        cert = _call_verify(self._unreachable("fail_open"))
        self.assertIsInstance(cert, ArceziaCertificate)
        self.assertEqual(cert.verdict, "ALLOW")
        self.assertTrue(cert.degraded)
        self.assertIsNone(cert.credential)
        self.assertEqual(cert.signature, "")

    def test_verify_review_is_a_synthetic_review(self):
        cert = _call_verify(self._unreachable("review"))
        self.assertEqual(cert.verdict, "REVIEW")
        self.assertTrue(cert.degraded)
        self.assertIsNone(cert.credential)

    def test_verify_chain_fail_open_is_synthetic_safe(self):
        res = _call_verify_chain(self._unreachable("fail_open"))
        self.assertEqual(res["overall_verdict"], "SAFE")
        self.assertTrue(res["_synthetic"])
        self.assertEqual(res["steps"], [])

    def test_verify_chain_review_is_review_required(self):
        res = _call_verify_chain(self._unreachable("review"))
        self.assertEqual(res["overall_verdict"], "REVIEW_REQUIRED")
        self.assertTrue(res["_synthetic"])

    def test_verify_outcome_degrades_to_a_marked_result(self):
        for mode, verdict in (("fail_open", "ALLOW"), ("review", "REVIEW")):
            with self.subTest(mode=mode):
                res = _call_verify_outcome(self._unreachable(mode))
                self.assertIsInstance(res, ArceziaOutcomeResult)
                self.assertEqual(res.verdict, verdict)
                self.assertEqual(res.status, "OUTCOME_UNVERIFIED")
                self.assertTrue(res.degraded)

    def test_start_session_degrades_to_a_pending_session_not_a_fake_one(self):
        for mode in ("review", "fail_open"):
            with self.subTest(mode=mode):
                az = self._unreachable(mode)
                body = az.start_session()
                self.assertIsNone(body["session_id"])
                self.assertTrue(body["_synthetic"])
                # Crucially: no id was invented. The next call retries.
                self.assertIsNone(az._session_id)

    def test_usage_and_audit_subject_raise_under_every_policy(self):
        for on_error in ("fail_closed", "review", "fail_open"):
            for name, call in (("usage", _call_usage),
                               ("audit_subject", _call_audit_subject)):
                with self.subTest(on_error=on_error, method=name):
                    with self.assertRaises(ArceziaUnavailableError):
                        call(self._unreachable(on_error))


# ── 3. The synthetic marker cannot be forged from the wire ───────────────────

class TestSyntheticMarkerIsNotForgeable(_Loopback):

    def test_a_server_cannot_claim_synthetic_on_a_chain_result(self):
        _OK_BODIES["/v1/verify_chain"]["_synthetic"] = True
        self.addCleanup(_OK_BODIES["/v1/verify_chain"].pop, "_synthetic", None)
        res = _call_verify_chain(self._client())
        self.assertNotIn("_synthetic", res,
                         "a response claimed the local-fallback marker")

    def test_a_server_cannot_set_degraded_on_a_certificate(self):
        _OK_BODIES["/v1/verify"]["_synthetic"] = True
        self.addCleanup(_OK_BODIES["/v1/verify"].pop, "_synthetic", None)
        cert = _call_verify(self._client())
        self.assertFalse(cert.degraded,
                         "a parsed response was reported as a local fallback")

    def test_a_real_allow_is_not_degraded(self):
        cert = _call_verify(self._client())
        self.assertEqual(cert.verdict, "ALLOW")
        self.assertFalse(cert.degraded)
        self.assertIsNotNone(cert.credential)


# ── 4. Transport hardening — no malformed body may crash ─────────────────────

class TestTransportNeverCrashes(_Loopback):
    """The urllib path called json.loads() unguarded at two sites.

    A WAF HTML 403, a truncated body, or a connection closed mid-response each
    produced a raw json.JSONDecodeError in the customer's agent loop —
    uncatchable by the documented handler, and invisible on a machine with
    httpx installed, which is every machine this suite had run on.
    """

    MALFORMED = ("html200", "truncated", "empty200", "notobject", "midbody")

    def test_no_json_decode_error_escapes_on_either_transport(self):
        for transport in TRANSPORTS:
            if transport == "httpx" and client_mod.httpx is None:
                continue
            for mode in self.MALFORMED:
                with self.subTest(transport=transport, mode=mode):
                    client_mod._TRANSPORT = transport
                    _MODE["*"] = mode
                    az = self._client("fail_closed")
                    try:
                        _call_verify(az)
                    except ArceziaUnavailableError:
                        pass
                    except json.JSONDecodeError as exc:      # the bug
                        self.fail(f"raw JSONDecodeError escaped: {exc}")
                    except KeyError as exc:                  # the sibling bug
                        self.fail(f"raw KeyError escaped: {exc}")
                    else:
                        self.fail("a malformed body produced a verdict")

    def test_a_waf_html_403_is_a_typed_api_error_on_both_transports(self):
        for transport in TRANSPORTS:
            if transport == "httpx" and client_mod.httpx is None:
                continue
            with self.subTest(transport=transport):
                client_mod._TRANSPORT = transport
                _MODE["*"] = "html403"
                with self.assertRaises(ArceziaAPIError) as ctx:
                    _call_verify(self._client())
                self.assertEqual(ctx.exception.status_code, 403)
                self.assertIn("403 Forbidden", str(ctx.exception))

    def test_both_transports_decode_an_error_body_identically(self):
        """The two paths used to disagree: httpx wrapped the text, urllib threw.

        'Two paths that should agree and don't' is the shape of most real
        defects in this codebase, so it is asserted directly rather than
        implied.
        """
        seen = {}
        for transport in TRANSPORTS:
            if transport == "httpx" and client_mod.httpx is None:
                continue
            client_mod._TRANSPORT = transport
            _MODE["*"] = "html403"
            try:
                _call_verify(self._client())
            except ArceziaAPIError as exc:
                seen[transport] = (exc.status_code, "403 Forbidden" in str(exc))
        self.assertEqual(len(set(seen.values())), 1, seen)

    def test_a_200_with_a_truncated_body_is_a_transport_error(self):
        _MODE["*"] = "truncated"
        with self.assertRaises(ArceziaTransportError):
            client_mod._once_post(f"{self.url}/v1/verify", {}, {}, 5.0)

    def test_a_200_that_is_not_a_json_object_is_a_transport_error(self):
        _MODE["*"] = "notobject"
        with self.assertRaises(ArceziaTransportError):
            client_mod._once_post(f"{self.url}/v1/verify", {}, {}, 5.0)

    def test_an_error_status_with_html_still_yields_a_dict(self):
        _MODE["*"] = "html403"
        status, body = client_mod._once_post(f"{self.url}/v1/verify", {}, {}, 5.0)
        self.assertEqual(status, 403)
        self.assertIsInstance(body, dict)
        self.assertIn("403 Forbidden", body["detail"])

    def test_a_402_carrying_a_string_detail_does_not_crash_the_error_path(self):
        """ArceziaUpgradeRequired reads detail with .get(); a proxy sends a str."""
        from arcezia.client import ArceziaUpgradeRequired, _raise_for_status
        with self.assertRaises(ArceziaUpgradeRequired) as ctx:
            _raise_for_status(402, {"detail": "payment required"})
        self.assertIn("payment required", str(ctx.exception))

    def test_a_missing_verdict_field_is_typed_not_a_key_error(self):
        from arcezia.client import _parse_cert
        with self.assertRaises(ArceziaTransportError):
            _parse_cert({"status": "ALLOWED", "trust_score": 1.0, "summary": "s"})

    def test_a_partial_constraint_row_reads_as_unresolved_not_satisfied(self):
        """Absence must tighten, never loosen — even in a half-read row."""
        from arcezia.client import _parse_cert
        cert = _parse_cert({
            "verdict": "REVIEW", "status": "INSUFFICIENT_EVIDENCE",
            "trust_score": 0.0, "summary": "s",
            "constraints": [{"name": "backup_verified"}],
        })
        self.assertIsNone(cert.constraints[0].value)
        self.assertEqual(cert.constraints[0].quality, "UNRESOLVED")


# ── 5. A human approval is never silently discarded ──────────────────────────

class TestApprovalSurvivesAnOutage(_Loopback):
    """The failure mode this SDK has already shipped once, in a new place.

    authorize() used to be a no-op before start_session(); that was fixed. The
    same discard was still reachable the other way round: with a session open,
    a failed POST /v1/authorize left the token in a field nothing ever retried.
    """

    def test_a_failed_attach_is_retried_before_the_next_verdict(self):
        az = self._client("review")
        az.start_session()
        _MODE["/v1/authorize"] = "500"
        az.authorize("user-jwt-abc")            # review mode: buffered, not raised
        self.assertIn("user", az._pending_tokens)

        _MODE.pop("/v1/authorize")
        _RECORDED.clear()
        _call_verify(az)
        paths = self._paths()
        self.assertIn("/v1/authorize", paths,
                      f"the approval was never retried: {paths}")
        self.assertLess(paths.index("/v1/authorize"), paths.index("/v1/verify"),
                        f"the verdict was asked for before the approval landed: {paths}")
        self.assertEqual(az._pending_tokens, {})

    def test_fail_closed_tells_the_human_their_approval_did_not_land(self):
        az = self._client("fail_closed")
        az.start_session()
        _MODE["/v1/authorize"] = "500"
        with self.assertRaises(ArceziaUnavailableError):
            az.authorize("user-jwt-abc")
        # …and it is still pending, so it is deferred, not lost.
        self.assertEqual(az._pending_tokens.get("user"), "user-jwt-abc")

    def test_a_server_refused_token_is_not_retried_forever(self):
        """A 4xx is deterministic: raise once, then stop re-raising it."""
        az = self._client()
        az.start_session()
        _MODE["/v1/authorize"] = "html403"
        with self.assertRaises(ArceziaAPIError):
            az.authorize("bad-token")
        self.assertNotIn("user", az._pending_tokens)
        _MODE.pop("/v1/authorize")
        cert = _call_verify(az)                 # no re-raise on the next call
        self.assertEqual(cert.verdict, "ALLOW")

    def test_an_unattached_approval_never_becomes_an_allow_by_default(self):
        az = self._client("fail_closed")
        az.start_session()
        _MODE["/v1/authorize"] = "500"
        with self.assertRaises(ArceziaUnavailableError):
            az.authorize("user-jwt-abc")
        with self.assertRaises(ArceziaUnavailableError):
            _call_verify(az)                    # the pending flush fails again

    def test_a_new_session_re_attaches_every_known_approval(self):
        az = self._client()
        az.authorize("user-jwt").authorize_production("prod-jwt")
        az.start_session()
        az._session_id = None                   # force a fresh session
        _RECORDED.clear()
        az.start_session()
        types = sorted(b["token_type"] for _, p, b in _RECORDED
                       if p == "/v1/authorize")
        self.assertEqual(types, ["production", "user"],
                         "a new session ran without the approvals already given")


# ── 6. An envelope's denials survive an implicit session retry ───────────────

class TestEnvelopeSurvivesSessionRetry(_Loopback):
    """An envelope axis set False is a DENIAL. Losing it widens authority.

    start_session() can fail; the next verify() opens the session implicitly.
    That retry used to send no envelope at all — so an outage between the two
    calls quietly removed every denial the operator had declared. Absence
    converted to a permissive value, which is the risk class of this change.
    """

    ENVELOPE = {
        "allowed_domains": ["payment_ops"],
        "structural_authority": {"outbound": False, "irreversible": True},
    }

    def test_the_retry_carries_the_envelope_the_failed_call_declared(self):
        az = self._client("review", url=self.url)
        _MODE["/v1/session"] = "500"
        body = az.start_session(capability_envelope=self.ENVELOPE)
        self.assertTrue(body["_synthetic"])

        _MODE.pop("/v1/session")
        _RECORDED.clear()
        _call_verify(az)
        sessions = [b for _, p, b in _RECORDED if p == "/v1/session"]
        self.assertEqual(len(sessions), 1, sessions)
        self.assertEqual(sessions[0].get("capability_envelope"), self.ENVELOPE,
                         "the retry opened a session with no envelope — the "
                         "operator's denials were dropped during an outage")

    def test_an_invalid_envelope_is_not_remembered(self):
        az = self._client()
        with self.assertRaises(ValueError):
            az.start_session(capability_envelope={
                "structural_authority": {"mutation": True}})
        self.assertIsNone(az._capability_envelope)


# ── 7. Backward compatibility ────────────────────────────────────────────────

class TestBackwardCompatibility(_Loopback):
    """A caller who never passed on_error sees identical verify() behaviour."""

    def test_default_is_fail_closed(self):
        az = Arcezia(api_key="ar_test_x", task="t", api_url=self.url)
        self.assertEqual(az._on_error, "fail_closed")

    def test_healthy_verify_is_unchanged(self):
        az = Arcezia(api_key="ar_test_x", task="t", api_url=self.url)
        cert = _call_verify(az)
        self.assertEqual((cert.verdict, cert.status), ("ALLOW", "ALLOWED"))
        self.assertEqual(cert.trust_score, 1.0)
        self.assertEqual(cert.signature, "sig")
        self.assertEqual(cert.credential, {"token": "c"})
        self.assertFalse(cert.degraded)

    def test_connection_refused_still_raises_unavailable(self):
        az = Arcezia(api_key="ar_test_x", task="t", api_url=self.dead_url,
                     max_retries=0)
        with self.assertRaises(ArceziaUnavailableError):
            _call_verify(az)

    def test_500_still_raises_unavailable(self):
        _MODE["*"] = "500"
        az = Arcezia(api_key="ar_test_x", task="t", api_url=self.url,
                     max_retries=0)
        with self.assertRaises(ArceziaUnavailableError):
            _call_verify(az)

    def test_a_4xx_still_raises_the_api_error_not_a_verdict(self):
        _MODE["*"] = "html403"
        az = Arcezia(api_key="ar_test_x", task="t", api_url=self.url,
                     max_retries=0)
        with self.assertRaises(ArceziaAPIError):
            _call_verify(az)

    def test_on_transport_failure_still_exists_and_still_obeys_the_policy(self):
        """Kept for anyone who reached into it directly."""
        az = Arcezia(api_key="ar_test_x", task="t", api_url=self.url)
        with self.assertRaises(ArceziaUnavailableError):
            az._on_transport_failure(ConnectionError("boom"))
        open_az = Arcezia(api_key="ar_test_x", task="t", api_url=self.url,
                          on_error="fail_open")
        self.assertEqual(
            open_az._on_transport_failure(ConnectionError("boom")).verdict, "ALLOW")

    def test_timeout_and_max_retries_now_reach_every_endpoint(self):
        """They were honoured by verify() alone; the rest used the defaults.

        A value the constructor accepts and four endpoints drop is a setting
        that works in the demo and not in production.
        """
        seen: list = []
        real_post = client_mod._post

        def spy(url, headers, body, **kw):
            seen.append((url.rsplit("/v1/", 1)[-1], kw.get("retries"),
                         kw.get("timeout")))
            return real_post(url, headers, body, **kw)

        client_mod._post = spy
        self.addCleanup(setattr, client_mod, "_post", real_post)
        az = Arcezia(api_key="ar_test_x", task="t", api_url=self.url,
                     max_retries=0, timeout=7.0)
        az.authorize("tok")
        _call_verify(az)
        _call_verify_chain(az)
        _call_verify_outcome(az)
        az.audit_subject(reference="r")
        for endpoint, retries, timeout in seen:
            with self.subTest(endpoint=endpoint):
                self.assertEqual(retries, 0)
                self.assertEqual(timeout, 7.0)
        self.assertEqual(
            sorted({e for e, _, _ in seen}),
            ["audit/subject", "authorize", "session", "verify", "verify_chain",
             "verify_outcome"])


# ── 8. The policy has one implementation ─────────────────────────────────────

class TestOnePolicyNotSeven(_Loopback):
    """Seven copies of a policy is seven chances to get one of them wrong.

    Asserted structurally: the decision between raising and degrading exists at
    exactly one place in the source, and every degraded value is reachable only
    through it.
    """

    def test_only_one_site_decides_between_raise_and_degrade(self):
        src = (ROOT / "arcezia" / "client.py").read_text()
        self.assertEqual(
            src.count('self._on_error == "fail_closed"'), 1,
            "the fail-closed decision is made in more than one place")
        self.assertEqual(
            src.count("def _apply_on_error"), 1)
        # _degraded_cert is the only ALLOW-producing constructor; it must be
        # reachable only from the degrade builders, never from a method body.
        self.assertEqual(src.count("self._degraded_cert("), 0)

    def test_every_network_method_routes_through_the_guard(self):
        import inspect
        src = inspect.getsource(Arcezia)
        for name in ("verify", "verify_chain", "verify_outcome", "usage",
                     "audit_subject"):
            with self.subTest(method=name):
                body = src.split(f"    def {name}(")[1].split("\n    def ")[0]
                self.assertIn("self._guarded(", body,
                              f"{name} does not consult the outage policy")


# ── 9. Integrations honour the policy they advertise ─────────────────────────

class TestIntegrationsHonourOnError(_Loopback):

    def test_dispatch_guard_forwards_on_error(self):
        from arcezia.integrations.openclaw import DispatchGuard
        for mode in ("fail_closed", "review", "fail_open"):
            with self.subTest(mode=mode):
                guard = DispatchGuard(api_key="ar_test_x", task="t",
                                      api_url=self.url, on_error=mode)
                self.assertEqual(guard.az._on_error, mode)

    def test_dispatch_guard_default_is_fail_closed(self):
        from arcezia.integrations.openclaw import DispatchGuard
        guard = DispatchGuard(api_key="ar_test_x", task="t", api_url=self.url)
        self.assertEqual(guard.az._on_error, "fail_closed")

    def test_on_error_with_a_conflicting_client_is_refused_not_ignored(self):
        from arcezia.integrations.openclaw import DispatchGuard
        az = self._client("fail_closed")
        with self.assertRaises(ValueError) as ctx:
            DispatchGuard(az, on_error="fail_open")
        self.assertIn("on_error", str(ctx.exception))

    def test_on_error_matching_an_existing_client_is_accepted(self):
        from arcezia.integrations.openclaw import DispatchGuard
        az = self._client("review")
        guard = DispatchGuard(az, on_error="review")
        self.assertIs(guard.az, az)

    def test_claude_code_hook_reads_on_error_from_the_environment(self):
        import os
        from arcezia.integrations import claude_code
        os.environ["ARCEZIA_API_KEY"] = "ar_test_x"
        os.environ["ARCEZIA_API_URL"] = self.url
        os.environ["ARCEZIA_ON_ERROR"] = "review"
        self.addCleanup(os.environ.pop, "ARCEZIA_ON_ERROR", None)
        self.addCleanup(os.environ.pop, "ARCEZIA_API_URL", None)
        self.addCleanup(os.environ.pop, "ARCEZIA_API_KEY", None)
        az = claude_code._default_verifier()
        self.assertEqual(az._on_error, "review")

    def test_every_integration_that_takes_on_error_forwards_it(self):
        """The audit, kept executable: any adapter that grows an on_error
        parameter must pass it on. Signature-level, so a new adapter that
        accepts and drops it fails here rather than in production."""
        import ast
        adapters = sorted((ROOT / "arcezia" / "integrations").glob("*.py"))
        accepting = []
        for path in adapters:
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                args = node.args
                names = [a.arg for a in args.args + args.kwonlyargs]
                if "on_error" not in names or path.name == "_common.py":
                    continue
                accepting.append((path.name, node.name))
                src = ast.get_source_segment(path.read_text(), node) or ""
                self.assertIn(
                    "on_error", src.split(":", 1)[1],
                    f"{path.name}:{node.name} accepts on_error and never uses it")
        self.assertTrue(accepting, "no adapter accepts on_error — audit stale")


if __name__ == "__main__":
    unittest.main()
