#!/usr/bin/env python3
"""
Tests for the Arcezia HTTP client SDK (client/arcezia/client.py).

Covers: SSRF guard, _parse_cert, certificate properties,
verify() flow, error handling, @az.gate(), verify_chain(),
usage(), and authorize().
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from arcezia.client import (  # noqa: E402
    Arcezia,
    ArceziaCertificate,
    ArceziaConstraintDetail,
    ArceziaBlockError,
    ArceziaReviewError,
    ArceziaUpgradeRequired,
    ArceziaAPIError,
    ArceziaRateLimitError,
    ArceziaUnavailableError,
    _parse_cert,
)


# ── Mock response helpers ──────────────────────────────────────────────────────

def _allow_resp() -> dict:
    return {
        "verdict": "ALLOW",
        "status": "ALLOWED",
        "precondition_score": 1.0,
        "trust_score": 1.0,
        "summary": "All constraints satisfied.",
        "violated": [],
        "missing": [],
        "fabrication_detected": False,
        "fabricated_constraints": [],
        "constraints": [],
        "signature": "mock_sig_allow",
        "credential": {"token": "arc_cred_test", "expires_at": 9_999_999_999},
    }


def _block_resp() -> dict:
    return {
        "verdict": "BLOCK",
        "status": "BLOCKED",
        "precondition_score": 0.0,
        "trust_score": 0.5,
        "summary": "Required constraint violated.",
        "violated": ["action_within_task_scope"],
        "missing": [],
        "fabrication_detected": False,
        "fabricated_constraints": [],
        "constraints": [],
        "signature": "mock_sig_block",
        "credential": None,
    }


def _review_resp() -> dict:
    return {
        "verdict": "REVIEW",
        "status": "INSUFFICIENT_EVIDENCE",
        "precondition_score": 0.5,
        "trust_score": 0.7,
        "summary": "Missing evidence.",
        "violated": [],
        "missing": ["user_explicit_authorization"],
        "fabrication_detected": False,
        "fabricated_constraints": [],
        "constraints": [],
        "signature": "mock_sig_review",
        "credential": None,
    }


def _session_resp() -> dict:
    return {"session_id": "test-session-001"}


def _make_post_side_effect(verify_resp: dict):
    """Side-effect for _post: session call returns session; any other call returns verify_resp."""
    def side_effect(url: str, headers: dict, body: dict, **kwargs):
        if "/v1/session" in url:
            return 200, _session_resp()
        return 200, verify_resp
    return side_effect


# ── SSRF guard ────────────────────────────────────────────────────────────────

class TestSsrfGuard(unittest.TestCase):
    """Live keys cannot be aimed at localhost (SSRF protection)."""

    def test_live_key_localhost_raises(self):
        with self.assertRaises(ValueError) as ctx:
            Arcezia(api_key="ar_live_somekey", api_url="http://localhost:8000")
        self.assertIn("localhost", str(ctx.exception))

    def test_live_key_127_0_0_1_raises(self):
        with self.assertRaises(ValueError):
            Arcezia(api_key="ar_live_somekey", api_url="http://127.0.0.1:8000")

    def test_live_key_loopback_ipv6_raises(self):
        # Proper IPv6 URL syntax: http://[::1]:8000
        with self.assertRaises(ValueError):
            Arcezia(api_key="ar_live_somekey", api_url="http://[::1]:8000")

    def test_test_key_localhost_is_allowed(self):
        """ar_test_ keys may point to localhost for local development."""
        az = Arcezia(api_key="ar_test_localdev", api_url="http://localhost:8000")
        self.assertIsNotNone(az)

    def test_no_api_key_raises(self):
        with self.assertRaises(RuntimeError) as ctx:
            Arcezia()
        self.assertIn("API key", str(ctx.exception))

    def test_invalid_scheme_raises(self):
        with self.assertRaises(ValueError) as ctx:
            Arcezia(api_key="ar_test_x", api_url="ftp://example.com")
        self.assertIn("http or https", str(ctx.exception))


# ── _parse_cert ───────────────────────────────────────────────────────────────

class TestParseCert(unittest.TestCase):
    """_parse_cert correctly maps all response fields to ArceziaCertificate."""

    def test_allow_cert_parsed(self):
        cert = _parse_cert(_allow_resp())
        self.assertEqual(cert.verdict, "ALLOW")
        self.assertEqual(cert.status, "ALLOWED")
        self.assertEqual(cert.precondition_score, 1.0)
        self.assertEqual(cert.trust_score, 1.0)
        self.assertFalse(cert.fabrication_detected)
        self.assertEqual(cert.violated, [])
        self.assertEqual(cert.missing, [])
        self.assertIsNotNone(cert.credential)

    def test_block_cert_parsed(self):
        cert = _parse_cert(_block_resp())
        self.assertEqual(cert.verdict, "BLOCK")
        self.assertIn("action_within_task_scope", cert.violated)
        self.assertIsNone(cert.credential)

    def test_constraint_details_parsed(self):
        resp = _allow_resp()
        resp["constraints"] = [
            {
                "name": "action_within_task_scope",
                "value": True,
                "quality": "GROUNDED",
                "detail": "scope check: ok",
            }
        ]
        cert = _parse_cert(resp)
        self.assertEqual(len(cert.constraints), 1)
        self.assertEqual(cert.constraints[0].name, "action_within_task_scope")
        self.assertEqual(cert.constraints[0].quality, "GROUNDED")
        self.assertTrue(cert.constraints[0].value)

    def test_missing_optional_fields_use_defaults(self):
        """_parse_cert must not crash on a minimal API response."""
        minimal = {
            "verdict": "ALLOW",
            "status": "ALLOWED",
            "precondition_score": 1.0,
            "trust_score": 1.0,
            "summary": "ok",
        }
        cert = _parse_cert(minimal)
        self.assertEqual(cert.violated, [])
        self.assertEqual(cert.missing, [])
        self.assertFalse(cert.fabrication_detected)
        self.assertEqual(cert.signature, "")
        self.assertIsNone(cert.credential)


# ── Certificate properties ────────────────────────────────────────────────────

class TestCertificateProperties(unittest.TestCase):
    """ArceziaCertificate.allow / block / review boolean properties."""

    def test_allow_property_true_on_allow(self):
        cert = _parse_cert(_allow_resp())
        self.assertTrue(cert.allow)
        self.assertFalse(cert.block)
        self.assertFalse(cert.review)

    def test_block_property_true_on_block(self):
        cert = _parse_cert(_block_resp())
        self.assertTrue(cert.block)
        self.assertFalse(cert.allow)
        self.assertFalse(cert.review)

    def test_review_property_true_on_review(self):
        cert = _parse_cert(_review_resp())
        self.assertTrue(cert.review)
        self.assertFalse(cert.allow)
        self.assertFalse(cert.block)

    def test_allow_false_when_fabrication_detected(self):
        """Fabrication overrides even an otherwise-ALLOW verdict."""
        resp = _allow_resp()
        resp["fabrication_detected"] = True
        resp["fabricated_constraints"] = ["user_explicit_authorization"]
        cert = _parse_cert(resp)
        # verdict is ALLOW but allow property must be False
        self.assertEqual(cert.verdict, "ALLOW")
        self.assertFalse(cert.allow)
        self.assertTrue(cert.block)

    def test_block_true_when_fabrication_on_allow(self):
        resp = _allow_resp()
        resp["fabrication_detected"] = True
        cert = _parse_cert(resp)
        self.assertTrue(cert.block)


# ── verify() flow ─────────────────────────────────────────────────────────────

class TestVerifyFlow(unittest.TestCase):
    """Session auto-creation, correct request shape, returns ArceziaCertificate."""

    @patch("arcezia.client._post")
    def test_verify_auto_starts_session(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_allow_resp())
        az = Arcezia(api_key="ar_test_xxx", task="clean up test records")
        cert = az.verify(
            action_type="execute_sql",
            action_description="SELECT 1",
            domain="database_ops",
        )
        # 2 POSTs: /v1/session then /v1/verify
        self.assertEqual(mock_post.call_count, 2)
        self.assertEqual(cert.verdict, "ALLOW")
        self.assertIsInstance(cert, ArceziaCertificate)

    @patch("arcezia.client._post")
    def test_verify_with_existing_session_skips_session_call(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_allow_resp())
        az = Arcezia(api_key="ar_test_xxx", task="test")
        az._session_id = "existing-session-123"  # pre-set — skip creation
        az.verify(action_type="read_file", action_description="read /tmp/f", domain="filesystem_ops")
        # Only 1 POST: /v1/verify
        self.assertEqual(mock_post.call_count, 1)

    @patch("arcezia.client._post")
    def test_verify_stores_session_id(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_allow_resp())
        az = Arcezia(api_key="ar_test_xxx", task="test")
        self.assertIsNone(az._session_id)
        az.verify(action_type="x", action_description="y")
        self.assertEqual(az._session_id, "test-session-001")

    @patch("arcezia.client._post")
    def test_verify_passes_agent_evidence(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_allow_resp())
        az = Arcezia(api_key="ar_test_xxx", task="test")
        az._session_id = "sess-123"
        az.verify(
            action_type="execute_sql",
            action_description="SELECT 1",
            agent_evidence={"action_within_task_scope": True},
        )
        # Check that /v1/verify body included agent_evidence
        verify_call_args = mock_post.call_args
        body = verify_call_args[0][2]
        self.assertIn("agent_evidence", body)
        self.assertTrue(body["agent_evidence"]["action_within_task_scope"])


# ── Error handling ────────────────────────────────────────────────────────────

class TestErrorHandling(unittest.TestCase):
    """HTTP error codes map to the correct exception types."""

    def _az(self):
        az = Arcezia(api_key="ar_test_xxx", task="test")
        az._session_id = "sess"
        return az

    @patch("arcezia.client._post")
    def test_402_raises_upgrade_required(self, mock_post):
        mock_post.return_value = (402, {
            "detail": {
                "message": "Upgrade required",
                "upgrade_url": "https://arcezia.com/billing",
            }
        })
        with self.assertRaises(ArceziaUpgradeRequired) as ctx:
            self._az().verify(action_type="x", action_description="y", domain="payment_ops")
        self.assertIn("arcezia.com/billing", ctx.exception.upgrade_url)

    @patch("arcezia.client._post")
    def test_429_raises_rate_limit_error(self, mock_post):
        mock_post.return_value = (429, {"detail": {"message": "Monthly limit exceeded"}})
        # ArceziaRateLimitError is a RuntimeError subclass; the message is surfaced.
        with self.assertRaises(ArceziaRateLimitError) as ctx:
            self._az().verify(action_type="x", action_description="y")
        self.assertIn("Monthly limit exceeded", str(ctx.exception))

    @patch("arcezia.client._post")
    def test_429_includes_retry_after_for_per_minute_window(self, mock_post):
        mock_post.return_value = (429, {"detail": {"message": "slow down", "window": "1m"}})
        with self.assertRaises(ArceziaRateLimitError) as ctx:
            self._az().verify(action_type="x", action_description="y")
        self.assertEqual(ctx.exception.retry_after, 60)

    @patch("arcezia.client._post")
    def test_401_raises_runtime_error_with_invalid_key_message(self, mock_post):
        mock_post.return_value = (401, {"detail": "Invalid API key"})
        with self.assertRaises(RuntimeError) as ctx:
            self._az().verify(action_type="x", action_description="y")
        self.assertIn("Invalid API key", str(ctx.exception))

    @patch("arcezia.client._post")
    def test_500_fail_closed_raises_unavailable(self, mock_post):
        # Default fail-closed: a 5xx (after retries) blocks the action — it is
        # never silently allowed because safety could not be verified.
        mock_post.return_value = (500, {"detail": "Internal server error"})
        with self.assertRaises(ArceziaUnavailableError):
            self._az().verify(action_type="x", action_description="y")

    @patch("arcezia.client._post")
    def test_500_fail_open_returns_degraded_allow(self, mock_post):
        # fail_open is a single deliberate flag: the old ARCEZIA_ALLOW_FAIL_OPEN
        # double-gate was removed on purpose (GTM finding F6) because it blocked
        # local experimentation. Constructing with on_error="fail_open" and no
        # env var is therefore the supported path — asserted here so the removed
        # gate is not mistaken for a safeguard that still exists.
        mock_post.return_value = (500, {"detail": "Internal server error"})
        os.environ.pop("ARCEZIA_ALLOW_FAIL_OPEN", None)
        az = Arcezia(api_key="ar_test_xxx", task="test", on_error="fail_open", max_retries=0)
        az._session_id = "sess"
        cert = az.verify(action_type="x", action_description="y")
        assert cert.verdict == "ALLOW"
        assert cert.signature == ""           # synthetic — not a signed verdict
        # The safety net that DOES exist: a synthetic verdict is always degraded
        # and never carries an executable credential.
        assert cert.degraded is True
        assert cert.credential is None

    @patch("arcezia.client._post")
    def test_500_review_mode_returns_degraded_review(self, mock_post):
        mock_post.return_value = (500, {"detail": "Internal server error"})
        az = Arcezia(api_key="ar_test_xxx", task="test", on_error="review", max_retries=0)
        az._session_id = "sess"
        cert = az.verify(action_type="x", action_description="y")
        assert cert.verdict == "REVIEW"

    @patch("arcezia.client._once_post")
    def test_transient_5xx_is_retried_then_succeeds(self, mock_once):
        # Patch the single-shot so the real retry loop runs: 503 then 200.
        mock_once.side_effect = [(503, {"detail": "warming up"}), (200, _allow_resp())]
        cert = self._az().verify(action_type="x", action_description="y")
        self.assertEqual(cert.verdict, "ALLOW")
        self.assertEqual(mock_once.call_count, 2)   # retried exactly once

    @patch("arcezia.client._once_post")
    def test_4xx_is_not_retried(self, mock_once):
        # Deterministic client errors must not be retried.
        mock_once.return_value = (402, {"detail": {"message": "upgrade", "upgrade_url": "u"}})
        with self.assertRaises(ArceziaUpgradeRequired):
            self._az().verify(action_type="x", action_description="y", domain="payment_ops")
        self.assertEqual(mock_once.call_count, 1)

    @patch("arcezia.client._post")
    def test_upgrade_required_has_upgrade_url(self, mock_post):
        mock_post.return_value = (402, {
            "detail": {
                "message": "Need team tier",
                "upgrade_url": "https://arcezia.com/billing",
            }
        })
        exc = None
        try:
            self._az().verify(action_type="x", action_description="y")
        except ArceziaUpgradeRequired as e:
            exc = e
        self.assertIsNotNone(exc)
        self.assertIn("arcezia.com", exc.upgrade_url)


# ── @az.gate() ────────────────────────────────────────────────────────────────

class TestGateDecorator(unittest.TestCase):
    """@az.gate() calls function on ALLOW, raises ArceziaBlockError on BLOCK/REVIEW."""

    @patch("arcezia.client._post")
    def test_gate_allow_calls_function(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_allow_resp())
        az = Arcezia(api_key="ar_test_xxx", task="test")
        called = []

        @az.gate(domain="database_ops", action_type="execute_sql")
        def run_query(sql: str):
            called.append(sql)
            return "executed"

        result = run_query("SELECT 1")
        self.assertEqual(result, "executed")
        self.assertIn("SELECT 1", called)

    @patch("arcezia.client._post")
    def test_gate_block_raises_arcezia_block_error(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_block_resp())
        az = Arcezia(api_key="ar_test_xxx", task="test")

        @az.gate(domain="database_ops", action_type="execute_sql")
        def drop_table(sql: str):
            return "must not reach"

        with self.assertRaises(ArceziaBlockError) as ctx:
            drop_table("DROP TABLE users")
        self.assertIsInstance(ctx.exception.cert, ArceziaCertificate)
        self.assertTrue(ctx.exception.cert.block)

    @patch("arcezia.client._post")
    def test_gate_review_raises_review_error(self, mock_post):
        """REVIEW means human confirmation required — gate must NOT run the function."""
        mock_post.side_effect = _make_post_side_effect(_review_resp())
        az = Arcezia(api_key="ar_test_xxx", task="test")
        called = []

        @az.gate(domain="database_ops")
        def update_role(sql: str):
            called.append(sql)
            return "called"

        with self.assertRaises(ArceziaReviewError):
            update_role("UPDATE users SET role='admin'")
        self.assertEqual(called, [])  # function never executed

    @patch("arcezia.client._post")
    def test_gate_review_passthrough_when_disabled(self, mock_post):
        """block_on_review=False restores the legacy behaviour: REVIEW runs."""
        mock_post.side_effect = _make_post_side_effect(_review_resp())
        az = Arcezia(api_key="ar_test_xxx", task="test")

        @az.gate(domain="database_ops", block_on_review=False)
        def update_role(sql: str):
            return "called"

        self.assertEqual(update_role("UPDATE users SET role='admin'"), "called")

    @patch("arcezia.client._post")
    def test_gate_block_does_not_invoke_wrapped_function(self, mock_post):
        """Raise-vs-return invariant: BLOCK must raise, never invoke the function."""
        mock_post.side_effect = _make_post_side_effect(_block_resp())
        az = Arcezia(api_key="ar_test_xxx", task="test")
        side_effects = []

        @az.gate(domain="database_ops")
        def dangerous(x):
            side_effects.append(x)

        try:
            dangerous("DROP TABLE secrets")
        except ArceziaBlockError:
            pass

        self.assertEqual(side_effects, [], "function must not be called on BLOCK")

    @patch("arcezia.client._post")
    def test_gate_uses_function_name_as_default_action_type(self, mock_post):
        """When action_type is not given to @gate, it defaults to the function name."""
        mock_post.side_effect = _make_post_side_effect(_allow_resp())
        az = Arcezia(api_key="ar_test_xxx", task="test")
        az._session_id = "sess"

        @az.gate(domain="database_ops")
        def my_custom_action(x):
            return x

        my_custom_action("arg")
        verify_body = mock_post.call_args[0][2]
        self.assertEqual(verify_body["action_type"], "my_custom_action")


# ── verify_chain() ────────────────────────────────────────────────────────────

class TestVerifyChain(unittest.TestCase):
    """verify_chain() sends the correct request shape."""

    @patch("arcezia.client._post")
    def test_verify_chain_sends_chain_manifest(self, mock_post):
        def side_effect(url, headers, body):
            if "/v1/session" in url:
                return 200, _session_resp()
            return 200, {
                "overall_verdict": "SAFE",
                "blocked_at": None,
                "steps": [],
                "final_state": {},
                "session_state_updated": False,
            }
        mock_post.side_effect = side_effect

        az = Arcezia(api_key="ar_test_xxx", task="test")
        manifest = {"task": "test", "steps": [{"id": "s1", "action_type": "read_file"}]}
        result = az.verify_chain(manifest, stop_on_block=True)

        self.assertEqual(result["overall_verdict"], "SAFE")
        verify_body = mock_post.call_args[0][2]
        self.assertIn("chain_manifest", verify_body)
        self.assertEqual(verify_body["chain_manifest"], manifest)
        self.assertTrue(verify_body["stop_on_block"])

    @patch("arcezia.client._post")
    def test_verify_chain_includes_session_id(self, mock_post):
        mock_post.side_effect = lambda url, h, b: (
            (200, _session_resp()) if "/v1/session" in url
            else (200, {"overall_verdict": "SAFE", "blocked_at": None, "steps": [], "final_state": {}, "session_state_updated": False})
        )
        az = Arcezia(api_key="ar_test_xxx", task="test")
        az.verify_chain({"task": "t", "steps": []})
        body = mock_post.call_args[0][2]
        self.assertIn("session_id", body)


# ── usage() ───────────────────────────────────────────────────────────────────

class TestUsage(unittest.TestCase):
    """usage() makes a GET to /v1/usage and returns the body."""

    @patch("arcezia.client._get")
    def test_usage_returns_stats(self, mock_get):
        mock_get.return_value = (200, {
            "verifications_this_month": 42,
            "limit": 1000,
            "tier": "free",
            "trust_score_avg": 0.95,
            "block_rate": 0.05,
            "fabrication_attempts": 0,
        })
        az = Arcezia(api_key="ar_test_xxx", task="test")
        result = az.usage()
        self.assertEqual(result["verifications_this_month"], 42)
        self.assertEqual(result["tier"], "free")

    @patch("arcezia.client._get")
    def test_usage_calls_v1_usage_endpoint(self, mock_get):
        mock_get.return_value = (200, {"verifications_this_month": 0})
        az = Arcezia(api_key="ar_test_xxx", task="test", api_url="https://api.arcezia.com")
        az.usage()
        called_url = mock_get.call_args[0][0]
        self.assertIn("/v1/usage", called_url)

    @patch("arcezia.client._get")
    def test_usage_401_raises_runtime_error(self, mock_get):
        mock_get.return_value = (401, {"detail": "Invalid API key"})
        az = Arcezia(api_key="ar_test_xxx", task="test")
        with self.assertRaises(RuntimeError):
            az.usage()


# ── authorize() ───────────────────────────────────────────────────────────────

class TestAuthorize(unittest.TestCase):
    """authorize() stores token and calls /v1/authorize when a session exists."""

    @patch("arcezia.client._post")
    def test_authorize_before_session_stores_token_only(self, mock_post):
        az = Arcezia(api_key="ar_test_xxx", task="test")
        az.authorize("my-user-jwt")
        mock_post.assert_not_called()
        self.assertEqual(az._user_token, "my-user-jwt")

    @patch("arcezia.client._post")
    def test_authorize_with_session_calls_attach_endpoint(self, mock_post):
        mock_post.return_value = (200, {"ok": True, "token_fingerprint": "abcd1234"})
        az = Arcezia(api_key="ar_test_xxx", task="test")
        az._session_id = "sess-xyz"
        az.authorize("my-jwt-token")
        called_url = mock_post.call_args[0][0]
        self.assertIn("/v1/authorize", called_url)

    @patch("arcezia.client._post")
    def test_authorize_returns_self_for_chaining(self, mock_post):
        az = Arcezia(api_key="ar_test_xxx", task="test")
        result = az.authorize("tok")
        self.assertIs(result, az)

    @patch("arcezia.client._post")
    def test_authorize_production_stores_prod_token(self, mock_post):
        az = Arcezia(api_key="ar_test_xxx", task="test")
        az.authorize_production("prod-jwt")
        mock_post.assert_not_called()
        self.assertEqual(az._prod_token, "prod-jwt")


if __name__ == "__main__":
    unittest.main(verbosity=2)
