#!/usr/bin/env python3
"""
Tests for the data-subject reference and data-categories plumbing.

The reference is RECORD-ONLY (it never changes a verdict); these tests pin the
transport contract only: which request bodies carry it, that an explicit
per-call value beats the client-level one, that clearing works, and that
audit_subject posts the reference in the JSON body — never the URL.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from arcezia.client import Arcezia, _parse_cert  # noqa: E402


# ── Mock response helpers (same style as test_client.py) ──────────────────────

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


def _chain_resp() -> dict:
    return {
        "overall_verdict": "SAFE",
        "blocked_at": None,
        "steps": [],
        "final_state": {},
        "session_state_updated": False,
    }


def _outcome_resp() -> dict:
    return {
        "verdict": "ALLOW",
        "status": "OUTCOME_VERIFIED",
        "summary": "Outcome matches intent.",
        "violations": [],
        "warnings": [],
        "outcome_recorded": {},
        "signature": "mock_sig_outcome",
    }


def _make_post_side_effect(resp: dict):
    def side_effect(url: str, headers: dict, body: dict, **kwargs):
        if "/v1/session" in url:
            return 200, {"session_id": "test-session-001"}
        return 200, resp
    return side_effect


def _az(**kwargs) -> Arcezia:
    az = Arcezia(api_key="ar_test_xxx", task="test", **kwargs)
    az._session_id = "sess-123"
    return az


# ── Client-level reference on every endpoint ──────────────────────────────────

class TestClientLevelSubject(unittest.TestCase):
    """The client-level reference rides along on verify / verify_chain /
    verify_outcome while set."""

    @patch("arcezia.client._post")
    def test_verify_body_carries_client_level_reference(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_allow_resp())
        az = _az(data_subject_reference="customer-42")
        az.verify(action_type="execute_sql", action_description="SELECT 1")
        body = mock_post.call_args[0][2]
        self.assertEqual(body["data_subject_reference"], "customer-42")

    @patch("arcezia.client._post")
    def test_verify_chain_body_carries_client_level_reference(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_chain_resp())
        az = _az(data_subject_reference="customer-42")
        az.verify_chain({"steps": []})
        body = mock_post.call_args[0][2]
        self.assertEqual(body["data_subject_reference"], "customer-42")

    @patch("arcezia.client._post")
    def test_verify_outcome_body_carries_client_level_reference(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_outcome_resp())
        az = _az(data_subject_reference="customer-42")
        az.verify_outcome(
            action_type="execute_sql",
            action_description="SELECT 1",
            outcome={"rows_affected": 1},
        )
        body = mock_post.call_args[0][2]
        self.assertEqual(body["data_subject_reference"], "customer-42")

    @patch("arcezia.client._post")
    def test_no_reference_means_no_key_in_any_body(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_allow_resp())
        az = _az()
        az.verify(action_type="x", action_description="y")
        self.assertNotIn("data_subject_reference", mock_post.call_args[0][2])

    @patch("arcezia.client._post")
    def test_set_data_subject_applies_to_subsequent_calls(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_allow_resp())
        az = _az()
        az.set_data_subject("customer-7")
        az.verify(action_type="x", action_description="y")
        body = mock_post.call_args[0][2]
        self.assertEqual(body["data_subject_reference"], "customer-7")

    @patch("arcezia.client._post")
    def test_set_data_subject_none_clears(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_allow_resp())
        az = _az(data_subject_reference="customer-42")
        az.set_data_subject(None)
        az.verify(action_type="x", action_description="y")
        self.assertNotIn("data_subject_reference", mock_post.call_args[0][2])


# ── Per-call override ─────────────────────────────────────────────────────────

class TestPerCallOverride(unittest.TestCase):
    """An explicit per-call reference beats the client-level one — same rule
    on all three endpoints (one shared helper)."""

    @patch("arcezia.client._post")
    def test_verify_per_call_wins(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_allow_resp())
        az = _az(data_subject_reference="client-level")
        az.verify(action_type="x", action_description="y",
                  data_subject_reference="per-call")
        body = mock_post.call_args[0][2]
        self.assertEqual(body["data_subject_reference"], "per-call")

    @patch("arcezia.client._post")
    def test_verify_chain_per_call_wins(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_chain_resp())
        az = _az(data_subject_reference="client-level")
        az.verify_chain({"steps": []}, data_subject_reference="per-call")
        body = mock_post.call_args[0][2]
        self.assertEqual(body["data_subject_reference"], "per-call")

    @patch("arcezia.client._post")
    def test_verify_outcome_per_call_wins(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_outcome_resp())
        az = _az(data_subject_reference="client-level")
        az.verify_outcome(
            action_type="x", action_description="y",
            outcome={"rows_affected": 1},
            data_subject_reference="per-call",
        )
        body = mock_post.call_args[0][2]
        self.assertEqual(body["data_subject_reference"], "per-call")

    @patch("arcezia.client._post")
    def test_override_does_not_mutate_client_level_value(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_allow_resp())
        az = _az(data_subject_reference="client-level")
        az.verify(action_type="x", action_description="y",
                  data_subject_reference="per-call")
        az.verify(action_type="x", action_description="y")
        body = mock_post.call_args[0][2]
        self.assertEqual(body["data_subject_reference"], "client-level")


# ── data_categories ───────────────────────────────────────────────────────────

class TestDataCategories(unittest.TestCase):

    @patch("arcezia.client._post")
    def test_verify_passes_data_categories(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_allow_resp())
        az = _az()
        az.verify(action_type="x", action_description="y",
                  data_categories=["health", "contact"])
        body = mock_post.call_args[0][2]
        self.assertEqual(body["data_categories"], ["health", "contact"])

    @patch("arcezia.client._post")
    def test_verify_omits_data_categories_when_absent(self, mock_post):
        mock_post.side_effect = _make_post_side_effect(_allow_resp())
        az = _az()
        az.verify(action_type="x", action_description="y")
        self.assertNotIn("data_categories", mock_post.call_args[0][2])

    def test_cert_parses_data_categories(self):
        resp = _allow_resp()
        resp["data_categories"] = {"resolved": ["health"]}
        cert = _parse_cert(resp)
        self.assertEqual(cert.data_categories, {"resolved": ["health"]})

    def test_cert_data_categories_defaults_to_none(self):
        cert = _parse_cert(_allow_resp())
        self.assertIsNone(cert.data_categories)


# ── audit_subject ─────────────────────────────────────────────────────────────

class TestAuditSubject(unittest.TestCase):
    """The GDPR Art 15 / DPDP §11 lookup: reference travels in the JSON body,
    never the URL."""

    @patch("arcezia.client._post")
    def test_posts_to_audit_subject_path(self, mock_post):
        mock_post.return_value = (200, {"decisions": [], "count": 0})
        az = _az()
        result = az.audit_subject("customer-42")
        url = mock_post.call_args[0][0]
        self.assertTrue(url.endswith("/v1/audit/subject"))
        self.assertEqual(result, {"decisions": [], "count": 0})

    @patch("arcezia.client._post")
    def test_reference_in_json_body_never_in_url(self, mock_post):
        mock_post.return_value = (200, {"decisions": []})
        az = _az()
        az.audit_subject("customer-42")
        url = mock_post.call_args[0][0]
        body = mock_post.call_args[0][2]
        self.assertNotIn("customer-42", url)
        self.assertEqual(body["reference"], "customer-42")

    @patch("arcezia.client._post")
    def test_default_limit_and_optional_dates(self, mock_post):
        mock_post.return_value = (200, {"decisions": []})
        az = _az()
        az.audit_subject("customer-42")
        body = mock_post.call_args[0][2]
        self.assertEqual(body["limit"], 500)
        self.assertNotIn("date_from", body)
        self.assertNotIn("date_to", body)

    @patch("arcezia.client._post")
    def test_date_bounds_and_limit_forwarded(self, mock_post):
        mock_post.return_value = (200, {"decisions": []})
        az = _az()
        az.audit_subject("customer-42", date_from="2026-01-01",
                         date_to="2026-06-30", limit=50)
        body = mock_post.call_args[0][2]
        self.assertEqual(body["date_from"], "2026-01-01")
        self.assertEqual(body["date_to"], "2026-06-30")
        self.assertEqual(body["limit"], 50)


# ── coerce_az plumbing ────────────────────────────────────────────────────────

class TestCoerceAzSubject(unittest.TestCase):

    def test_sets_subject_on_existing_client(self):
        from arcezia.integrations._common import coerce_az
        az = MagicMock(spec=Arcezia)
        result = coerce_az(az, data_subject_reference="customer-42")
        self.assertIs(result, az)
        az.set_data_subject.assert_called_once_with("customer-42")

    def test_leaves_existing_client_alone_when_not_given(self):
        from arcezia.integrations._common import coerce_az
        az = MagicMock(spec=Arcezia)
        coerce_az(az)
        az.set_data_subject.assert_not_called()

    def test_sets_subject_on_newly_built_client(self):
        from arcezia.integrations._common import coerce_az
        client = coerce_az(api_key="ar_test_xxx", task="t",
                           data_subject_reference="customer-42")
        self.assertEqual(client._data_subject_reference, "customer-42")


# ── universal guard per-call pass-through ─────────────────────────────────────

class TestUniversalGuardSubject(unittest.TestCase):

    def _allow_cert(self):
        return _parse_cert(_allow_resp())

    def test_guard_callable_passes_reference_per_call(self):
        from arcezia.integrations.universal import guard_callable
        az = MagicMock(spec=Arcezia)
        az.verify.return_value = self._allow_cert()
        safe = guard_callable(lambda x: x, az, domain="database_ops",
                              data_subject_reference="customer-42")
        safe("SELECT 1")
        kwargs = az.verify.call_args.kwargs
        self.assertEqual(kwargs["data_subject_reference"], "customer-42")

    def test_guard_callable_omits_kwarg_when_unset(self):
        """Compatibility: an unset reference must not even appear as a kwarg,
        so user-supplied clients with a strict verify() signature keep working."""
        from arcezia.integrations.universal import guard_callable
        az = MagicMock(spec=Arcezia)
        az.verify.return_value = self._allow_cert()
        safe = guard_callable(lambda x: x, az, domain="database_ops")
        safe("SELECT 1")
        self.assertNotIn("data_subject_reference", az.verify.call_args.kwargs)


# ── n8n body builder ──────────────────────────────────────────────────────────

class TestN8nSubject(unittest.TestCase):

    def test_build_verify_body_includes_reference(self):
        from arcezia.integrations.n8n import build_verify_body
        body = build_verify_body(
            task="t", action_type="a", action_description="d",
            data_subject_reference="customer-42",
            data_categories=["contact"],
        )
        self.assertEqual(body["data_subject_reference"], "customer-42")
        self.assertEqual(body["data_categories"], ["contact"])

    def test_build_verify_body_omits_when_absent(self):
        from arcezia.integrations.n8n import build_verify_body
        body = build_verify_body(task="t", action_type="a", action_description="d")
        self.assertNotIn("data_subject_reference", body)
        self.assertNotIn("data_categories", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
