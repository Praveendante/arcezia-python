"""
The two wire fields added in 1.0.2, and the compatibility they must preserve.

`denied_authority_axes` and `unresolved` were already on the wire; the SDK read
neither, so an integrator could see them over raw HTTP and not through the
client. Both are additive, and the tests that matter most here are the ones
proving the client still works against a server that does not send them — an SDK
release must not require a matching server.
"""
from __future__ import annotations

import unittest

from arcezia.client import ArceziaCertificate, _parse_cert


def _wire(**extra) -> dict:
    body = {
        "verdict": "BLOCK",
        "status": "BLOCKED",
        "precondition_score": 1.0,
        "dc_score": 1.0,
        "trust_score": 0.6,
        "summary": "Blocked.",
        "violated": [],
        "missing": [],
        "fabrication_detected": False,
        "fabricated_constraints": [],
        "constraints": [],
        "signature": "abc",
    }
    body.update(extra)
    return body


class TestNewFieldsAreRead(unittest.TestCase):

    def test_denied_axes_parsed(self):
        cert = _parse_cert(_wire(denied_authority_axes=["irreversible", "outbound"]))
        self.assertEqual(cert.denied_authority_axes, ["irreversible", "outbound"])

    def test_unresolved_parsed(self):
        cert = _parse_cert(_wire(unresolved=["user_explicit_authorization"]))
        self.assertEqual(cert.unresolved, ["user_explicit_authorization"])

    def test_unresolved_can_be_populated_while_missing_is_empty(self):
        """The case the guide documents: `missing` lists only what the caller can
        act on, so it is legitimately empty on a verdict that is still holding
        facts. Before 1.0.2 that left an SDK user with nothing to read."""
        cert = _parse_cert(_wire(missing=[], unresolved=["cascade_effects_verified"]))
        self.assertEqual(cert.missing, [])
        self.assertTrue(cert.unresolved)


class TestOlderServersStillWork(unittest.TestCase):
    """An SDK release must not require a server that sends the new fields."""

    def test_absent_fields_default_to_empty(self):
        cert = _parse_cert(_wire())          # no new keys at all
        self.assertEqual(cert.denied_authority_axes, [])
        self.assertEqual(cert.unresolved, [])

    def test_verdict_still_parses_without_them(self):
        cert = _parse_cert(_wire())
        self.assertEqual(cert.verdict, "BLOCK")
        self.assertTrue(cert.block)

    def test_synthetic_certificates_construct(self):
        """Degraded certs are built directly, bypassing the wire parser. Adding
        required fields here would break every on_error='review'/'fail_open'
        path, so both must carry defaults."""
        cert = ArceziaCertificate(
            verdict="REVIEW", status="INSUFFICIENT_EVIDENCE",
            precondition_score=0.0, trust_score=0.0, summary="unreachable",
            violated=[], missing=["arcezia_reachable"], fabrication_detected=False,
            fabricated_constraints=[], constraints=[], signature="",
        )
        self.assertEqual(cert.denied_authority_axes, [])
        self.assertEqual(cert.unresolved, [])

    def test_defaults_are_not_shared_between_instances(self):
        """A mutable default declared without a factory would be shared by every
        certificate ever created."""
        a = _parse_cert(_wire())
        b = _parse_cert(_wire())
        a.denied_authority_axes.append("irreversible")
        self.assertEqual(b.denied_authority_axes, [])


if __name__ == "__main__":
    unittest.main()
