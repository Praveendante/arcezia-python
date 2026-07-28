"""
A cross-step block must close the gate, not just annotate it.

The server detects a dangerous SEQUENCE — a sensitive read earlier, an outbound
send now — sets `chain_status: SEMANTIC_BLOCK`, names the patterns, and withholds
the credential. The per-action verdict stays ALLOW, correctly: the action really
is unobjectionable on its own.

Until 1.0.3 the client read none of that, so `cert.allow` was True and the gate
this SDK's own README tells you to write —

    if not cert.allow:
        raise

— let a detected exfiltration through. The withheld credential was the only thing
standing in the way, and only for tools that require one.
"""
from __future__ import annotations

import unittest

from arcezia.client import ArceziaCertificate, _parse_cert


def _wire(**extra) -> dict:
    body = {
        "verdict": "ALLOW", "status": "ALLOWED",
        "precondition_score": 1.0, "trust_score": 0.8,
        "summary": "All required preconditions satisfied.",
        "violated": [], "missing": [], "constraints": [],
        "fabrication_detected": False, "fabricated_constraints": [],
        "signature": "sig",
    }
    body.update(extra)
    return body


_SEMANTIC = dict(
    chain_status="SEMANTIC_BLOCK",
    chain_patterns=[{"pattern_name": "structural_exfiltration"},
                    {"pattern_name": "pii_exfiltration_structural"}],
    credential=None,
)


class TestSemanticBlockClosesTheGate(unittest.TestCase):

    def test_allow_is_false_despite_an_ALLOW_verdict(self):
        cert = _parse_cert(_wire(**_SEMANTIC))
        self.assertEqual(cert.verdict, "ALLOW")
        self.assertFalse(cert.allow, "the documented `if not cert.allow` gate would let this run")

    def test_block_is_true(self):
        self.assertTrue(_parse_cert(_wire(**_SEMANTIC)).block)

    def test_review_is_not_true(self):
        """It is a refusal, not a hold — routing it to a human queue as REVIEW
        would misdescribe it."""
        self.assertFalse(_parse_cert(_wire(**_SEMANTIC)).review)

    def test_semantic_block_flag_and_patterns_exposed(self):
        cert = _parse_cert(_wire(**_SEMANTIC))
        self.assertTrue(cert.semantic_block)
        self.assertIn("structural_exfiltration", cert.chain_patterns)

    def test_patterns_survive_a_plain_string_shape(self):
        """Defensive: the wire sends dicts today, but a bare list of names must
        not crash a client in the field."""
        cert = _parse_cert(_wire(chain_status="SEMANTIC_BLOCK",
                                 chain_patterns=["structural_exfiltration"]))
        self.assertEqual(cert.chain_patterns, ["structural_exfiltration"])

    def test_str_says_why(self):
        self.assertIn("CROSS-STEP BLOCK", str(_parse_cert(_wire(**_SEMANTIC))))


class TestOrdinaryVerdictsAreUntouched(unittest.TestCase):
    """The change must not make anything else stricter."""

    def test_plain_allow_still_allows(self):
        cert = _parse_cert(_wire())
        self.assertTrue(cert.allow)
        self.assertFalse(cert.semantic_block)
        self.assertEqual(cert.chain_patterns, [])

    def test_plain_review_still_reviews(self):
        cert = _parse_cert(_wire(verdict="REVIEW", status="INSUFFICIENT_EVIDENCE"))
        self.assertTrue(cert.review)
        self.assertFalse(cert.allow)

    def test_absent_chain_fields_are_not_a_block(self):
        """Older servers send neither field. They must not read as a refusal."""
        cert = _parse_cert(_wire())
        self.assertIsNone(cert.chain_status)
        self.assertFalse(cert.block)

    def test_synthetic_certificates_construct(self):
        """Degraded certs bypass the wire parser — both fields need defaults."""
        cert = ArceziaCertificate(
            verdict="REVIEW", status="INSUFFICIENT_EVIDENCE", precondition_score=0.0,
            trust_score=0.0, summary="unreachable", violated=[],
            missing=["arcezia_reachable"], fabrication_detected=False,
            fabricated_constraints=[], constraints=[], signature="")
        self.assertIsNone(cert.chain_status)
        self.assertEqual(cert.chain_patterns, [])


if __name__ == "__main__":
    unittest.main()
