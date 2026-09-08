"""`to_reach_allow` on the client surface.

`violated` and `missing` tell an integrator what went wrong. This field tells
them what would put it right: the checks nobody could make whose confirmation,
by the system entitled to answer each one, would turn the verdict into ALLOW.

Two things must hold and are easy to lose:

  * an older server that does not send the field must not break the client,
    and its silence must read as SILENCE — never as "no confirmation would
    change your verdict", which is a wrong answer with the shape of a right
    one;
  * every default in the defensive parse must be the least useful reading,
    never the most permissive.
"""
from __future__ import annotations

import unittest

from arcezia.client import _parse_cert


def _wire(**extra) -> dict:
    body = {
        "verdict": "REVIEW",
        "status": "REVIEW_REQUIRED",
        "precondition_score": 0.5,
        "dc_score": 0.5,
        "trust_score": 0.4,
        "summary": "Held for review.",
        "violated": [],
        "missing": ["fraud_indicators_absent"],
        "fabrication_detected": False,
        "fabricated_constraints": [],
        "constraints": [],
        "signature": "abc",
    }
    body.update(extra)
    return body


_ITEM = {
    "name": "fraud_indicators_absent",
    "value": True,
    "source": "system_probe",
    "channel": ("your own system — register a check named "
                "'fraud_indicators_absent' (hosted) or connect a check in "
                "the SDK configuration"),
    "minimised": True,
}


class TestItIsRead(unittest.TestCase):

    def test_the_list_and_the_flag_are_both_exposed(self):
        cert = _parse_cert(_wire(to_reach_allow=[_ITEM],
                                 to_reach_allow_reachable=True))
        self.assertEqual(cert.to_reach_allow, [_ITEM])
        self.assertIs(cert.to_reach_allow_reachable, True)
        self.assertTrue(cert.to_reach_allow_reported)

    def test_established_unreachability_is_False(self):
        cert = _parse_cert(_wire(verdict="BLOCK", to_reach_allow=[],
                                 to_reach_allow_reachable=False))
        self.assertEqual(cert.to_reach_allow, [])
        self.assertIs(cert.to_reach_allow_reachable, False)
        self.assertTrue(cert.to_reach_allow_reported)

    def test_an_allow_reports_nothing_to_reach(self):
        cert = _parse_cert(_wire(verdict="ALLOW", to_reach_allow=[],
                                 to_reach_allow_reachable=None))
        self.assertEqual(cert.to_reach_allow, [])
        self.assertIsNone(cert.to_reach_allow_reachable)


class TestAnOlderServer(unittest.TestCase):
    """An SDK release must not require a matching server."""

    def test_absence_does_not_raise(self):
        cert = _parse_cert(_wire())
        self.assertEqual(cert.to_reach_allow, [])
        self.assertIsNone(cert.to_reach_allow_reachable)
        self.assertEqual(cert.to_reach_allow_plain, [])

    def test_absence_is_silence_not_a_no(self):
        """`None` must not be readable as 'nothing would change this'."""
        cert = _parse_cert(_wire())
        self.assertFalse(cert.to_reach_allow_reported)
        self.assertIsNot(cert.to_reach_allow_reachable, False)

    def test_a_non_bool_flag_reads_as_not_reported(self):
        for junk in ("true", 1, [], {}):
            cert = _parse_cert(_wire(to_reach_allow_reachable=junk))
            self.assertIsNone(cert.to_reach_allow_reachable, junk)

    def test_a_non_list_field_reads_as_empty(self):
        for junk in ("nope", 3, {"a": 1}, None):
            cert = _parse_cert(_wire(to_reach_allow=junk))
            self.assertEqual(cert.to_reach_allow, [], junk)


class TestTheDefensiveParse(unittest.TestCase):

    def test_a_row_with_no_name_is_dropped(self):
        cert = _parse_cert(_wire(
            to_reach_allow=[{"value": True}, _ITEM, "not-a-dict", None],
            to_reach_allow_reachable=True))
        self.assertEqual([i["name"] for i in cert.to_reach_allow],
                         ["fraud_indicators_absent"])

    def test_a_missing_value_asks_for_a_confirmation_not_a_denial(self):
        cert = _parse_cert(_wire(
            to_reach_allow=[{"name": "x"}], to_reach_allow_reachable=True))
        self.assertIs(cert.to_reach_allow[0]["value"], True)

    def test_a_missing_channel_says_nothing_rather_than_inventing_one(self):
        cert = _parse_cert(_wire(
            to_reach_allow=[{"name": "x", "value": True}],
            to_reach_allow_reachable=True))
        self.assertEqual(cert.to_reach_allow[0]["channel"], "")
        self.assertEqual(cert.to_reach_allow[0]["source"], "")

    def test_minimised_defaults_to_true_only_when_unstated(self):
        cert = _parse_cert(_wire(
            to_reach_allow=[dict(_ITEM, minimised=False)],
            to_reach_allow_reachable=True))
        self.assertIs(cert.to_reach_allow[0]["minimised"], False)


class TestPlainSentences(unittest.TestCase):

    def test_one_sentence_per_check(self):
        cert = _parse_cert(_wire(to_reach_allow=[_ITEM],
                                 to_reach_allow_reachable=True))
        lines = cert.to_reach_allow_plain
        self.assertEqual(len(lines), 1)
        self.assertIn("fraud indicators absent", lines[0])
        self.assertIn("come back true", lines[0])
        self.assertIn("Who can answer", lines[0])
        self.assertIn("register a check named", lines[0])

    def test_a_risk_flag_says_it_must_come_back_false(self):
        cert = _parse_cert(_wire(
            to_reach_allow=[dict(_ITEM, name="data_transfer_is_cross_border",
                                 value=False)],
            to_reach_allow_reachable=True))
        self.assertIn("come back false", cert.to_reach_allow_plain[0])

    def test_established_unreachability_says_so_in_one_line(self):
        cert = _parse_cert(_wire(verdict="BLOCK", to_reach_allow=[],
                                 to_reach_allow_reachable=False))
        self.assertEqual(
            cert.to_reach_allow_plain,
            ["No unchecked fact would change this decision."])

    def test_an_unminimised_list_says_it_is_not_the_shortest(self):
        cert = _parse_cert(_wire(
            to_reach_allow=[dict(_ITEM, minimised=False)],
            to_reach_allow_reachable=True))
        self.assertIn("not the shortest set", cert.to_reach_allow_plain[-1])

    def test_the_sentences_carry_no_raw_underscored_identifier(self):
        """The plain rendering is for a person; the raw name stays in
        `to_reach_allow[].name` for the integrator who registers the probe."""
        cert = _parse_cert(_wire(to_reach_allow=[_ITEM],
                                 to_reach_allow_reachable=True))
        first_clause = cert.to_reach_allow_plain[0].split("Who can answer")[0]
        self.assertNotIn("fraud_indicators_absent", first_clause)


class TestItDoesNotTouchTheGate(unittest.TestCase):
    """The field is a signpost, never a decision."""

    def test_it_cannot_turn_a_review_into_an_allow(self):
        cert = _parse_cert(_wire(to_reach_allow=[_ITEM],
                                 to_reach_allow_reachable=True))
        self.assertFalse(cert.allow)
        self.assertTrue(cert.review)

    def test_it_cannot_clear_a_block(self):
        cert = _parse_cert(_wire(verdict="BLOCK", to_reach_allow=[_ITEM],
                                 to_reach_allow_reachable=True))
        self.assertTrue(cert.block)
        self.assertFalse(cert.allow)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
