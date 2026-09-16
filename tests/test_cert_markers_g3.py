"""The two response markers added 2026-09-12 are parsed, never left in .raw only."""
from arcezia.client import _parse_cert


def _base(**extra):
    d = {"verdict": "REVIEW", "status": "INSUFFICIENT_EVIDENCE", "dc_score": 0.0,
         "precondition_score": 0.0, "trust_score": 0.0, "constraints": [],
         "violated_constraints": [], "missing_constraints": [], "summary": ""}
    d.update(extra)
    return d


def test_absence_channel_and_envelope_signed_parse():
    c = _parse_cert(_base(absence_channel="undeclared", envelope_signed=False))
    assert c.absence_channel == "undeclared"
    assert c.envelope_signed is False


def test_markers_absent_on_old_servers_are_none_not_false():
    c = _parse_cert(_base())
    assert c.absence_channel is None
    assert c.envelope_signed is None


def test_envelope_signed_non_bool_is_unknown():
    c = _parse_cert(_base(envelope_signed="yes"))
    assert c.envelope_signed is None
