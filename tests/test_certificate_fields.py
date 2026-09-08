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

    def test_an_absent_denied_axes_list_reads_as_UNKNOWN_not_as_empty(self):
        """Re-pinned by T7, to the stronger fact.

        This used to assert `== []` — that a server which said nothing about
        the denied axes was read as having said "nothing is denied". Those are
        different facts, and the second one is the permissive one: an
        envelope's denials are the operator's own ceiling. Absence now stays
        absence, and `denied_axes_or_unknown()` is how a caller reads it
        without crashing on None.
        """
        cert = _parse_cert(_wire())          # no new keys at all
        self.assertIsNone(cert.denied_authority_axes)
        self.assertFalse(cert.denied_authority_axes_reported)
        self.assertEqual(cert.denied_axes_or_unknown(), ((), False))
        self.assertEqual(cert.unresolved, [])

    def test_a_reported_empty_denied_axes_list_is_distinguishable_from_absence(self):
        cert = _parse_cert(_wire(denied_authority_axes=[]))
        self.assertEqual(cert.denied_authority_axes, [])
        self.assertTrue(cert.denied_authority_axes_reported)
        self.assertEqual(cert.denied_axes_or_unknown(), ((), True))

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
        # Re-pinned by T7: the field's default is None ("not reported"), not
        # [] ("reported, and nothing was denied"). A hand-built certificate
        # that declares no axes has not been told any, which is the first fact.
        self.assertIsNone(cert.denied_authority_axes)
        self.assertFalse(cert.denied_authority_axes_reported)
        self.assertEqual(cert.unresolved, [])

    def test_parsed_lists_are_not_shared_between_instances(self):
        """A mutable default declared without a factory would be shared by every
        certificate ever created.

        Re-pinned by T7 onto the reported case, which is where a shared list is
        now possible at all: the absent case is None, which cannot be mutated.
        This also proves the parsed list is a COPY of the response's list, so a
        caller's append cannot rewrite what `raw` reports the server said.
        """
        a = _parse_cert(_wire(denied_authority_axes=[]))
        b = _parse_cert(_wire(denied_authority_axes=[]))
        a.denied_authority_axes.append("irreversible")
        self.assertEqual(b.denied_authority_axes, [])

        wire = _wire(denied_authority_axes=["outbound"])
        cert = _parse_cert(wire)
        cert.denied_authority_axes.append("irreversible")
        self.assertEqual(wire["denied_authority_axes"], ["outbound"])
        self.assertEqual(cert.raw["denied_authority_axes"], ["outbound"])


class TestEvidenceChannelFieldsAreRead(unittest.TestCase):
    """The v30 evidence-channel surface added in 1.0.4.

    These shipped verified against production by hand but with no regression
    test on the client side — the server tests cover emitting them, nothing
    covered parsing them. A rename or a dropped key in `_parse_cert` would have
    been silent, and these are exactly the fields the complete guide names as
    the way to answer "why did my verdicts go to REVIEW".
    """

    def test_probe_outcomes_and_channel_parsed(self):
        cert = _parse_cert(_wire(
            probe_outcomes={"verified_recent_backup": "answered",
                            "cascade_effects_verified": "unreachable"},
            evidence_channel="degraded",
            evidence_channel_failures={"cascade_effects_verified": "timeout"},
            degraded_defenses=["probe_evidence_channel"],
            unverified_approvals=["user_explicit_authorization"],
        ))
        self.assertEqual(cert.probe_outcomes["verified_recent_backup"], "answered")
        self.assertEqual(cert.evidence_channel, "degraded")
        self.assertEqual(cert.evidence_channel_failures,
                         {"cascade_effects_verified": "timeout"})
        self.assertEqual(cert.degraded_defenses, ["probe_evidence_channel"])
        self.assertEqual(cert.unverified_approvals, ["user_explicit_authorization"])

    def test_channel_health_distinguishes_expected_review_from_broken(self):
        # None means healthy: a REVIEW here is the engine asking for evidence.
        self.assertTrue(_parse_cert(_wire()).evidence_channel_healthy)
        # Set means probes did not answer — the REVIEW needs a human, not evidence.
        self.assertFalse(
            _parse_cert(_wire(evidence_channel="unavailable")).evidence_channel_healthy)

    def test_probes_not_consulted_names_a_lost_registration(self):
        cert = _parse_cert(_wire(probe_outcomes={"verified_recent_backup": "answered"}))
        self.assertEqual(
            cert.probes_not_consulted(["verified_recent_backup",
                                       "cascade_effects_verified"]),
            ["cascade_effects_verified"],
        )
        # Accepts a set as documented, and is empty when everything was asked.
        self.assertEqual(cert.probes_not_consulted({"verified_recent_backup"}), [])

    def test_raw_carries_fields_the_sdk_does_not_model(self):
        """`raw` exists so a future server field is never gated behind an SDK
        release. A field this client has never heard of must still arrive."""
        cert = _parse_cert(_wire(some_future_field={"nested": 1}))
        self.assertEqual(cert.raw["some_future_field"], {"nested": 1})
        self.assertEqual(cert.raw["verdict"], "BLOCK")

    def test_older_server_omitting_all_of_them_still_parses(self):
        """Same compatibility rule as 1.0.2: an SDK release must not require a
        matching server."""
        cert = _parse_cert(_wire())
        self.assertEqual(cert.probe_outcomes, {})
        self.assertIsNone(cert.evidence_channel)
        self.assertEqual(cert.evidence_channel_failures, {})
        self.assertEqual(cert.degraded_defenses, [])
        self.assertEqual(cert.unverified_approvals, [])
        self.assertTrue(cert.evidence_channel_healthy)

    def test_null_valued_fields_do_not_become_none(self):
        """The server may send explicit nulls; the `or {}` guards must hold, or
        every consumer gets a TypeError instead of an empty map."""
        cert = _parse_cert(_wire(probe_outcomes=None, evidence_channel_failures=None,
                                 degraded_defenses=None, unverified_approvals=None))
        self.assertEqual(cert.probe_outcomes, {})
        self.assertEqual(cert.evidence_channel_failures, {})
        self.assertEqual(cert.degraded_defenses, [])
        self.assertEqual(cert.unverified_approvals, [])

    def test_evidence_defaults_are_not_shared_between_instances(self):
        a, b = _parse_cert(_wire()), _parse_cert(_wire())
        a.probe_outcomes["x"] = "answered"
        a.degraded_defenses.append("probe_evidence_channel")
        self.assertEqual(b.probe_outcomes, {})
        self.assertEqual(b.degraded_defenses, [])


if __name__ == "__main__":
    unittest.main()


class TestDecisionIdentityFields(unittest.TestCase):
    """Decision identity + provenance (server v31): log_id, created_at,
    request_id, session_id, action_identity, ruleset_hash, engine_version,
    record_signature, signed_at. Additive — an older server sending none of
    them must still parse."""

    def test_identity_fields_parsed(self):
        cert = _parse_cert(_wire(
            log_id=4711,
            created_at="2026-09-01T12:00:00+00:00",
            request_id="req-1",
            session_id="sess-1",
            action_identity={"type": "execute_sql", "domain": "database_ops",
                             "digest": "ab" * 32},
            ruleset_hash="builtin",
            engine_version="1.0.0+src-deadbeef",
            record_signature={"scheme": "ed25519-record-v1", "key_id": "k",
                              "signature": "s"},
            signed_at="2026-09-01T12:00:00+00:00",
        ))
        self.assertEqual(cert.log_id, 4711)
        self.assertEqual(cert.request_id, "req-1")
        self.assertEqual(cert.session_id, "sess-1")
        self.assertEqual(cert.action_identity["digest"], "ab" * 32)
        self.assertEqual(cert.ruleset_hash, "builtin")
        self.assertEqual(cert.engine_version, "1.0.0+src-deadbeef")
        self.assertEqual(cert.record_signature["scheme"], "ed25519-record-v1")
        self.assertEqual(cert.signed_at, "2026-09-01T12:00:00+00:00")
        self.assertTrue(cert.created_at.startswith("2026-09-01"))

    def test_older_server_defaults_to_none(self):
        cert = _parse_cert(_wire())
        self.assertIsNone(cert.log_id)
        self.assertIsNone(cert.created_at)
        self.assertIsNone(cert.request_id)
        self.assertIsNone(cert.session_id)
        self.assertIsNone(cert.action_identity)
        self.assertIsNone(cert.ruleset_hash)
        self.assertIsNone(cert.engine_version)
        self.assertIsNone(cert.record_signature)
        self.assertIsNone(cert.signed_at)
        # And everything is still visible through raw regardless of SDK age.
        self.assertIn("signature", cert.raw)
