"""
T7 — an omitted field is UNKNOWN, never a clearance.

`_parse_cert` used to read three auxiliary fields with permissive defaults:

    fabrication_detected  -> False   ("no fabrication")
    denied_authority_axes -> []      ("nothing was denied")
    chain_status          -> None    ("no cross-step block")

A server that omitted any of them was therefore indistinguishable from one that
had looked and found nothing. That is absence converted into a fact — the
defect class already closed at five probe sites and in the outage policy, found
here on the client's own parser.

What this file pins:

  * the three states of `fabrication_detected` (True / False / absent) and what
    each accessor answers on each;
  * that `denied_authority_axes` distinguishes "reported and empty" from "not
    reported", and that no read of it crashes on the new None;
  * that `is_clean()` fails CLOSED on the unknown, while `allow` / `block` /
    `review` — which gate on `verdict`, always present — are unchanged, so an
    older server is not silently blocked by the parse change alone;
  * a real old-shaped response body, from before any of these fields existed,
    still parses and still reads.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from arcezia.client import Arcezia, ArceziaCertificate, _parse_cert  # noqa: E402


# ── Fixtures ─────────────────────────────────────────────────────────────────

def _modern(**extra) -> dict:
    """What a current deployment returns: every auxiliary field present."""
    body = {
        "verdict": "ALLOW",
        "status": "ALLOWED",
        "precondition_score": 1.0,
        "trust_score": 0.9,
        "summary": "Allowed.",
        "violated": [],
        "missing": [],
        "fabrication_detected": False,
        "fabricated_constraints": [],
        "denied_authority_axes": [],
        "unresolved": [],
        "constraints": [],
        "signature": "sig",
    }
    body.update(extra)
    return body


# A REAL old-shaped response: the 1.0.0-era /v1/verify body, before
# `fabrication_detected` was surfaced, before `denied_authority_axes` and
# `unresolved` (1.0.2), before the evidence-channel fields (1.0.4). Only the
# four fields `_parse_cert` has always required, plus the ones it has always
# read. This is the compatibility bar: an SDK release must not require a
# matching server.
_OLD_SHAPED_VERIFY_RESPONSE = {
    "verdict": "ALLOW",
    "status": "ALLOWED",
    "dc_score": 1.0,               # the pre-rename precondition_score
    "trust_score": 0.75,
    "summary": "Allowed: bounded write, backup verified.",
    "violated": [],
    "missing": [],
    "constraints": [
        {"name": "bounded_write", "value": True,
         "quality": "GROUNDED", "detail": "WHERE clause present"},
    ],
    "signature": "old-server-signature",
    "credential": {"token": "cred-abc", "expires_in": 60},
}


# ── 1. fabrication_detected: three states ────────────────────────────────────

class TestFabricationDetectedIsThreeState(unittest.TestCase):

    def test_present_true(self):
        cert = _parse_cert(_modern(verdict="BLOCK", status="BLOCKED",
                                   fabrication_detected=True,
                                   fabricated_constraints=["backup_verified"]))
        self.assertIs(cert.fabrication_detected, True)
        self.assertTrue(cert.fabrication_reported)
        self.assertEqual(cert.fabrication_status, "detected")
        self.assertFalse(cert.is_clean())
        self.assertTrue(cert.block)
        self.assertFalse(cert.allow)

    def test_present_false(self):
        cert = _parse_cert(_modern())
        self.assertIs(cert.fabrication_detected, False)
        self.assertTrue(cert.fabrication_reported)
        self.assertEqual(cert.fabrication_status, "none detected")
        self.assertTrue(cert.is_clean())
        self.assertTrue(cert.allow)

    def test_absent_is_None_not_False(self):
        """THE defect. Absent used to arrive as False — a finding nobody made."""
        body = _modern()
        del body["fabrication_detected"]
        cert = _parse_cert(body)
        self.assertIsNone(cert.fabrication_detected)
        self.assertFalse(cert.fabrication_reported)
        self.assertEqual(cert.fabrication_status,
                         "not reported by this server")

    def test_the_accessor_fails_closed_on_the_unknown(self):
        body = _modern()
        del body["fabrication_detected"]
        cert = _parse_cert(body)
        self.assertFalse(cert.is_clean(),
                         "an unreported fabrication flag was read as a clearance")

    def test_the_verdict_gates_are_unchanged_by_the_unknown(self):
        """`verdict` is the decision and is always present.

        Flipping `allow` to require a positively-reported fabrication flag
        would block every response from an older server — the reason T7 is
        resolved with an ADDITIVE accessor rather than by inverting the
        defaults. So this asserts the deliberate non-change.
        """
        body = _modern()
        del body["fabrication_detected"]
        cert = _parse_cert(body)
        self.assertTrue(cert.allow)
        self.assertFalse(cert.block)
        self.assertFalse(cert.review)

    def test_a_truthy_non_bool_is_normalised(self):
        cert = _parse_cert(_modern(fabrication_detected=1))
        self.assertIs(cert.fabrication_detected, True)
        cert = _parse_cert(_modern(fabrication_detected=0))
        self.assertIs(cert.fabrication_detected, False)

    def test_str_names_the_unknown_rather_than_printing_nothing(self):
        body = _modern()
        del body["fabrication_detected"]
        self.assertIn("not reported", str(_parse_cert(body)))
        self.assertNotIn("not reported", str(_parse_cert(_modern())))
        self.assertIn("FABRICATION DETECTED",
                      str(_parse_cert(_modern(fabrication_detected=True))))


# ── 2. denied_authority_axes: reported-empty vs not-reported ─────────────────

class TestDeniedAuthorityAxesIsThreeState(unittest.TestCase):

    def test_present_and_populated(self):
        cert = _parse_cert(_modern(denied_authority_axes=["outbound"]))
        self.assertEqual(cert.denied_authority_axes, ["outbound"])
        self.assertTrue(cert.denied_authority_axes_reported)
        self.assertEqual(cert.denied_axes_or_unknown(), (("outbound",), True))

    def test_present_and_empty(self):
        cert = _parse_cert(_modern(denied_authority_axes=[]))
        self.assertEqual(cert.denied_authority_axes, [])
        self.assertTrue(cert.denied_authority_axes_reported)
        self.assertEqual(cert.denied_axes_or_unknown(), ((), True))

    def test_absent_is_None_never_empty(self):
        body = _modern()
        del body["denied_authority_axes"]
        cert = _parse_cert(body)
        self.assertIsNone(cert.denied_authority_axes)
        self.assertFalse(cert.denied_authority_axes_reported)
        self.assertEqual(cert.denied_axes_or_unknown(), ((), False))

    def test_a_non_list_value_is_not_reported(self):
        """A server sending null, or a proxy mangling the field, is an absence
        — not an empty declaration."""
        for bad in (None, "outbound", 0):
            with self.subTest(value=bad):
                cert = _parse_cert(_modern(denied_authority_axes=bad))
                self.assertIsNone(cert.denied_authority_axes)

    def test_the_safe_reader_never_makes_a_caller_crash(self):
        body = _modern()
        del body["denied_authority_axes"]
        axes, reported = _parse_cert(body).denied_axes_or_unknown()
        self.assertEqual(list(axes), [])          # iterable, always
        self.assertFalse(reported)                # but nobody may call it empty


# ── 3. chain_status: the residual the client cannot close ────────────────────

class TestChainStatusIsThreeState(unittest.TestCase):
    """The wire now separates all three, so the SDK must too.

        "SEMANTIC_BLOCK" — the scan ran, a cross-step pattern fired
        "CLEAR"          — the scan ran, nothing fired  (the explicit negative)
        absent           — the scan DID NOT RUN (no session, or it raised)

    Before the server emitted "CLEAR" this field was positive-only: absence
    meant either "nothing fired" or "this deployment computes no patterns", and
    no reader could tell. That gap is closed on the wire; these pin that the
    client reads all three rather than collapsing two of them.
    """

    # ── state 1: the scan ran and fired ─────────────────────────────────────

    def test_semantic_block_is_reported_and_not_clean(self):
        cert = _parse_cert(_modern(chain_status="SEMANTIC_BLOCK",
                                   chain_patterns=["structural_exfiltration"]))
        self.assertEqual(cert.chain_status, "SEMANTIC_BLOCK")
        self.assertTrue(cert.chain_status_reported)
        self.assertTrue(cert.semantic_block)
        self.assertEqual(cert.chain_status_plain, "cross-step pattern fired")
        self.assertFalse(cert.is_clean())
        self.assertFalse(cert.allow)
        self.assertTrue(cert.block)

    # ── state 2: the scan ran and cleared ───────────────────────────────────

    def test_CLEAR_is_reported_and_clean(self):
        """The new explicit negative. It must read as a POSITIVE clearance —
        the scan ran and said nothing fired — not merely as 'not a block'."""
        cert = _parse_cert(_modern(chain_status="CLEAR"))
        self.assertEqual(cert.chain_status, "CLEAR")
        self.assertTrue(cert.chain_status_reported)
        self.assertFalse(cert.semantic_block)
        self.assertEqual(cert.chain_status_plain, "cross-step scan clear")
        self.assertTrue(cert.is_clean())
        self.assertTrue(cert.allow)

    def test_CLEAR_is_distinguishable_from_absence(self):
        """The whole point of the server change: two states that used to be
        one. If these ever compare equal again, the distinction was lost."""
        ran = _parse_cert(_modern(chain_status="CLEAR"))
        did_not_run = _parse_cert(_modern())
        self.assertNotEqual(ran.chain_status_reported,
                            did_not_run.chain_status_reported)
        self.assertNotEqual(ran.chain_status_plain,
                            did_not_run.chain_status_plain)
        # …while both agree there is no cross-step danger to act on.
        self.assertFalse(ran.semantic_block)
        self.assertFalse(did_not_run.semantic_block)

    # ── state 3: the scan did not run ───────────────────────────────────────

    def test_absent_means_the_scan_did_not_run(self):
        cert = _parse_cert(_modern())
        self.assertIsNone(cert.chain_status)
        self.assertFalse(cert.chain_status_reported)
        self.assertFalse(cert.semantic_block)
        self.assertEqual(cert.chain_status_plain, "cross-step scan did not run")

    def test_absence_alone_does_not_make_a_certificate_unclean(self):
        """The derived decision, pinned so it cannot drift into either error.

        The cross-step scan is PER-SESSION and is absent exactly when it did
        not run — commonly because there was no session, and a sessionless
        single verify has no earlier step to compose with. Refusing on that
        would refuse every sessionless call, and every server predating
        "CLEAR", for no safety gain. Contrast the per-action fabrication check
        below, whose absence can only be a lost report.
        """
        cert = _parse_cert(_modern())          # fabrication reported, no scan
        self.assertFalse(cert.chain_status_reported)
        self.assertTrue(cert.is_clean())

        body = _modern()                       # scan absent AND fabrication absent
        del body["fabrication_detected"]
        self.assertFalse(_parse_cert(body).is_clean(),
                         "the per-action check's absence must still refuse")

    def test_a_caller_who_wants_the_scan_required_has_a_lever(self):
        """`is_clean()` does not require the scan; this is how you do require
        it, and it is the documented form."""
        ran = _parse_cert(_modern(chain_status="CLEAR"))
        did_not_run = _parse_cert(_modern())
        self.assertTrue(ran.is_clean() and ran.chain_status_reported)
        self.assertFalse(did_not_run.is_clean()
                         and did_not_run.chain_status_reported)

    # ── the three states, one table ─────────────────────────────────────────

    def test_the_full_three_state_table(self):
        for wire, reported, sem, clean, plain in (
            ("SEMANTIC_BLOCK", True,  True,  False, "cross-step pattern fired"),
            ("CLEAR",          True,  False, True,  "cross-step scan clear"),
            (None,             False, False, True,  "cross-step scan did not run"),
        ):
            with self.subTest(chain_status=wire):
                body = _modern()
                if wire is not None:
                    body["chain_status"] = wire
                cert = _parse_cert(body)
                self.assertEqual(cert.chain_status_reported, reported)
                self.assertEqual(cert.semantic_block, sem)
                self.assertEqual(cert.is_clean(), clean)
                self.assertEqual(cert.chain_status_plain, plain)

    def test_an_unrecognised_status_is_reported_but_not_a_block(self):
        """A future value the server adds must not read as SEMANTIC_BLOCK, and
        must not read as 'the scan did not run' either — it ran and said
        something this SDK version does not know."""
        cert = _parse_cert(_modern(chain_status="SOME_FUTURE_STATE"))
        self.assertTrue(cert.chain_status_reported)
        self.assertFalse(cert.semantic_block)
        self.assertEqual(cert.chain_status_plain, "cross-step scan clear")


# ── 4. A degraded certificate reports nothing, and says so ───────────────────

class TestDegradedCertificateClaimsNoFinding(unittest.TestCase):

    def test_a_synthetic_cert_does_not_claim_no_fabrication(self):
        cert = Arcezia._degraded_cert("ALLOW", ConnectionError("unreachable"))
        self.assertIsNone(cert.fabrication_detected,
                          "the SDK asserted a fabrication finding it never obtained")
        self.assertIsNone(cert.denied_authority_axes)
        self.assertFalse(cert.is_clean())
        # …while the documented outage contract is untouched.
        self.assertTrue(cert.degraded)
        self.assertTrue(cert.allow)
        self.assertIsNone(cert.credential)


# ── 5. The old-shaped response, end to end ───────────────────────────────────

class TestARealOldShapedResponseStillWorks(unittest.TestCase):
    """Backward compatibility, proven against a body from before the fields."""

    def setUp(self):
        self.cert = _parse_cert(dict(_OLD_SHAPED_VERIFY_RESPONSE))

    def test_it_parses(self):
        self.assertEqual(self.cert.verdict, "ALLOW")
        self.assertEqual(self.cert.precondition_score, 1.0)   # from dc_score
        self.assertEqual(self.cert.constraints[0].name, "bounded_write")

    def test_every_gate_still_answers(self):
        self.assertTrue(self.cert.allow)
        self.assertFalse(self.cert.block)
        self.assertFalse(self.cert.review)
        self.assertFalse(self.cert.degraded)

    def test_every_changed_field_reads_as_unknown(self):
        self.assertIsNone(self.cert.fabrication_detected)
        self.assertIsNone(self.cert.denied_authority_axes)
        self.assertIsNone(self.cert.chain_status)
        self.assertFalse(self.cert.chain_status_reported)
        self.assertFalse(self.cert.is_clean())

    def test_a_server_that_never_emits_CLEAR_is_not_refused_for_that_reason(self):
        """Backward compatibility for the server change, isolated.

        The 1.0.0-era body has no `chain_status` at all — that deployment does
        not know the key exists, let alone "CLEAR". If the missing scan were
        treated as unclean, every such response would be refused at every
        adapter. Prove it is not: with the per-action fabrication flag supplied
        and nothing else changed, this old body is clean.
        """
        body = dict(_OLD_SHAPED_VERIFY_RESPONSE, fabrication_detected=False)
        cert = _parse_cert(body)
        self.assertIsNone(cert.chain_status)
        self.assertFalse(cert.chain_status_reported)
        self.assertTrue(cert.is_clean(),
                        "a server predating CLEAR was refused for not sending it")
        self.assertTrue(cert.allow)

    def test_the_old_body_is_refused_only_for_the_fabrication_report(self):
        """…and the refusal it DOES get is attributable to one named cause."""
        self.assertFalse(self.cert.is_clean())
        self.assertFalse(self.cert.fabrication_reported)
        self.assertFalse(self.cert.semantic_block)

    def test_no_read_of_a_changed_field_raises(self):
        """The compatibility bar stated in T7: None must not crash a reader.

        Every accessor, every string rendering, and both list-shaped fields.
        """
        c = self.cert
        _ = (c.fabrication_detected, c.fabrication_reported, c.fabrication_status,
             c.denied_authority_axes, c.denied_authority_axes_reported,
             c.denied_axes_or_unknown(), c.chain_status, c.chain_status_reported,
             c.chain_status_plain,
             c.semantic_block, c.is_clean(), c.allow, c.block, c.review,
             c.degraded, c.evidence_channel_healthy, str(c),
             c.probes_not_consulted(["x"]))
        self.assertIsInstance(str(c), str)

    def test_the_integration_message_helpers_handle_the_unknown(self):
        """Every site in `client/` that renders the flag, on a None."""
        from arcezia.integrations.openai import _fabrication_note
        note = _fabrication_note(self.cert)
        self.assertIn("not reported", note)
        self.assertEqual(_fabrication_note(_parse_cert(_modern())), "")
        self.assertIn(
            "FABRICATION",
            _fabrication_note(_parse_cert(_modern(fabrication_detected=True))))
        # langchain interpolates `fabrication_status`, never the raw field.
        self.assertNotIn("None", f"Fabrication: {self.cert.fabrication_status}")


# ── 6. The adapter gate turns the unknown into a refusal ─────────────────────

class TestTheGuardRefusesAnUnclearedCertificate(unittest.TestCase):
    """`guard_callable` is where None becomes a decision.

    `cert.allow` stays verdict-driven so the parse change alone blocks nobody.
    The single place that fails closed on the unknown is the guard that also
    already refuses degraded certificates — one refusal site, not eight.
    """

    def _guard(self, cert):
        from unittest.mock import MagicMock
        from arcezia.integrations.universal import guard_callable
        az = MagicMock(spec=Arcezia)
        az.verify.return_value = cert
        ran = []
        return guard_callable(lambda **k: ran.append(1), az,
                              domain="database_ops", action_type="run_sql"), ran

    def test_a_reported_clean_allow_runs(self):
        safe, ran = self._guard(_parse_cert(_modern()))
        safe()
        self.assertEqual(ran, [1])

    def test_an_allow_whose_fabrication_flag_was_never_reported_is_refused(self):
        from arcezia.client import ArceziaBlockError
        body = _modern()
        del body["fabrication_detected"]
        safe, ran = self._guard(_parse_cert(body))
        with self.assertRaises(ArceziaBlockError):
            safe()
        self.assertEqual(ran, [], "an unverified-fabrication ALLOW executed")

    def test_a_semantic_block_riding_on_an_ALLOW_is_still_refused(self):
        from arcezia.client import ArceziaBlockError
        safe, ran = self._guard(
            _parse_cert(_modern(chain_status="SEMANTIC_BLOCK")))
        with self.assertRaises(ArceziaBlockError):
            safe()
        self.assertEqual(ran, [])


if __name__ == "__main__":
    unittest.main()


# ── 7. The gate holds at EVERY adapter, not just the universal one ───────────

class TestEveryAdapterRefusesAnUnclearedAllow(unittest.TestCase):
    """One accessor, called at every adapter's refusal point.

    T7's fix is worth only as much as its coverage. `_common.refuse_unless_clean`
    is called at every site that already refuses a degraded certificate — twelve
    of them share one uniform block, and the three that are not exceptions (the
    Claude Code hook decision, the OpenClaw CLI decision, and the Anthropic
    tool-use filter) consult `is_clean()` in their own idiom.

    Each case below exercises a REAL adapter entry point with a certificate
    whose only defect is an unreported fabrication flag: verdict ALLOW,
    credential present, not degraded. Nothing else about it would refuse.
    """

    def _certs(self):
        clean = _parse_cert(_modern(credential={"token": "t"}))
        body = _modern(credential={"token": "t"})
        del body["fabrication_detected"]
        return clean, _parse_cert(body)

    def _az(self, cert):
        from unittest.mock import MagicMock
        az = MagicMock(spec=Arcezia)
        az.verify.return_value = cert
        return az

    def test_autogen_sync_wrap(self):
        from arcezia.integrations.autogen import ArceziaAutoGenGuard
        clean, unreported = self._certs()
        for cert, should_run in ((clean, True), (unreported, False)):
            with self.subTest(reported=cert.fabrication_reported):
                ran = []
                guard = ArceziaAutoGenGuard(self._az(cert))
                safe = guard.wrap("execute_sql", lambda **k: ran.append(1),
                                  domain="database_ops")
                if should_run:
                    safe(query="SELECT 1")
                else:
                    with self.assertRaises(RuntimeError):
                        safe(query="SELECT 1")
                self.assertEqual(bool(ran), should_run)

    def test_openclaw_dispatch(self):
        from arcezia.integrations.openclaw import DispatchGuard
        clean, unreported = self._certs()
        for cert, should_run in ((clean, True), (unreported, False)):
            with self.subTest(reported=cert.fabrication_reported):
                ran = []
                guard = DispatchGuard(api_key="ar_test_key", task="t")
                guard._client = self._az(cert)
                if should_run:
                    guard.dispatch("execute_sql", {"q": 1},
                                   fn=lambda **k: ran.append(1))
                else:
                    with self.assertRaises(RuntimeError):
                        guard.dispatch("execute_sql", {"q": 1},
                                       fn=lambda **k: ran.append(1))
                self.assertEqual(bool(ran), should_run)

    def test_openai_execute_tool_call(self):
        from arcezia.integrations.openai import ArceziaGuard
        clean, unreported = self._certs()
        call = {"name": "execute_sql", "arguments": '{"q": 1}'}
        impls = {"execute_sql": lambda **k: "ran"}
        self.assertEqual(
            ArceziaGuard(self._az(clean)).execute_tool_call(call, impls)["result"],
            "ran")
        from arcezia.client import ArceziaBlockError
        with self.assertRaises(ArceziaBlockError):
            ArceziaGuard(self._az(unreported)).execute_tool_call(call, impls)

    def test_anthropic_filter_does_not_put_it_on_the_safe_list(self):
        from arcezia.integrations.anthropic import ArceziaAnthropicGuard
        clean, unreported = self._certs()
        block = {"type": "tool_use", "name": "execute_sql",
                 "id": "tu_1", "input": {"q": 1}}
        safe, blocked = ArceziaAnthropicGuard(
            self._az(clean)).filter_tool_uses([block])
        self.assertEqual(len(safe), 1)
        self.assertEqual(blocked, [])
        safe, blocked = ArceziaAnthropicGuard(
            self._az(unreported)).filter_tool_uses([block])
        self.assertEqual(safe, [], "an uncleared ALLOW reached the safe list")
        self.assertEqual(len(blocked), 1)

    def test_the_openclaw_cli_decision_blocks(self):
        import json
        from arcezia.integrations import openclaw
        clean, unreported = self._certs()

        class _V:
            def __init__(self, cert):
                self.cert = cert

            def _verify(self, tool_name, args, domain=None):
                return self.cert

        payload = json.dumps({"tool": "read_file", "args": {"path": "/tmp/a"}})
        self.assertEqual(
            openclaw.run_cli_hook(payload, verifier=_V(clean))["decision"],
            "allow")
        out = openclaw.run_cli_hook(payload, verifier=_V(unreported))
        self.assertEqual(out["decision"], "block")
        self.assertIn("not cleared", out["reason"])

    def test_the_rule_has_one_implementation(self):
        """Fourteen copies of a rule is fourteen chances to get one wrong —
        which is exactly how `_synthetic` reached three spellings (T8).

        The refusal itself lives in `_common.refuse_unless_clean`; the three
        surfaces that are not exceptions call `is_clean()` in their own idiom.
        Nothing re-derives the rule from the raw field.
        """
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent / "arcezia"
        offenders = []
        for f in root.rglob("*.py"):
            if "__pycache__" in str(f) or f.name == "client.py":
                continue
            for i, line in enumerate(f.read_text().splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                if ("fabrication_detected is None" in line
                        or "fabrication_detected is False" in line):
                    # Only the plain-words renderer may branch on the raw
                    # field; every gate goes through the accessor.
                    if f.name != "openai.py":
                        offenders.append(f"{f.name}:{i}")
        self.assertEqual(offenders, [], "a gate re-derived the three-state rule")
