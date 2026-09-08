"""
R2 — `on_error="fail_open"` inside a framework adapter is a contradiction.

An operator sets `fail_open` to buy one thing: "my agent keeps running when
Arcezia is down". Inside an adapter they do not get it. `fail_open` makes
verify() return a SYNTHETIC ALLOW, and every adapter refuses a degraded
certificate and raises `ArceziaUnavailableError` instead of running the tool.

Both halves are right on their own. Together they are a safety setting that
silently does nothing exactly where it is most likely to be set — and the
operator finds out during an incident, from an exception they were told they
had configured away.

The behaviour is NOT changed here: refusing an unverified verdict is the
fail-safe half, and a synthetic ALLOW is not a verification. What changes is
that the contradiction cannot be hit in silence. It is stated once, at
construction, while the operator is still looking at the line that chose it.

This file pins that the warning fires from every construction path, says the
load-bearing things, and does not fire when there is nothing to warn about.
"""
from __future__ import annotations

import os
import sys
import unittest
import warnings
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from arcezia.client import Arcezia, ArceziaUnavailableError  # noqa: E402
from arcezia.integrations._common import (  # noqa: E402
    FAIL_OPEN_ADAPTER_WARNING,
    coerce_az,
    warn_if_fail_open,
)


def _client(on_error: str) -> Arcezia:
    return Arcezia(api_key="ar_test_x", task="t", on_error=on_error)


def _warnings_from(fn) -> list:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        fn()
    return [str(w.message) for w in caught]


class TestTheWarningFires(unittest.TestCase):

    def test_wrapping_an_existing_fail_open_client_warns(self):
        msgs = _warnings_from(lambda: coerce_az(_client("fail_open")))
        self.assertEqual(len(msgs), 1, msgs)
        self.assertEqual(msgs[0], FAIL_OPEN_ADAPTER_WARNING)

    def test_building_a_fail_open_client_from_kwargs_warns(self):
        msgs = _warnings_from(
            lambda: coerce_az(None, api_key="ar_test_x", task="t",
                              on_error="fail_open"))
        self.assertEqual(len(msgs), 1, msgs)

    def test_it_fires_through_a_real_adapter_constructor(self):
        from arcezia.integrations.openclaw import DispatchGuard
        msgs = _warnings_from(
            lambda: DispatchGuard(api_key="ar_test_x", task="t",
                                  on_error="fail_open"))
        self.assertIn(FAIL_OPEN_ADAPTER_WARNING, msgs)

    def test_it_fires_from_the_universal_guard(self):
        from arcezia.integrations.universal import guard_callable
        az = _client("fail_open")
        msgs = _warnings_from(
            lambda: guard_callable(lambda: None, az, domain="database_ops",
                                   action_type="run_sql"))
        self.assertIn(FAIL_OPEN_ADAPTER_WARNING, msgs)

    def test_it_fires_from_az_gate(self):
        """`az.gate()` is guard_callable bound to the client — same path."""
        az = _client("fail_open")

        def build():
            @az.gate(domain="database_ops", action_type="run_sql")
            def run_sql(q):
                return q
            return run_sql

        self.assertIn(FAIL_OPEN_ADAPTER_WARNING, _warnings_from(build))

    def test_it_fires_from_the_claude_code_hook_verifier(self):
        from arcezia.integrations import claude_code
        env = {"ARCEZIA_API_KEY": "ar_test_x", "ARCEZIA_ON_ERROR": "fail_open"}
        # No envelope: loading one opens a session, which would put this test
        # on the network. The warning is emitted before that, which is the
        # point — it reaches the operator without a round trip.
        with patch.dict(os.environ, env, clear=False), \
                patch.object(claude_code, "_load_capability_envelope",
                             return_value=None):
            msgs = _warnings_from(claude_code._default_verifier)
        self.assertIn(FAIL_OPEN_ADAPTER_WARNING, msgs)


class TestTheWarningSaysWhatMatters(unittest.TestCase):
    """A warning nobody can act on is noise. These are the facts it must carry."""

    def test_it_names_the_setting_and_the_refusal(self):
        for phrase in ("fail_open", "REFUSE", "ArceziaUnavailableError",
                       "synthetic"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase.lower(), FAIL_OPEN_ADAPTER_WARNING.lower())

    def test_it_says_the_behaviour_is_deliberate_not_a_bug(self):
        self.assertIn("deliberate", FAIL_OPEN_ADAPTER_WARNING)

    def test_it_tells_the_operator_what_to_do_instead(self):
        self.assertIn("catch ArceziaUnavailableError", FAIL_OPEN_ADAPTER_WARNING)

    def test_it_points_at_the_documented_reason(self):
        self.assertIn("WHAT HAPPENS WHEN ARCEZIA IS UNREACHABLE",
                      FAIL_OPEN_ADAPTER_WARNING)
        self.assertIn("WHAT HAPPENS WHEN ARCEZIA IS UNREACHABLE",
                      Arcezia.__doc__)


class TestTheWarningDoesNotFireOtherwise(unittest.TestCase):

    def test_silent_for_the_other_two_policies(self):
        for mode in ("fail_closed", "review"):
            with self.subTest(mode=mode):
                msgs = _warnings_from(lambda: coerce_az(_client(mode)))
                self.assertEqual(
                    [m for m in msgs if "fail_open" in m], [])

    def test_once_per_client_not_once_per_wrapped_tool(self):
        """A toolkit that wraps forty tools must not emit forty copies."""
        from arcezia.integrations.universal import guard_callable
        az = _client("fail_open")

        def wrap_many():
            for i in range(5):
                guard_callable(lambda: None, az, domain="database_ops",
                               action_type=f"tool_{i}")

        msgs = [m for m in _warnings_from(wrap_many)
                if m == FAIL_OPEN_ADAPTER_WARNING]
        self.assertEqual(len(msgs), 1, msgs)

    def test_a_mock_client_does_not_trip_it(self):
        """Tests and callers pass MagicMock(spec=Arcezia); `_on_error` is an
        instance attribute, so a spec'd mock has none and nothing is claimed."""
        msgs = _warnings_from(lambda: warn_if_fail_open(MagicMock(spec=Arcezia)))
        self.assertEqual(msgs, [])


class TestTheRefusalItWarnsAboutIsStillReal(unittest.TestCase):
    """The warning would be a lie if the behaviour had quietly changed."""

    def test_a_fail_open_degraded_allow_is_still_refused_by_the_guard(self):
        from arcezia.integrations.universal import guard_callable
        cert = Arcezia._degraded_cert("ALLOW", ConnectionError("unreachable"))
        self.assertTrue(cert.allow)          # the client says ALLOW …
        az = MagicMock(spec=Arcezia)
        az.verify.return_value = cert
        ran = []
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            safe = guard_callable(lambda **k: ran.append(1), az,
                                  domain="database_ops", action_type="run_sql")
        with self.assertRaises(ArceziaUnavailableError):   # … and the adapter refuses
            safe()
        self.assertEqual(ran, [])


if __name__ == "__main__":
    unittest.main()
