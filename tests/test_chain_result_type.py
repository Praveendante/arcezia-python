"""
T8 — `_synthetic` had three spellings; the chain result is now typed.

The marker for "this SDK made this up locally because Arcezia was unreachable"
existed as a dataclass field on `ArceziaCertificate`, as a dataclass field on
`ArceziaOutcomeResult`, and as a bare string key in the dict `verify_chain`
returned. One property, three surfaces. The dict was the root cause: an untyped
return value has nothing to keep it in step with the two dataclasses beside it,
so the next reader gets one of the three wrong.

`verify_chain` now returns `ArceziaChainResult`, with `_synthetic` as the same
field name and `.degraded` as the same reader as on the other two.

The constraint is backward compatibility: six adapter docstrings, the package
docstring and the README all teach `result["overall_verdict"]`. The last class
in this file EXTRACTS those examples from the shipped source and runs every
subscript in them against both a real and a synthetic result, so "no documented
example breaks" is measured rather than asserted.
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from arcezia.client import (  # noqa: E402
    Arcezia,
    ArceziaCertificate,
    ArceziaChainResult,
    ArceziaOutcomeResult,
    _parse_chain,
)

ROOT = pathlib.Path(__file__).resolve().parent.parent


# A real /v1/verify_chain body, in the shape the README documents.
def _wire(**extra) -> dict:
    body = {
        "overall_verdict": "SEMANTIC_BLOCK",
        "blocked_at": "s2",
        "steps": [
            {"id": "s1", "verdict": "ALLOW"},
            {"id": "s2", "verdict": "BLOCK"},
        ],
        "semantic_triggers": [{"pattern_name": "structural_exfiltration"}],
        # The wire key is `human_summary` — see server/main.py's chain
        # response builder. `summary` has never been on a chain response; it
        # existed only in the degraded dict, and survives as an alias.
        "human_summary": "Step 2 composes into exfiltration.",
        "final_state": {"sensitive_data_read": True},
        "session_state_updated": True,
    }
    body.update(extra)
    return body


# The oldest chain response shape: no `semantic_triggers`, no `summary`.
_OLD_SHAPED_CHAIN_RESPONSE = {
    "overall_verdict": "SAFE",
    "blocked_at": None,
    "steps": [{"id": "s1", "verdict": "ALLOW"}],
    "final_state": {},
}


# ── 1. One spelling, three result types ──────────────────────────────────────

class TestTheMarkerHasOneSpelling(unittest.TestCase):

    def test_all_three_result_types_carry_the_same_field(self):
        for cls in (ArceziaCertificate, ArceziaOutcomeResult, ArceziaChainResult):
            with self.subTest(cls=cls.__name__):
                self.assertIn("_synthetic", cls.__dataclass_fields__,
                              "the local-origin marker is spelled differently here")

    def test_all_three_expose_it_as_degraded(self):
        exc = ConnectionError("unreachable")
        for obj in (Arcezia._degrade_cert("fail_open", exc),
                    Arcezia._degrade_outcome("fail_open", exc),
                    Arcezia._degrade_chain("fail_open", exc)):
            with self.subTest(cls=type(obj).__name__):
                self.assertTrue(obj.degraded)
                self.assertTrue(obj._synthetic)

    def test_a_real_chain_result_is_not_degraded(self):
        self.assertFalse(_parse_chain(_wire()).degraded)


# ── 2. The typed surface ─────────────────────────────────────────────────────

class TestTypedFields(unittest.TestCase):

    def test_fields_are_parsed(self):
        r = _parse_chain(_wire())
        self.assertEqual(r.overall_verdict, "SEMANTIC_BLOCK")
        self.assertEqual(r.blocked_at, "s2")
        self.assertEqual([s["id"] for s in r.steps], ["s1", "s2"])
        self.assertEqual(r.semantic_triggers[0]["pattern_name"],
                         "structural_exfiltration")
        self.assertEqual(r.human_summary, "Step 2 composes into exfiltration.")
        self.assertEqual(r.raw["session_state_updated"], True)

    def test_safe_is_stricter_than_the_verdict_string(self):
        """The reason to move off dict access at all.

        Under `on_error="fail_open"` the degraded result's overall_verdict is
        the string "SAFE" — the documented gate cannot tell it from a chain
        that was actually checked. `.safe` can.
        """
        real = _parse_chain(_wire(overall_verdict="SAFE", blocked_at=None))
        fake = Arcezia._degrade_chain("fail_open", ConnectionError("down"))
        self.assertTrue(real.safe)
        self.assertEqual(fake["overall_verdict"], "SAFE")
        self.assertFalse(fake.safe, "a degraded chain result reported itself safe")

    def test_the_summary_alias_never_shadows_a_real_wire_field(self):
        r = _parse_chain(_wire(summary="a field the server actually sent"))
        self.assertEqual(r["summary"], "a field the server actually sent")
        self.assertEqual(r["human_summary"], "Step 2 composes into exfiltration.")

    def test_an_old_shaped_response_parses(self):
        r = _parse_chain(dict(_OLD_SHAPED_CHAIN_RESPONSE))
        self.assertTrue(r.safe)
        self.assertEqual(r.semantic_triggers, [])   # absent -> empty, not None
        self.assertEqual(r.human_summary, "")
        self.assertEqual(r["final_state"], {})

    def test_null_valued_list_fields_do_not_become_None(self):
        r = _parse_chain(_wire(steps=None, semantic_triggers=None,
                               human_summary=None))
        self.assertEqual(r.steps, [])
        self.assertEqual(r.semantic_triggers, [])
        self.assertEqual(r.human_summary, "")

    def test_str_is_readable(self):
        self.assertIn("SEMANTIC_BLOCK", str(_parse_chain(_wire())))
        self.assertIn("degraded",
                      str(Arcezia._degrade_chain("review", ConnectionError("d"))))


# ── 3. Dict compatibility, key by key ────────────────────────────────────────

class TestDictAccessStillWorks(unittest.TestCase):

    def setUp(self):
        self.r = _parse_chain(_wire())

    def test_every_documented_key_resolves(self):
        for key, expected in (
            ("overall_verdict", "SEMANTIC_BLOCK"),
            ("blocked_at", "s2"),
            ("human_summary", "Step 2 composes into exfiltration."),
            ("summary", "Step 2 composes into exfiltration."),   # the alias
            ("final_state", {"sensitive_data_read": True}),
            ("session_state_updated", True),
        ):
            with self.subTest(key=key):
                self.assertEqual(self.r[key], expected)
        self.assertEqual(len(self.r["steps"]), 2)
        self.assertEqual(len(self.r["semantic_triggers"]), 1)

    def test_get_and_in_and_keys(self):
        self.assertEqual(self.r.get("blocked_at"), "s2")
        self.assertIsNone(self.r.get("nope"))
        self.assertEqual(self.r.get("nope", "fallback"), "fallback")
        self.assertIn("overall_verdict", self.r)
        self.assertNotIn("nope", self.r)
        self.assertIn("final_state", self.r.keys())
        self.assertEqual(dict(self.r.items())["blocked_at"], "s2")

    def test_it_iterates_like_the_dict_it_replaces(self):
        """`__getitem__` without `__iter__` would silently switch iteration to
        the old integer-indexing protocol and raise KeyError on `for k in
        result`. The dict yielded keys; so does this."""
        self.assertIn("overall_verdict", list(iter(self.r)))
        self.assertEqual(len(self.r), len(self.r.to_dict()))
        self.assertEqual(dict(self.r)["blocked_at"], "s2")

    def test_an_unknown_key_still_raises_KeyError(self):
        with self.assertRaises(KeyError):
            self.r["no_such_field"]

    def test_to_dict_round_trips_for_logging(self):
        d = self.r.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["overall_verdict"], "SEMANTIC_BLOCK")

    # ── the two rules the dict had, kept exactly ─────────────────────────────

    def test_the_synthetic_key_is_absent_on_a_parsed_result(self):
        """A server must not be able to claim the local-origin marker."""
        self.assertNotIn("_synthetic", self.r)
        self.assertNotIn("_synthetic", self.r.to_dict())
        with self.assertRaises(KeyError):
            self.r["_synthetic"]
        # …even when the wire tries to set it. verify_chain strips it, and
        # `_parse_chain` does not read it either — two independent refusals.
        self.assertNotIn("_synthetic", _parse_chain(_wire(_synthetic=True)))

    def test_the_synthetic_key_is_present_and_true_on_a_degraded_result(self):
        fake = Arcezia._degrade_chain("review", ConnectionError("down"))
        self.assertIn("_synthetic", fake)
        self.assertTrue(fake["_synthetic"])
        self.assertEqual(fake["overall_verdict"], "REVIEW_REQUIRED")
        self.assertEqual(fake["steps"], [])
        self.assertEqual(fake["final_state"], {})


# ── 4. Proof: no documented example breaks ───────────────────────────────────

_SUBSCRIPT = re.compile(r'\bresult\[\s*"(\w+)"\s*\]')


def _documented_chain_snippets() -> "list[tuple[str, str]]":
    """(label, source) for every shipped place that teaches chain access.

    The six adapter docstrings, the package docstring, and the README. Read
    from the files as shipped, so this cannot drift from what a user is told.
    """
    found = []
    for path in sorted((ROOT / "arcezia").rglob("*.py")):
        if "__pycache__" in str(path):
            continue
        text = path.read_text()
        if "verify_chain" not in text:
            continue
        found.append((str(path.relative_to(ROOT)), text))
    readme = ROOT / "README.md"
    for i, block in enumerate(re.findall(r"```python\n(.*?)```", readme.read_text(),
                                         re.S)):
        if "verify_chain" in block:
            found.append((f"README.md block {i}", block))
    return found


class TestEveryDocumentedExampleStillRuns(unittest.TestCase):

    def test_the_examples_were_actually_found(self):
        labels = [lbl for lbl, _ in _documented_chain_snippets()]
        # Six adapter docstrings + the package docstring + the README block.
        for expected in ("arcezia/__init__.py", "README.md block",
                         "arcezia/integrations/anthropic.py",
                         "arcezia/integrations/autogen.py",
                         "arcezia/integrations/langchain.py",
                         "arcezia/integrations/llamaindex.py",
                         "arcezia/integrations/openai.py",
                         "arcezia/integrations/openclaw.py"):
            self.assertTrue(any(expected in lbl for lbl in labels),
                            f"no chain example found in {expected}")

    def test_every_subscript_any_doc_teaches_resolves_on_both_result_kinds(self):
        """The measurement. Every `result["..."]` in shipped documentation,
        evaluated against a real result and a synthetic one."""
        keys = set()
        for label, text in _documented_chain_snippets():
            for m in _SUBSCRIPT.finditer(text):
                keys.add((label, m.group(1)))
        self.assertTrue(keys, "no documented subscripts were extracted")

        real = _parse_chain(_wire())
        degraded = Arcezia._degrade_chain("fail_open", ConnectionError("down"))
        for label, key in sorted(keys):
            with self.subTest(where=label, key=key):
                if key == "_synthetic":
                    # Documented as present only on the local fallback.
                    self.assertTrue(degraded[key])
                    continue
                real[key]        # KeyError here = a documented example broke
                degraded[key]

    def test_the_canonical_documented_gate_runs_verbatim(self):
        """The exact five lines the README teaches, executed."""
        aborted = []

        def abort(step):
            aborted.append(step)

        for result in (_parse_chain(_wire()),
                       Arcezia._degrade_chain("review", ConnectionError("d"))):
            aborted.clear()
            if result["overall_verdict"] != "SAFE":
                step = result["blocked_at"] or next(
                    (s["id"] for s in result["steps"] if s["verdict"] != "ALLOW"),
                    None,
                )
                abort(step)
            self.assertEqual(len(aborted), 1)
        # The real one names the blocking step; the degraded one has no steps
        # to name, and says None rather than inventing one.
        self.assertEqual(_parse_chain(_wire())["blocked_at"], "s2")

    def test_verify_chain_returns_the_typed_result_not_a_dict(self):
        from unittest.mock import patch
        az = Arcezia(api_key="ar_test_x", task="t")
        with patch("arcezia.client._post") as post:
            post.side_effect = lambda url, *a, **k: (
                (200, {"session_id": "sess-1"}) if url.endswith("/v1/session")
                else (200, _wire())
            )
            result = az.verify_chain({"steps": []})
        self.assertIsInstance(result, ArceziaChainResult)
        self.assertEqual(result["overall_verdict"], "SEMANTIC_BLOCK")
        self.assertEqual(result.blocked_at, "s2")


if __name__ == "__main__":
    unittest.main()
