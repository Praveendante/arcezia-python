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

    @property
    def allow(self): return self.verdict == "ALLOW"
    @property
    def block(self): return self.verdict == "BLOCK"
    @property
    def review(self): return self.verdict == "REVIEW"
    @property
    def degraded(self): return self.credential is None and self.trust_score == 0


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
        for tool in ("Read", "Grep", "Glob", "LS", "WebSearch"):
            self.assertIsNone(cc.map_tool(tool, {"any": "x"}))

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
