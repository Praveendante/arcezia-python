"""
Pinned tests for the A5 audit findings (client SDK partition).

One test per finding id. Each asserts the DIRECTION of the fix — an unknown
case fails closed — rather than the enumerated list of cases the audit happened
to try, so a new spelling of the same absence cannot pass.
"""
from __future__ import annotations

import asyncio
import io
import json
import sys
from typing import Any, ClassVar

import pytest

from arcezia.client import ArceziaCertificate
from arcezia.integrations import _common
from arcezia.integrations.openai import ArceziaCrewTool


# ── a verifier that refuses everything, and counts ───────────────────────────

class _BlockingAz:
    _on_error = "fail_closed"

    def __init__(self):
        self.calls = 0
        self.descriptions: list[str] = []

    def verify(self, **kw):
        self.calls += 1
        self.descriptions.append(kw.get("action_description", ""))
        return ArceziaCertificate(
            verdict="BLOCK", status="BLOCKED", precondition_score=0.0,
            trust_score=0.0, summary="blocked", violated=["x"], missing=[],
            fabrication_detected=False, fabricated_constraints=[], constraints=[],
            signature="s", credential=None, raw={"chain_status": "CLEAR"},
            chain_status="CLEAR",
        )


# ── A5-1 — the async execution entry point is gated like its sync twin ───────

class TestA5_1AsyncCrewToolIsGated:
    def _tool(self):
        az = _BlockingAz()
        ran = {"n": 0}

        class T(ArceziaCrewTool):
            az: ClassVar[Any] = None
            domain: ClassVar[str] = "database_ops"
            name = "execute_sql"

            def _run(self, sql: str) -> str:
                ran["n"] += 1
                return "SYNC RAN"

            async def _arun(self, sql: str) -> str:
                ran["n"] += 1
                return "ASYNC RAN"

        T.az = az
        return T(), az, ran

    def test_arun_is_gated(self):
        tool, az, ran = self._tool()
        with pytest.raises(RuntimeError):
            asyncio.run(tool.arun(sql="DELETE FROM users"))
        assert az.calls == 1
        assert ran["n"] == 0

    def test_private_arun_is_gated(self):
        tool, az, ran = self._tool()
        with pytest.raises(RuntimeError):
            asyncio.run(tool._arun(sql="DELETE FROM users"))
        assert az.calls == 1
        assert ran["n"] == 0

    def test_sync_twin_still_gated(self):
        tool, az, ran = self._tool()
        for call in (lambda: tool.run(sql="x"), lambda: tool._run(sql="x")):
            az.calls = 0
            ran["n"] = 0
            with pytest.raises(RuntimeError):
                call()
            assert az.calls == 1 and ran["n"] == 0

    def test_every_declared_entry_point_is_gated(self):
        """The direction: the gate covers the LIST, not two hand-written cases."""
        tool, az, ran = self._tool()
        for name in _openai_module()._GATED_ENTRY_POINTS:
            attr = getattr(tool, name)
            assert getattr(attr, "_arcezia_gated", False), f"{name} is not gated"

    def test_a_tool_implementing_neither_still_raises_not_implemented(self):
        az = _BlockingAz()

        class Empty(ArceziaCrewTool):
            az: ClassVar[Any] = None
            name = "nothing"

        Empty.az = az
        with pytest.raises(NotImplementedError):
            Empty().run(x=1)
        assert az.calls == 0, "a tool that cannot run must not spend a verification"


def _openai_module():
    from arcezia.integrations import openai as _m
    return _m


# ── A5-18 — the gate holds however `_run` arrived ────────────────────────────

class TestA5_18LateBoundRunIsGated:
    def _late(self):
        az = _BlockingAz()
        ran = {"n": 0}

        class Late(ArceziaCrewTool):
            az: ClassVar[Any] = None
            domain: ClassVar[str] = "database_ops"
            name = "execute_sql"

            def _run(self, sql: str) -> str:
                return "original"

        Late.az = az

        def late_impl(self, sql: str) -> str:
            ran["n"] += 1
            return "LATE RAN"

        Late._run = late_impl          # assigned AFTER the class body
        return Late(), az, ran

    def test_late_bound_run_through_run(self):
        tool, az, ran = self._late()
        with pytest.raises(RuntimeError):
            tool.run(sql="anything")
        assert az.calls == 1 and ran["n"] == 0

    def test_late_bound_run_called_directly(self):
        """Access time, not definition time: fetching `_run` yields a gated callable."""
        tool, az, ran = self._late()
        with pytest.raises(RuntimeError):
            tool._run(sql="anything")
        assert az.calls == 1 and ran["n"] == 0

    def test_instance_level_assignment_is_gated(self):
        tool, az, ran = self._late()
        tool.__dict__["_run"] = lambda **kw: ran.__setitem__("n", ran["n"] + 1)
        with pytest.raises(RuntimeError):
            tool.run(sql="anything")
        assert az.calls == 1 and ran["n"] == 0

    def test_gate_fires_exactly_once_for_a_class_body_run(self):
        az = _BlockingAz()

        class T(ArceziaCrewTool):
            az: ClassVar[Any] = None
            name = "t"

            def _run(self, **kw) -> str:
                return "ran"

        T.az = az
        with pytest.raises(RuntimeError):
            T().run(x=1)
        assert az.calls == 1, "a gated _run must not be verified twice"


# ── A5-5 — one description, every argument, a visible clip ───────────────────

class TestA5_5Describe:
    def test_every_argument_reaches_the_engine(self):
        desc = _common.describe(
            "run_sql", (), {"table": "users", "where": "1=1; DELETE FROM users"},
            priority=_common.ACTION_KEYS)
        assert "DELETE FROM users" in desc
        assert "users" in desc

    def test_a_long_single_argument_is_not_clipped_at_eighty(self):
        payload = "x" * 240 + "; DROP TABLE users"
        desc = _common.describe("run_sql", (payload,))
        assert "DROP TABLE users" in desc
        assert _common.TRUNCATION_MARKER not in desc

    def test_a_clip_is_announced_and_stays_within_budget(self):
        desc = _common.describe(
            "write_file", (), {"content": "y" * (_common.DESCRIBE_BUDGET * 2)})
        assert _common.TRUNCATION_MARKER in desc
        assert len(desc) <= _common.DESCRIBE_BUDGET

    def test_the_small_argument_survives_a_huge_sibling(self):
        """A path rule must still see the path when `content` is 100 KB."""
        desc = _common.describe(
            "write_file", (),
            {"file_path": "/etc/shadow", "content": "z" * (_common.DESCRIBE_BUDGET * 2)},
            priority=_common.ACTION_KEYS)
        assert "/etc/shadow" in desc
        assert _common.TRUNCATION_MARKER in desc

    def test_budget_and_marker_match_the_engine_side_copy(self):
        """Two copies of one contract must agree, or a clip is only half seen."""
        assert _common.DESCRIBE_BUDGET == 32768
        assert _common.TRUNCATION_MARKER == "[TRUNCATED"
        clipped = _common._clip("a" * 100, 50)
        assert clipped.endswith("]")
        assert " [TRUNCATED " in clipped

    def test_crew_tool_describes_all_arguments(self):
        az = _BlockingAz()

        class T(ArceziaCrewTool):
            az: ClassVar[Any] = None
            name = "run_sql"

            def _run(self, **kw) -> str:
                return "ran"

        T.az = az
        with pytest.raises(RuntimeError):
            T().run(table="users", where="1=1; DELETE FROM users WHERE 1=1")
        assert "DELETE FROM users" in az.descriptions[0]


# ── A5-2 — the hook always exits 0 carrying a decision ───────────────────────

class TestA5_2HookAlwaysDecides:
    def test_verifier_construction_failure_becomes_deny(self, monkeypatch):
        import arcezia.integrations.claude_code as cc
        monkeypatch.setattr(
            cc, "_default_verifier",
            lambda: (_ for _ in ()).throw(RuntimeError("unreachable")))
        out = cc.run_hook(json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}))
        decision = out["hookSpecificOutput"]["permissionDecision"]
        assert decision == "deny"

    @pytest.mark.parametrize("failure", [
        RuntimeError("outage"), ValueError("bad ARCEZIA_API_URL"),
        KeyboardInterrupt(), MemoryError(),
    ])
    def test_main_exits_zero_with_a_deny_on_any_failure(self, monkeypatch, capsys, failure):
        import arcezia.integrations.claude_code as cc

        def _boom(*a, **k):
            raise failure

        monkeypatch.setattr(cc, "run_hook", _boom)
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": "x"}})))
        rc = cc.main([])
        assert rc == 0, "a non-zero exit is a NON-BLOCKING error: the tool runs"
        out = json.loads(capsys.readouterr().out)
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_non_object_payload_denies_instead_of_crashing(self):
        import arcezia.integrations.claude_code as cc
        for stdin_text in ("[]", "null", '"x"', "3"):
            out = cc.run_hook(stdin_text)
            assert out["hookSpecificOutput"]["permissionDecision"] in ("deny", "ask")

    def test_hook_command_names_the_interpreter_not_bare_python(self):
        import arcezia.integrations.claude_code as cc
        cmd = cc._hook_command()
        assert not cmd.startswith("python "), (
            "a bare `python` is resolved by the harness PATH, not by the "
            "interpreter arcezia is installed into")
        assert ("arcezia-hook" in cmd) or (sys.executable in cmd)


# ── A5-12 — install() never overwrites an unparseable settings.json ──────────

class TestA5_12Install:
    _PRIOR = (
        '{ // my notes\n'
        '  "permissions": {"allow": ["Bash(git:*)"], "deny": ["Bash(curl:*)"]},\n'
        '  "env": {"FOO": "bar"} }\n'
    )

    def test_parse_error_refuses_and_leaves_the_file_untouched(self, tmp_path):
        import arcezia.integrations.claude_code as cc
        path = tmp_path / "settings.json"
        path.write_text(self._PRIOR)
        with pytest.raises(ValueError) as ctx:
            cc.install(str(path))
        assert str(path) in str(ctx.value)
        assert path.read_text() == self._PRIOR, "the user's deny rules survived"

    def test_a_json_non_object_is_also_refused(self, tmp_path):
        import arcezia.integrations.claude_code as cc
        path = tmp_path / "settings.json"
        path.write_text("[1, 2, 3]")
        with pytest.raises(ValueError):
            cc.install(str(path))
        assert path.read_text() == "[1, 2, 3]"

    def test_a_real_write_keeps_a_backup_and_merges(self, tmp_path):
        import arcezia.integrations.claude_code as cc
        path = tmp_path / "settings.json"
        prior = {"permissions": {"deny": ["Bash(curl:*)"]}, "env": {"FOO": "bar"}}
        path.write_text(json.dumps(prior))
        cc.install(str(path))
        after = json.loads(path.read_text())
        assert after["permissions"]["deny"] == ["Bash(curl:*)"]
        assert after["env"] == {"FOO": "bar"}
        assert after["hooks"]["PreToolUse"]
        backups = list(tmp_path.glob("settings.json.bak-*"))
        assert backups and json.loads(backups[0].read_text()) == prior

    def test_install_is_idempotent(self, tmp_path):
        import arcezia.integrations.claude_code as cc
        path = tmp_path / "settings.json"
        cc.install(str(path))
        cc.install(str(path))
        hooks = json.loads(path.read_text())["hooks"]["PreToolUse"]
        commands = [h["command"] for e in hooks for h in e["hooks"]]
        assert len(commands) == 1


# ── A5-10 — the verifier's address is checked on its value ───────────────────

class TestA5_10BaseUrlGuard:
    LOCAL_SPELLINGS = [
        "http://127.0.0.2:8000",
        "http://[::ffff:127.0.0.1]:8000",
        "http://2130706433:8000",
        "http://0x7f000001:8000",
        "http://169.254.169.254",
        "http://10.0.0.5",
        "http://192.168.1.1",
        "https://127.0.0.1",
    ]

    @pytest.mark.parametrize("url", LOCAL_SPELLINGS)
    def test_every_spelling_of_a_local_address_is_refused(self, url):
        from arcezia.client import Arcezia
        with pytest.raises(ValueError):
            Arcezia(api_key="ar_live_somekey", api_url=url)

    @pytest.mark.parametrize("url", LOCAL_SPELLINGS)
    def test_an_unrecognised_key_shape_is_treated_as_live(self, url):
        """"Not ar_test_" is live — the guard used to key on the ar_live_ prefix."""
        from arcezia.client import Arcezia
        with pytest.raises(ValueError):
            Arcezia(api_key="ar_key_othershape", api_url=url)

    def test_plaintext_http_is_refused_for_a_live_key(self):
        from arcezia.client import Arcezia
        with pytest.raises(ValueError) as ctx:
            Arcezia(api_key="ar_live_somekey", api_url="http://example.com")
        assert "https" in str(ctx.value)

    def test_an_unresolvable_host_is_refused_not_assumed_safe(self):
        from arcezia.client import Arcezia
        with pytest.raises(ValueError) as ctx:
            Arcezia(api_key="ar_live_somekey",
                    api_url="https://no-such-host.invalid")
        assert "resolve" in str(ctx.value)

    def test_test_keys_keep_local_development(self):
        from arcezia.client import Arcezia
        assert Arcezia(api_key="ar_test_localdev", api_url="http://localhost:8000")
        assert Arcezia(api_key="ar_test_localdev", api_url="http://127.0.0.1:8000")


# ── A5-16 — the async dispatch wrapper actually runs the upstream ────────────

def test_a5_16_async_wrap_awaits_the_upstream():
    from arcezia.integrations.openclaw import DispatchGuard

    class _AllowAz:
        _on_error = "fail_closed"

        def verify(self, **kw):
            return ArceziaCertificate(
                verdict="ALLOW", status="SAFE", precondition_score=1.0,
                trust_score=1.0, summary="ok", violated=[], missing=[],
                fabrication_detected=False, fabricated_constraints=[],
                constraints=[], signature="s",
                credential={"token": "t", "expires_at": 0, "action_type": "x"},
                raw={"chain_status": "CLEAR"}, chain_status="CLEAR",
            )

    ran = {"n": 0}

    async def real_dispatch(tool_name, args, **kw):
        ran["n"] += 1
        return f"ran {tool_name}"

    wrapped = DispatchGuard.wrap(real_dispatch, az=_AllowAz(), domain="agent_action")
    result = asyncio.run(wrapped("write_file", {"path": "/tmp/x"}))
    assert ran["n"] == 1, "the upstream dispatch never executed"
    assert result == "ran write_file", f"got {result!r} — an un-awaited coroutine?"


# ── A5-17 — the documented co-inheritance form is the one that works ─────────

def test_a5_17_docstring_shows_the_annotated_classvar_form():
    doc = ArceziaCrewTool.__doc__ or ""
    assert "ArceziaCrewTool, CrewBaseTool" in doc
    assert "az: ClassVar[Any]" in doc, (
        "the un-annotated form raises PydanticUserError on current CrewAI")
    assert "domain: ClassVar[str]" in doc


# ── Sibling sweep (Law Ω / Law P) — an unrecognised verdict never executes ───
#
# Every adapter reached its ALLOW by ELIMINATION: "not block, not review, not
# degraded". A verdict that is none of the three satisfied none of the tests and
# ran the tool. That is the same inversion A5-3 and A5-4 named in the n8n node
# and the MCP proxy; these are the Python instances of it.

_UNRECOGNISED = ["", "allow", "Allow", "ALLOWED", "SEMANTIC_BLOCK", "OK",
                 "PASS", "UNKNOWN_STATE_2031"]

_DESTRUCTIVE = "DELETE FROM users WHERE 1=1"


def _cert_with(verdict: str) -> ArceziaCertificate:
    return ArceziaCertificate(
        verdict=verdict, status="?", precondition_score=1.0, trust_score=1.0,
        summary="s", violated=[], missing=[], fabrication_detected=False,
        fabricated_constraints=[], constraints=[], signature="s",
        credential={"token": "t", "expires_at": 0, "action_type": "x"},
        raw={"chain_status": "CLEAR"}, chain_status="CLEAR",
    )


@pytest.mark.parametrize("verdict", _UNRECOGNISED)
def test_sibling_refuse_unless_clean_refuses_an_unrecognised_verdict(verdict):
    from arcezia.client import ArceziaBlockError
    with pytest.raises(ArceziaBlockError):
        _common.refuse_unless_clean(_cert_with(verdict))


def test_sibling_a_declared_review_passthrough_still_works():
    """REVIEW reaches this helper only by an operator's declared choice."""
    _common.refuse_unless_clean(_cert_with("REVIEW"))
    _common.refuse_unless_clean(_cert_with("ALLOW"))


@pytest.mark.parametrize("verdict", _UNRECOGNISED)
def test_sibling_claude_code_hook_denies_an_unrecognised_verdict(verdict):
    import arcezia.integrations.claude_code as cc

    class _V:
        def verify(self, **kw):
            return _cert_with(verdict)

    out = cc.run_hook(
        json.dumps({"tool_name": "Bash", "tool_input": {"command": "shred /etc"}}),
        verifier=_V())
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("verdict", _UNRECOGNISED)
def test_sibling_openclaw_hook_blocks_an_unrecognised_verdict(verdict):
    from arcezia.integrations.openclaw import run_cli_hook

    class _G:
        def _verify(self, tool_name, args, *, domain=None):
            return _cert_with(verdict)

    out = run_cli_hook(json.dumps({"tool": "write_file", "args": {}}), verifier=_G())
    assert out["decision"] == "block"


@pytest.mark.parametrize("verdict", _UNRECOGNISED)
def test_sibling_universal_guard_does_not_execute_on_an_unrecognised_verdict(verdict):
    from arcezia.client import ArceziaBlockError
    from arcezia.integrations.universal import guard_callable

    ran = {"n": 0}

    class _Az:
        _on_error = "fail_closed"

        def verify(self, **kw):
            return _cert_with(verdict)

    def tool(**kw):
        ran["n"] += 1
        return "ran"

    guarded = guard_callable(tool, az=_Az(), domain="database_ops")
    with pytest.raises(ArceziaBlockError):
        guarded(sql=_DESTRUCTIVE)
    assert ran["n"] == 0


def test_sibling_openai_wrap_function_handles_the_async_twin():
    """A sync wrapper over a coroutine function returns an un-awaited coroutine."""
    from arcezia.integrations.openai import ArceziaGuard

    ran = {"n": 0}

    class _Az:
        _on_error = "fail_closed"

        def verify(self, **kw):
            return _cert_with("ALLOW")

    async def real(**kw):
        ran["n"] += 1
        return "ran"

    guard = ArceziaGuard(_Az())
    wrapped = guard.wrap_function("do_thing", real, domain="agent_action")
    assert asyncio.iscoroutinefunction(wrapped)
    assert asyncio.run(wrapped(x=1)) == "ran"
    assert ran["n"] == 1


def test_sibling_unreadable_capability_envelope_is_not_an_absent_one(tmp_path, monkeypatch):
    """An envelope's False axes are DENIALS; dropping them widens authority."""
    import arcezia.integrations.claude_code as cc
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "arcezia.json").write_text("{ not json ")
    monkeypatch.setenv("HOME", str(home))
    with pytest.raises(RuntimeError) as ctx:
        cc._load_capability_envelope()
    assert "authority" in str(ctx.value)

    # Absent file stays an honest absence.
    (home / ".claude" / "arcezia.json").unlink()
    assert cc._load_capability_envelope() is None
