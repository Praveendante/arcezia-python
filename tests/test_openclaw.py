"""Tests for the OpenCLAW dispatch guard."""
from __future__ import annotations

import asyncio
import json
import pytest
from unittest.mock import MagicMock, patch


def _cert(verdict: str, fabricated: bool = False):
    from arcezia.client import ArceziaCertificate
    # Production-like: trust_score > 0 for all real engine verdicts.
    # trust_score=0 + credential=None is ONLY for synthetic degraded certs
    # (engine unreachable). REVIEW from the engine IS a real verdict.
    return ArceziaCertificate(
        verdict=verdict,
        status={"ALLOW": "ALLOWED", "BLOCK": "BLOCKED", "REVIEW": "INSUFFICIENT_EVIDENCE"}[verdict],
        precondition_score=1.0 if verdict == "ALLOW" else 0.5,
        trust_score=1.0 if verdict == "ALLOW" else 0.5,
        summary=f"{verdict} test",
        violated=[] if verdict != "BLOCK" else ["test_constraint"],
        missing=[],
        fabrication_detected=fabricated,
        fabricated_constraints=[],
        constraints=[],
        signature="sig",
        credential={"token": "cred"} if verdict == "ALLOW" else None,
    )


def _make_guard(verdict: str, **kwargs):
    from arcezia.integrations.openclaw import DispatchGuard
    guard = DispatchGuard(api_key="ar_test_key", task="test task", **kwargs)
    guard._client = MagicMock()
    guard._client.verify.return_value = _cert(verdict)
    return guard


class TestDispatchGuardSync:
    def test_allow_returns_cert_without_fn(self):
        guard = _make_guard("ALLOW")
        result = guard.dispatch("read_file", {"path": "/tmp/a.txt"})
        assert result.allow

    def test_allow_calls_fn(self):
        guard = _make_guard("ALLOW")
        called = []
        def fn(**kwargs):
            called.append(kwargs)
            return "ok"
        result = guard.dispatch("read_file", {"path": "/tmp"}, fn=fn)
        assert result == "ok"
        assert called == [{"path": "/tmp"}]

    def test_block_raises(self):
        from arcezia.client import ArceziaBlockError
        guard = _make_guard("BLOCK")
        with pytest.raises(ArceziaBlockError):
            guard.dispatch("write_file", {"path": "/etc/passwd"})

    def test_review_raises_by_default(self):
        from arcezia.client import ArceziaReviewError
        guard = _make_guard("REVIEW")
        with pytest.raises(ArceziaReviewError):
            guard.dispatch("delete_file", {"path": "/data"})

    def test_review_passthrough_when_block_false(self):
        guard = _make_guard("REVIEW", block_on_review=False)
        result = guard.dispatch("delete_file", {"path": "/data"})
        assert result.review

    def test_review_handler_allow(self):
        guard = _make_guard("REVIEW")
        guard._review_handler = lambda cert: True
        guard._client.verify.return_value = _cert("REVIEW")
        result = guard.dispatch("delete_file", {"path": "/data"})
        assert result.review

    def test_review_handler_block(self):
        from arcezia.client import ArceziaBlockError
        guard = _make_guard("REVIEW")
        guard._review_handler = lambda cert: False
        with pytest.raises(ArceziaBlockError):
            guard.dispatch("delete_file", {"path": "/data"})

    def test_active_permissions_recorded_on_allow(self):
        guard = _make_guard("ALLOW", domain="filesystem_ops")
        guard.dispatch("write_file", {"path": "/tmp/x"})
        assert any("write_file" in k for k in guard.active_permissions)

    def test_evidence_provider_called(self):
        calls = []
        def evidence(tool, args):
            calls.append((tool, args))
            return {"file_is_in_sandbox": True}
        guard = _make_guard("ALLOW", evidence_provider=evidence)
        guard.dispatch("write_file", {"path": "/tmp/x"})
        assert calls == [("write_file", {"path": "/tmp/x"})]
        # evidence passed to verify
        _, kwargs = guard._client.verify.call_args
        assert kwargs.get("agent_evidence") == {"file_is_in_sandbox": True}

    def test_evidence_provider_failure_does_not_block(self):
        def bad_evidence(tool, args):
            raise RuntimeError("probe down")
        guard = _make_guard("ALLOW", evidence_provider=bad_evidence)
        result = guard.dispatch("write_file", {"path": "/tmp/x"})
        assert result.allow  # evidence failure = Ω, not a block


class TestDispatchGuardAsync:
    def test_async_allow(self):
        guard = _make_guard("ALLOW")

        async def run():
            return await guard.adispatch("write_file", {"path": "/tmp/x"})

        result = asyncio.run(run())
        assert result.allow

    def test_async_block(self):
        from arcezia.client import ArceziaBlockError
        guard = _make_guard("BLOCK")

        async def run():
            return await guard.adispatch("write_file", {"path": "/etc/passwd"})

        with pytest.raises(ArceziaBlockError):
            asyncio.run(run())


class TestWrap:
    def test_wrap_gates_sync_dispatch(self):
        from arcezia.integrations.openclaw import DispatchGuard

        executed = []
        def original_dispatch(tool_name, args):
            executed.append(tool_name)
            return f"ok:{tool_name}"

        mock_client = MagicMock()
        mock_client.verify.return_value = _cert("ALLOW")

        with patch("arcezia.integrations.openclaw.coerce_az", return_value=mock_client):
            safe_dispatch = DispatchGuard.wrap(original_dispatch, api_key="ar_test_k", task="t")

        safe_dispatch("write_file", {"path": "/tmp/x"})
        assert "write_file" in executed

    def test_wrap_blocks_do_not_call_original(self):
        from arcezia.client import ArceziaBlockError
        from arcezia.integrations.openclaw import DispatchGuard

        executed = []
        def original_dispatch(tool_name, args):
            executed.append(tool_name)

        mock_client = MagicMock()
        mock_client.verify.return_value = _cert("BLOCK")

        with patch("arcezia.integrations.openclaw.coerce_az", return_value=mock_client):
            safe_dispatch = DispatchGuard.wrap(original_dispatch, api_key="ar_test_k", task="t")

        with pytest.raises(ArceziaBlockError):
            safe_dispatch("drop_table", {"table": "users"})
        assert executed == []


class TestCLIHook:
    def test_allow_decision(self):
        from arcezia.integrations.openclaw import run_cli_hook, DispatchGuard
        guard = _make_guard("ALLOW")
        payload = json.dumps({"tool": "write_file", "args": {"path": "/tmp/x", "content": "hi"}})
        result = run_cli_hook(payload, verifier=guard)
        assert result["decision"] == "allow"

    def test_block_decision(self):
        from arcezia.integrations.openclaw import run_cli_hook
        guard = _make_guard("BLOCK")
        result = run_cli_hook(json.dumps({"tool": "drop_table", "args": {"table": "users"}}), verifier=guard)
        assert result["decision"] == "block"

    def test_review_decision(self):
        from arcezia.integrations.openclaw import run_cli_hook
        guard = _make_guard("REVIEW")
        result = run_cli_hook(json.dumps({"tool": "delete_all_records", "args": {}}), verifier=guard)
        assert result["decision"] == "review"

    # ── A5-14 ────────────────────────────────────────────────────────────────
    # These three used to answer "review". "review" is a NON-REFUSAL in a
    # protocol whose host behaviour this module does not define — it names no
    # host, so it cannot assume one holds the action — and a missing API key is
    # not a held action, it is an UNGATED one. The sibling claude_code hook
    # answers the same three with a decision its host enforces. One question,
    # one policy: every absence blocks, and the reason says which absence.

    def test_a5_14_malformed_json_blocks(self):
        from arcezia.integrations.openclaw import run_cli_hook
        result = run_cli_hook("not json at all")
        assert result["decision"] == "block"
        assert "parse" in result["reason"].lower()

    def test_a5_14_no_api_key_blocks(self, monkeypatch):
        monkeypatch.delenv("ARCEZIA_API_KEY", raising=False)
        from arcezia.integrations.openclaw import run_cli_hook
        result = run_cli_hook(json.dumps({"tool": "write_file", "args": {}}))
        assert result["decision"] == "block"
        assert "ARCEZIA_API_KEY" in result["reason"]

    def test_a5_14_no_tool_name_blocks(self):
        from arcezia.integrations.openclaw import run_cli_hook
        result = run_cli_hook(json.dumps({"args": {"path": "/etc/passwd"}}))
        assert result["decision"] == "block"

    def test_a5_14_every_absence_blocks_and_review_is_only_a_verdict(self, monkeypatch):
        """The direction: "review" is reachable only from an engine REVIEW.

        Asserted over a set of malformed payloads rather than the three the
        audit named, so a new way to be absent cannot quietly become a
        non-refusal.
        """
        monkeypatch.delenv("ARCEZIA_API_KEY", raising=False)
        from arcezia.integrations.openclaw import run_cli_hook
        for stdin_text in ("", "   ", "not json", "[]", "null", "{}",
                           json.dumps({"args": {}}),
                           json.dumps({"tool": ""}),
                           json.dumps({"tool": "write_file"})):
            result = run_cli_hook(stdin_text)
            assert result["decision"] == "block", f"{stdin_text!r} → {result}"
            assert result.get("reason")

    def test_a5_14_verifier_construction_failure_blocks(self, monkeypatch):
        """Building the verifier is part of verifying (the A5-2 shape here)."""
        import arcezia.integrations.openclaw as oc
        monkeypatch.setattr(
            oc, "_default_guard",
            lambda: (_ for _ in ()).throw(ValueError("bad ARCEZIA_API_URL")))
        result = oc.run_cli_hook(json.dumps({"tool": "write_file", "args": {}}))
        assert result["decision"] == "block"
        assert "bad ARCEZIA_API_URL" in result["reason"]
