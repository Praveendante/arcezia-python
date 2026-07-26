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

    def test_malformed_json_returns_review(self):
        from arcezia.integrations.openclaw import run_cli_hook
        result = run_cli_hook("not json at all")
        assert result["decision"] == "review"

    def test_no_api_key_returns_review(self, monkeypatch):
        monkeypatch.delenv("ARCEZIA_API_KEY", raising=False)
        from arcezia.integrations.openclaw import run_cli_hook
        result = run_cli_hook(json.dumps({"tool": "write_file", "args": {}}))
        assert result["decision"] == "review"
