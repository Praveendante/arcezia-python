"""Tests for the n8n workflow helper."""
from __future__ import annotations

import json
import pytest


def test_build_verify_body_minimal():
    from arcezia.integrations.n8n import build_verify_body
    body = build_verify_body(
        task="clean up logs",
        action_type="delete_file",
        action_description="delete /var/log/old.log",
    )
    assert body["task"] == "clean up logs"
    assert body["action_type"] == "delete_file"
    assert body["domain"] == "agent_action"
    assert "session_id" not in body


def test_build_verify_body_full():
    from arcezia.integrations.n8n import build_verify_body
    body = build_verify_body(
        task="deploy app",
        action_type="run_deploy",
        action_description="deploy to prod",
        domain="deployment_ops",
        session_id="sess-123",
        agent_evidence={"env_is_staging": False},
    )
    assert body["domain"] == "deployment_ops"
    assert body["session_id"] == "sess-123"
    assert body["agent_evidence"] == {"env_is_staging": False}


def test_code_snippet_is_javascript():
    from arcezia.integrations.n8n import n8n_code_snippet
    snippet = n8n_code_snippet(domain="filesystem_ops")
    assert "filesystem_ops" in snippet
    assert "$input" in snippet  # n8n expression


def test_workflow_template_is_valid_json():
    from arcezia.integrations.n8n import workflow_template
    raw = workflow_template()
    data = json.loads(raw)
    assert data["name"] == "Arcezia Gate Template"
    assert len(data["nodes"]) > 0


def test_workflow_template_contains_verify_node():
    from arcezia.integrations.n8n import workflow_template
    data = json.loads(workflow_template())
    names = {n["name"] for n in data["nodes"]}
    assert "Arcezia Verify" in names
    assert "Route on Verdict" in names
    assert "Wait for Human Approval" in names


def test_workflow_template_custom_url():
    from arcezia.integrations.n8n import workflow_template
    data = json.loads(workflow_template(arcezia_api_url="http://localhost:8000"))
    verify_node = next(n for n in data["nodes"] if n["name"] == "Arcezia Verify")
    assert "localhost:8000" in verify_node["parameters"]["url"]


def test_save_template(tmp_path):
    from arcezia.integrations.n8n import save_template
    out = save_template(str(tmp_path / "wf.json"))
    assert (tmp_path / "wf.json").exists()
    data = json.loads((tmp_path / "wf.json").read_text())
    assert "nodes" in data
