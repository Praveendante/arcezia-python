"""
Arcezia ⨉ n8n — workflow template and evidence helper.

n8n is a visual workflow automation tool.  Agent tools in n8n are HTTP Request
nodes, Code nodes, or built-in service nodes.  The gate for n8n sits at
the HTTP Request node (or Code node) — the point where the workflow's action
leaves the n8n runtime and touches an external resource.

Coverage caveat — please read before relying on this integration:
    n8n does not expose a harness-level pre-dispatch hook. The Arcezia gate
    must be placed by the workflow AUTHOR as an HTTP Request node before each
    consequential node. This means:
      • Complete gate placement depends on the author following the pattern.
      • A workflow author who skips the gate can bypass verification.
    Mitigation: use `enforce_workflow_gate` on the server to audit that every
    verify call is followed by a credential step, so ungated paths are visible
    in the audit trail.

Typical pattern (inside n8n workflow):
    1. Arcezia Verify node   →  POST https://api.arcezia.com/v1/verify
    2. Route on verdict:
         "ALLOW"  → proceed to the action node
         "BLOCK"  → route to error / stop node
         "REVIEW" → route to Wait node (pause for human signal)
    3. Human approval (REVIEW path):
         → Approval HTTP Request node: POST /v1/authorize with signed token
         → Continue after approval
    4. Action node (Write file, HTTP Request, etc.)

This module provides:
  • `build_verify_body()` — build the correct request body to POST to /v1/verify
    from an n8n Code node (JavaScript/Python), ready to copy-paste.
  • `workflow_template()` — returns a ready-to-import n8n workflow JSON with the
    Arcezia pre-action gate pattern pre-wired.  Import it in n8n → Settings →
    Import Workflow.

Usage in an n8n Code node (JavaScript mode):
    const body = {
      task:               "{{ $workflow.name }}",
      action_type:        "{{ $json.tool }}",
      action_description: "{{ $json.description }}",
      domain:             "{{ $json.domain || 'agent_action' }}",
      session_id:         "{{ $('Set Session').item.json.session_id }}",
      agent_evidence:     {{ $json.evidence || {} }}
    };

    return [{ json: body }];

The `workflow_template()` function returns a JSON string you can save as
`arcezia_gate.json` and import directly into n8n (Settings → Import Workflow).
"""
from __future__ import annotations

import json
from typing import Optional


# ── verify body builder ────────────────────────────────────────────────────────

def build_verify_body(
    task: str,
    action_type: str,
    action_description: str,
    domain: str = "agent_action",
    session_id: Optional[str] = None,
    agent_evidence: Optional[dict] = None,
) -> dict:
    """
    Build a /v1/verify request body.

    Use this from a Python Code node in n8n, or construct the equivalent in
    JavaScript using n8n expressions (see module docstring).

    Returns a dict ready to pass as the JSON body of an HTTP Request node
    pointing at https://api.arcezia.com/v1/verify.
    """
    body: dict = {
        "task": task,
        "action_type": action_type,
        "action_description": action_description,
        "domain": domain,
    }
    if session_id:
        body["session_id"] = session_id
    if agent_evidence:
        body["agent_evidence"] = agent_evidence
    return body


def n8n_code_snippet(domain: str = "agent_action") -> str:
    """
    Return a JavaScript snippet for an n8n Code node that builds the
    /v1/verify body from upstream node data.  Paste into the Code node.
    """
    return f"""\
// Arcezia pre-action gate — paste into an n8n Code node (JavaScript mode)
// Place this node BEFORE each consequential action node.
const body = {{
  task:               $workflow.name,
  action_type:        $input.item.json.tool || "run_action",
  action_description: $input.item.json.description || JSON.stringify($input.item.json),
  domain:             $input.item.json.domain || "{domain}",
  session_id:         $('Start Session').item.json.session_id || undefined,
  // agent_evidence: CLAIMED quality only. For GROUNDED evidence, register
  // a probe webhook via the Arcezia admin API (POST /v1/probes).
  agent_evidence:     $input.item.json.evidence || undefined,
}};

// Remove undefined keys
Object.keys(body).forEach(k => body[k] === undefined && delete body[k]);

return [{{ json: body }}];
"""


# ── workflow template ──────────────────────────────────────────────────────────

def workflow_template(
    arcezia_api_url: str = "https://api.arcezia.com",
    domain: str = "agent_action",
    name: str = "Arcezia Gate Template",
) -> str:
    """
    Return a ready-to-import n8n workflow JSON.

    Import: n8n UI → Settings (⚙) → Import Workflow → paste this JSON.

    The template includes:
      • Start Session node   (POST /v1/session)
      • Build Verify Body    (Code node, JavaScript)
      • Arcezia Verify       (POST /v1/verify)
      • Route on Verdict     (Switch node: ALLOW / BLOCK / REVIEW)
      • Human Approval Wait  (on REVIEW path)
      • Authorize            (POST /v1/authorize after human approval)
      • Action Placeholder   (replace with your actual action node)
      • Block Handler        (log / stop)

    Wire your upstream trigger → "Build Verify Body" input.
    Replace "Action Placeholder" with your real action node.
    """
    template = {
        "name": name,
        "nodes": [
            {
                "parameters": {
                    "method": "POST",
                    "url": f"{arcezia_api_url}/v1/session",
                    "authentication": "genericCredentialType",
                    "genericAuthType": "httpHeaderAuth",
                    "sendBody": True,
                    "bodyParameters": {
                        "parameters": [
                            {"name": "task", "value": "={{ $workflow.name }}"}
                        ]
                    },
                    "options": {}
                },
                "name": "Start Session",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [250, 300],
                "id": "node-start-session",
                "credentials": {"httpHeaderAuth": {"id": "arcezia-key", "name": "Arcezia API Key"}}
            },
            {
                "parameters": {
                    "jsCode": n8n_code_snippet(domain)
                },
                "name": "Build Verify Body",
                "type": "n8n-nodes-base.code",
                "typeVersion": 2,
                "position": [450, 300],
                "id": "node-build-body"
            },
            {
                "parameters": {
                    "method": "POST",
                    "url": f"{arcezia_api_url}/v1/verify",
                    "authentication": "genericCredentialType",
                    "genericAuthType": "httpHeaderAuth",
                    "sendBody": True,
                    "specifyBody": "json",
                    "jsonBody": "={{ JSON.stringify($json) }}",
                    "options": {}
                },
                "name": "Arcezia Verify",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [650, 300],
                "id": "node-verify",
                "credentials": {"httpHeaderAuth": {"id": "arcezia-key", "name": "Arcezia API Key"}}
            },
            {
                "parameters": {
                    "rules": {
                        "values": [
                            {"conditions": {"options": {"caseSensitive": True}, "combinator": "and", "conditions": [{"leftValue": "={{ $json.verdict }}", "rightValue": "ALLOW", "operator": {"type": "string", "operation": "equals"}}]}, "renameOutput": True, "outputKey": "allow"},
                            {"conditions": {"options": {"caseSensitive": True}, "combinator": "and", "conditions": [{"leftValue": "={{ $json.verdict }}", "rightValue": "BLOCK", "operator": {"type": "string", "operation": "equals"}}]}, "renameOutput": True, "outputKey": "block"},
                            {"conditions": {"options": {"caseSensitive": True}, "combinator": "and", "conditions": [{"leftValue": "={{ $json.verdict }}", "rightValue": "REVIEW", "operator": {"type": "string", "operation": "equals"}}]}, "renameOutput": True, "outputKey": "review"}
                        ]
                    },
                    "options": {}
                },
                "name": "Route on Verdict",
                "type": "n8n-nodes-base.switch",
                "typeVersion": 3,
                "position": [850, 300],
                "id": "node-route"
            },
            {
                "parameters": {
                    "resume": "webhook",
                    "webhookSuffix": "arcezia-approval"
                },
                "name": "Wait for Human Approval",
                "type": "n8n-nodes-base.wait",
                "typeVersion": 1,
                "position": [1050, 450],
                "id": "node-wait",
                "webhookId": "arcezia-approval-webhook"
            },
            {
                "parameters": {
                    "method": "POST",
                    "url": f"{arcezia_api_url}/v1/authorize",
                    "authentication": "genericCredentialType",
                    "genericAuthType": "httpHeaderAuth",
                    "sendBody": True,
                    "bodyParameters": {
                        "parameters": [
                            {"name": "session_id",  "value": "={{ $('Start Session').item.json.session_id }}"},
                            {"name": "token_type",  "value": "user"},
                            {"name": "token",       "value": "={{ $json.approval_token || 'n8n-human-approved' }}"}
                        ]
                    },
                    "options": {}
                },
                "name": "Authorize (Human Approved)",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [1250, 450],
                "id": "node-authorize",
                "credentials": {"httpHeaderAuth": {"id": "arcezia-key", "name": "Arcezia API Key"}}
            },
            {
                "parameters": {
                    "content": "## ❌ Arcezia BLOCK\n**Reason:** {{ $('Arcezia Verify').item.json.summary }}\n\nThis action was blocked by Arcezia safety verification.",
                    "height": 200,
                    "width": 300
                },
                "name": "Block Handler",
                "type": "n8n-nodes-base.stickyNote",
                "typeVersion": 1,
                "position": [1050, 150],
                "id": "node-block-note"
            },
            {
                "parameters": {
                    "content": "🔧 Replace this placeholder with your\nactual action node (HTTP Request, Write\nFile, etc.).\n\nOn the ALLOW path, the arcezia credential\nis available at:\n{{ $('Arcezia Verify').item.json.credential }}",
                    "height": 200,
                    "width": 300
                },
                "name": "Action Placeholder",
                "type": "n8n-nodes-base.stickyNote",
                "typeVersion": 1,
                "position": [1050, 300],
                "id": "node-action-note"
            }
        ],
        "connections": {
            "Start Session": {"main": [[{"node": "Build Verify Body", "type": "main", "index": 0}]]},
            "Build Verify Body": {"main": [[{"node": "Arcezia Verify", "type": "main", "index": 0}]]},
            "Arcezia Verify": {"main": [[{"node": "Route on Verdict", "type": "main", "index": 0}]]},
            "Route on Verdict": {
                "main": [
                    [{"node": "Action Placeholder", "type": "main", "index": 0}],
                    [{"node": "Block Handler", "type": "main", "index": 0}],
                    [{"node": "Wait for Human Approval", "type": "main", "index": 0}]
                ]
            },
            "Wait for Human Approval": {"main": [[{"node": "Authorize (Human Approved)", "type": "main", "index": 0}]]},
            "Authorize (Human Approved)": {"main": [[{"node": "Arcezia Verify", "type": "main", "index": 0}]]}
        },
        "pinData": {},
        "settings": {"executionOrder": "v1"},
        "staticData": None,
        "tags": [{"name": "arcezia"}, {"name": "ai-safety"}],
        "triggerCount": 0,
        "updatedAt": "2026-06-12T00:00:00.000Z",
        "versionId": "arcezia-gate-v1"
    }
    return json.dumps(template, indent=2)


def save_template(path: str = "arcezia_gate_workflow.json", **kwargs) -> str:
    """Write the workflow template to a file. Returns the path."""
    content = workflow_template(**kwargs)
    with open(path, "w") as f:
        f.write(content)
    return path
