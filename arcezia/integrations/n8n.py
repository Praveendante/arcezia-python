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
    There is NO server-side backstop for this today. An action node with no
    check in front of it produces no record at all, so nothing detects it —
    coverage in n8n rests entirely on the workflow author. An earlier version of
    this note claimed an `enforce_workflow_gate` audit existed. It does not; no
    such function was ever written.

    The one structural remedy: make the action's own endpoint require the
    short-lived single-use grant that a successful check issues. A skipped check
    then yields nothing to present, and the action cannot succeed. This works
    where you control the endpoint being called, and not where the action node
    reaches a third party directly.

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
    action_parameters: Optional[dict] = None,
    data_subject_reference: Optional[str] = None,
    data_categories: Optional[list] = None,
) -> dict:
    """
    Build a /v1/verify request body.

    Use this from a Python Code node in n8n, or construct the equivalent in
    JavaScript using n8n expressions (see module docstring).

    Returns a dict ready to pass as the JSON body of an HTTP Request node
    pointing at https://api.arcezia.com/v1/verify.

    data_subject_reference: optional identifier for the person this action is
    about. Record-only — never changes the verdict; enables per-person audit
    lookup via POST /v1/audit/subject. data_categories: optional list of
    personal-data category names the action touches (verdict-tightening only).
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
    if action_parameters:
        # Structured addressing (P2): the typed tool-call arguments (record
        # ids, paths, amounts) — forwarded to probe webhooks AND read by the
        # engine's own probes (e.g. a numeric amount escalates
        # action_is_high_stakes in a way prose rewording cannot evade).
        body["action_parameters"] = action_parameters
    if data_subject_reference is not None:
        # Record-only: names the person the action is about so the decision
        # can be found later per person. Never changes the verdict.
        body["data_subject_reference"] = data_subject_reference
    if data_categories is not None:
        body["data_categories"] = data_categories
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
  // action_parameters: the TYPED tool-call arguments (record ids, paths,
  // amounts). Flat scalar map, max 32 keys. Probe webhooks receive it as
  // `parameters`; the engine's own probes read it too (a numeric amount
  // escalates stakes in a way prose rewording cannot evade).
  action_parameters:  $input.item.json.parameters || undefined,
  // data_subject_reference: who this action is about (your customer id).
  // Record-only — never changes the verdict; lets you look up every decision
  // about that person later via POST /v1/audit/subject.
  data_subject_reference: $input.item.json.data_subject_reference || undefined,
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
        # n8n's CLI importer (`n8n import:workflow`) writes straight to the
        # workflow_entity table, where `id` is NOT NULL — a template without one
        # fails with SQLITE_CONSTRAINT before any node is read. The UI importer
        # generates an id for you; the CLI does not. Verified against n8n 2.32.7.
        "id": "arcezia-gate-template",
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
                    "jsCode": (
                        "// COMPOSITION layer — describe the whole plan before any step runs.\n"
                        "// Each step may be individually legal while the SEQUENCE is not;\n"
                        "// /v1/verify_chain is what catches that.\n"
                        "// NOTE: `domain` goes on EVERY STEP, not on the manifest.\n"
                        "// The engine reads step['domain']; a step without one raises\n"
                        "// inside the runner and comes back as an opaque HTTP 500.\n"
                        f"const DOMAIN = '{domain}';\n"
                        "const steps = ($json.steps || [\n"
                        "// The key is `action_description`. A step carrying a bare\n"
                        "// `description` parses to an EMPTY description — the step\n"
                        "// verifies successfully against nothing at all.\n"
                        "  { id: 'step-1', action_type: 'read_record',  action_description: 'read the source record' },\n"
                        "  { id: 'step-2', action_type: 'update_record', action_description: 'apply the change' },\n"
                        "]).map(s => ({ domain: DOMAIN, ...s }));\n"
                        "return [{ json: {\n"
                        "  task: $workflow.name,\n"
                        "  chain_manifest: { steps },\n"
                        "  stop_on_block: true,\n"
                        "  session_id: $('Start Session').item.json.session_id,\n"
                        "} }];"
                    )
                },
                "name": "Build Chain Manifest",
                "type": "n8n-nodes-base.code",
                "typeVersion": 2,
                "position": [450, 300],
                "id": "node-build-chain"
            },
            {
                "parameters": {
                    "method": "POST",
                    "url": f"{arcezia_api_url}/v1/verify_chain",
                    "authentication": "genericCredentialType",
                    "genericAuthType": "httpHeaderAuth",
                    "sendBody": True,
                    "specifyBody": "json",
                    "jsonBody": "={{ JSON.stringify($json) }}",
                    "options": {}
                },
                "name": "Verify Chain",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [650, 300],
                "id": "node-verify-chain",
                "credentials": {"httpHeaderAuth": {"id": "arcezia-key", "name": "Arcezia API Key"}}
            },
            {
                "parameters": {
                    "rules": {
                        "values": [
                            {"conditions": {"options": {"caseSensitive": True}, "combinator": "and", "conditions": [{"leftValue": "={{ $json.overall_verdict }}", "rightValue": "SAFE", "operator": {"type": "string", "operation": "equals"}}]}, "renameOutput": True, "outputKey": "safe"},
                            {"conditions": {"options": {"caseSensitive": True}, "combinator": "and", "conditions": [{"leftValue": "={{ $json.overall_verdict }}", "rightValue": "REVIEW_REQUIRED", "operator": {"type": "string", "operation": "equals"}}]}, "renameOutput": True, "outputKey": "review"}
                        ],
                        "fallbackOutput": "extra"
                    },
                    "options": {"fallbackOutput": "extra"}
                },
                "name": "Route on Chain",
                "type": "n8n-nodes-base.switch",
                "typeVersion": 3,
                "position": [850, 300],
                "id": "node-route-chain"
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
                        ],
                        # Anything that is not ALLOW / BLOCK / REVIEW — including
                        # SEMANTIC_BLOCK — falls through here and is treated as a stop.
                        # Never let an unrecognised verdict reach the action node.
                        "fallbackOutput": "extra"
                    },
                    "options": {"fallbackOutput": "extra"}
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
                # Real node, not a sticky note: a blocked path must actually stop
                # the run. A comment box lets execution fall off the end silently.
                "parameters": {
                    "errorMessage": "=Arcezia blocked this run: {{ $json.summary || $json.overall_verdict || $json.verdict }}"
                },
                "name": "Blocked - Stop Run",
                "type": "n8n-nodes-base.stopAndError",
                "typeVersion": 1,
                "position": [1050, 150],
                "id": "node-blocked-stop"
            },
            {
                # Replace the URL with your real action. Left as a live HTTP node
                # so the template runs end to end out of the box.
                # The single-use credential from the ALLOW is forwarded here — if
                # your endpoint requires it, an ungated action cannot succeed.
                "parameters": {
                    "method": "POST",
                    "url": "https://httpbin.org/post",
                    "sendHeaders": True,
                    "headerParameters": {
                        "parameters": [
                            # .token, not the whole object — the response returns
                            # {token, expires_at, action_type}, and interpolating
                            # the object into a header sends "[object Object]".
                            {"name": "X-Arcezia-Credential", "value": "={{ $('Arcezia Verify').item.json.credential.token }}"}
                        ]
                    },
                    "sendBody": True,
                    "specifyBody": "json",
                    "jsonBody": "={{ JSON.stringify({ action: $('Build Verify Body').item.json.action_type }) }}",
                    "options": {}
                },
                "name": "Action (Replace Me)",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [1050, 300],
                "id": "node-action"
            },
            {
                # AUDIT layer — report what actually happened back to Arcezia.
                # Without this the record ends at "we allowed it", not "here is
                # what it did".
                "parameters": {
                    "method": "POST",
                    "url": f"{arcezia_api_url}/v1/verify_outcome",
                    "authentication": "genericCredentialType",
                    "genericAuthType": "httpHeaderAuth",
                    "sendBody": True,
                    "specifyBody": "json",
                    "jsonBody": (
                        "={{ JSON.stringify({"
                        " session_id: $('Start Session').item.json.session_id,"
                        " action_type: $('Build Verify Body').item.json.action_type,"
                        " action_description: $('Build Verify Body').item.json.action_description,"
                        " outcome: { status_code: $json.statusCode || 200 }"
                        "}) }}"
                    ),
                    "options": {}
                },
                "name": "Verify Outcome",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [1250, 300],
                "id": "node-verify-outcome",
                "credentials": {"httpHeaderAuth": {"id": "arcezia-key", "name": "Arcezia API Key"}}
            }
        ],
        "connections": {
            # MEMORY → COMPOSITION → GATE → action → AUDIT
            "Start Session": {"main": [[{"node": "Build Chain Manifest", "type": "main", "index": 0}]]},
            "Build Chain Manifest": {"main": [[{"node": "Verify Chain", "type": "main", "index": 0}]]},
            "Verify Chain": {"main": [[{"node": "Route on Chain", "type": "main", "index": 0}]]},
            "Route on Chain": {
                "main": [
                    [{"node": "Build Verify Body", "type": "main", "index": 0}],        # SAFE
                    [{"node": "Wait for Human Approval", "type": "main", "index": 0}],  # REVIEW_REQUIRED
                    [{"node": "Blocked - Stop Run", "type": "main", "index": 0}]        # BLOCKED / SEMANTIC_BLOCK
                ]
            },
            "Build Verify Body": {"main": [[{"node": "Arcezia Verify", "type": "main", "index": 0}]]},
            "Arcezia Verify": {"main": [[{"node": "Route on Verdict", "type": "main", "index": 0}]]},
            "Route on Verdict": {
                "main": [
                    [{"node": "Action (Replace Me)", "type": "main", "index": 0}],      # ALLOW
                    [{"node": "Blocked - Stop Run", "type": "main", "index": 0}],       # BLOCK
                    [{"node": "Wait for Human Approval", "type": "main", "index": 0}],  # REVIEW
                    [{"node": "Blocked - Stop Run", "type": "main", "index": 0}]        # anything else
                ]
            },
            "Wait for Human Approval": {"main": [[{"node": "Authorize (Human Approved)", "type": "main", "index": 0}]]},
            "Authorize (Human Approved)": {"main": [[{"node": "Arcezia Verify", "type": "main", "index": 0}]]},
            "Action (Replace Me)": {"main": [[{"node": "Verify Outcome", "type": "main", "index": 0}]]}
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
