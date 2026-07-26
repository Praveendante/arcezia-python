"""
Arcezia ⨉ Claude Code — PreToolUse hook.

This is the *never-missed* integration for the Claude Code CLI agent. It runs as
a `PreToolUse` hook, which the Claude Code harness invokes before EVERY tool
call. Because the harness — not the agent — runs the hook, the agent cannot opt
out of it: every consequential action crosses this checkpoint, including
built-in tools you never enumerated.

Verdict → harness permission decision:
    ALLOW  → "allow"   (tool runs)
    BLOCK  → "deny"    (tool is refused; the reason is shown to Claude)
    REVIEW → "ask"     (Claude Code prompts YOU to approve — your keystroke is
                        the human authorization that grounds the action; the
                        agent cannot forge it)

Read-only tools (Read, Glob, Grep, LS, …) are not consequential and pass through.

Install (writes the hook into ~/.claude/settings.json):
    arcezia-hook install            # or: python -m arcezia.integrations.claude_code install

Hook protocol: stdin = JSON {tool_name, tool_input, ...}; stdout = JSON with
hookSpecificOutput.permissionDecision. Exit 0 always (the decision is in the JSON).
"""
from __future__ import annotations

import json
import os
import sys
from typing import Optional

# Tools that never produce an irreversible effect — pass straight through.
_READ_ONLY_TOOLS = frozenset({
    "Read", "Glob", "Grep", "LS", "NotebookRead", "TodoWrite", "TodoRead",
    "WebFetch", "WebSearch",
})

# How each consequential Claude Code tool maps to an Arcezia action. The domain
# default routes through filesystem_ops (it carries the destructive-action
# handling and extends the structural-primitive base), so a coding agent's
# shell + file writes are evaluated against real rules. Override the domain with
# ARCEZIA_DEFAULT_DOMAIN.
_DEFAULT_DOMAIN = os.environ.get("ARCEZIA_DEFAULT_DOMAIN", "filesystem_ops")


def map_tool(tool_name: str, tool_input: dict) -> Optional[tuple[str, str, str]]:
    """
    Map a Claude Code tool call to (action_type, action_description, domain).
    Returns None for read-only / non-consequential tools (let them run).
    """
    if tool_name in _READ_ONLY_TOOLS:
        return None

    ti = tool_input or {}
    if tool_name == "Bash":
        cmd = ti.get("command", "")
        return ("run_shell", cmd, _DEFAULT_DOMAIN)
    if tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = ti.get("file_path") or ti.get("notebook_path") or ""
        verb = "write_file" if tool_name == "Write" else "edit_file"
        # Include the path AND a snippet of new content so structural probes can
        # see secrets / critical paths.
        snippet = ti.get("content") or ti.get("new_string") or ""
        desc = f"{verb} {path} {snippet}".strip()
        return (verb, desc, _DEFAULT_DOMAIN)

    # Unknown / MCP / custom tool: still gate it — never-missed means we do not
    # silently pass an unrecognised consequential tool. Describe it generically.
    desc = f"{tool_name} {json.dumps(ti, default=str)[:300]}"
    return (tool_name.lower(), desc, _DEFAULT_DOMAIN)


def _decision(permission: str, reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission,           # "allow" | "deny" | "ask"
            "permissionDecisionReason": reason,
        }
    }


def run_hook(stdin_text: str, *, verifier=None) -> dict:
    """
    Pure hook core (no I/O) — returns the JSON dict to print.

    `verifier`: an object with a .verify(action_type, action_description, domain)
    method returning a cert with .allow/.block/.review/.summary. Defaults to a
    real Arcezia client built from env (ARCEZIA_API_KEY, ARCEZIA_API_URL, TASK).
    On any client/transport error the client's own on_error policy decides
    (default fail-closed → we surface "deny").
    """
    try:
        payload = json.loads(stdin_text) if stdin_text.strip() else {}
    except json.JSONDecodeError:
        # Malformed hook input — fail safe: ask the human rather than allow.
        return _decision("ask", "Arcezia: could not parse tool input; manual review.")

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}

    mapped = map_tool(tool_name, tool_input)
    if mapped is None:
        return _decision("allow", f"{tool_name} is read-only.")

    action_type, action_description, domain = mapped

    if verifier is None:
        verifier = _default_verifier()
        if verifier is None:
            # No API key configured — do not silently allow a consequential tool.
            return _decision("ask", "Arcezia not configured (set ARCEZIA_API_KEY); manual review.")

    try:
        cert = verifier.verify(
            action_type=action_type,
            action_description=action_description,
            domain=domain,
        )
    except Exception as exc:  # fail-closed default surfaces here
        return _decision("deny", f"Arcezia could not verify the action (fail-closed): {exc}")

    if cert.block:
        return _decision("deny", f"Arcezia BLOCK: {cert.summary}")
    if cert.degraded:
        return _decision("deny", f"Arcezia DENY (degraded cert — unverified): {cert.summary}")
    if cert.review:
        # Default: "ask" (prompt the human — their keystroke grounds the action).
        # Strict mode (ARCEZIA_REVIEW_MODE=deny): REVIEW halts HARD — the agent
        # must change the action or re-request with real grounding. This only
        # moves verdicts toward blocking (fail-safe direction) and never alters the
        # engine's verification logic, so it does not inflate the engine's FPR —
        # it is an enforcement-policy choice for high-security deployments.
        if os.environ.get("ARCEZIA_REVIEW_MODE", "ask").lower() == "deny":
            return _decision("deny", f"Arcezia REVIEW→strict-deny (re-request with grounding): {cert.summary}")
        return _decision("ask", f"Arcezia REVIEW (approval required): {cert.summary}")
    return _decision("allow", f"Arcezia ALLOW: {cert.summary}")


def _load_capability_envelope() -> dict | None:
    """Load capability_envelope from ~/.claude/arcezia.json if it exists.

    Production pattern: human defines authority scope in a config file.
    The hook reads it at startup and injects into the session.
    """
    config_path = os.path.expanduser("~/.claude/arcezia.json")
    if os.path.exists(config_path):
        try:
            import json as _json
            with open(config_path) as f:
                cfg = _json.load(f)
            return cfg.get("capability_envelope")
        except Exception:
            return None
    return None


def _default_verifier():
    api_key = os.environ.get("ARCEZIA_API_KEY", "").strip()
    if not api_key:
        return None
    from arcezia.client import Arcezia
    az = Arcezia(
        api_key=api_key,
        task=os.environ.get("TASK", os.environ.get("ARCEZIA_TASK", "")),
        api_url=os.environ.get("ARCEZIA_API_URL", "https://api.arcezia.com"),
        on_error=os.environ.get("ARCEZIA_ON_ERROR", "fail_closed"),
    )
    # Load capability_envelope from config (human-defined authority scope)
    envelope = _load_capability_envelope()
    if envelope:
        az.start_session(capability_envelope=envelope)
    return az


# ── settings.json install helper ──────────────────────────────────────────────

_HOOK_COMMAND = "python -m arcezia.integrations.claude_code hook"


def settings_snippet() -> dict:
    """The PreToolUse hook block to merge into ~/.claude/settings.json."""
    return {
        "hooks": {
            "PreToolUse": [
                {"matcher": "*", "hooks": [{"type": "command", "command": _HOOK_COMMAND}]}
            ]
        }
    }


def install(settings_path: Optional[str] = None) -> str:
    """
    Merge the PreToolUse hook into the user's Claude Code settings.json.
    Returns the path written. Idempotent — does not duplicate the hook.
    """
    from pathlib import Path
    path = Path(settings_path or os.path.expanduser("~/.claude/settings.json"))
    path.parent.mkdir(parents=True, exist_ok=True)
    settings: dict = {}
    if path.exists():
        try:
            settings = json.loads(path.read_text())
        except json.JSONDecodeError:
            settings = {}
    hooks = settings.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    if not any(
        h.get("command") == _HOOK_COMMAND
        for entry in pre for h in entry.get("hooks", [])
    ):
        pre.append({"matcher": "*", "hooks": [{"type": "command", "command": _HOOK_COMMAND}]})
    path.write_text(json.dumps(settings, indent=2))
    return str(path)


def main(argv: Optional[list[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if argv and argv[0] == "install":
        written = install()
        print(f"Arcezia PreToolUse hook installed → {written}")
        print("Set ARCEZIA_API_KEY (and optionally TASK) in your environment.")
        return 0
    if argv and argv[0] == "print-config":
        print(json.dumps(settings_snippet(), indent=2))
        return 0
    # Default: act as the hook (read stdin, emit decision).
    out = run_hook(sys.stdin.read())
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
