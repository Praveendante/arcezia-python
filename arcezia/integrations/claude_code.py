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
                        the person's approval; the agent cannot forge it)

File reads and searches (Read, Grep, Glob, LS, NotebookRead) are verified too,
each as the shell read it performs: what they return reaches the model and any
later call. Only the harness's own to-do list tools are not verified.

Install (writes the hook into ~/.claude/settings.json):
    arcezia-hook install            # or: python -m arcezia.integrations.claude_code install

Hook protocol: stdin = JSON {tool_name, tool_input, ...}; stdout = JSON with
hookSpecificOutput.permissionDecision. Exit 0 always (the decision is in the JSON).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import sys
import time
from typing import Optional

from arcezia.integrations import _hook_state
from arcezia.integrations._common import ACTION_KEYS, call_of, describe, pass_hold_reason
from arcezia.integrations._params import scalar_params

# Tools that never produce an irreversible effect — pass straight through.
#
# Every name here is an assertion that the tool is harmless, and the hook never
# verifies what it lists. So the bar is "produces no effect outside this
# machine", not "the harness calls it a read". WebFetch and WebSearch send a
# request to a URL the agent chooses, so they are verified as outbound actions
# below. Read, Grep, Glob, LS and NotebookRead return content into the agent's
# context, so each is verified as the shell program that does the same act
# (_READ_TOOLS).
_READ_ONLY_TOOLS = frozenset({"TodoWrite", "TodoRead"})

# The harness's file-reading tools, each as the shell act it performs: the same
# action type and the same kind of description as `cat <path>` / `grep <pattern>
# <path>` / `ls <path>`, so both routes to the same act get the same verdict.
_READ_TOOLS = {
    "Read": ("shell_read", "cat", ("file_path",)),
    "NotebookRead": ("shell_read", "cat", ("notebook_path", "file_path")),
    "Grep": ("shell_search", "grep", ("pattern", "path", "glob")),
    "Glob": ("shell_search", "find", ("path", "pattern")),
    "LS": ("shell_search", "ls", ("path",)),
}

# Outbound tools: the payload leaves the machine, so they are verified in the
# agent_action domain, never the filesystem default.
_OUTBOUND_TOOLS = {
    "WebFetch": "fetch_url",
    "WebSearch": "web_search",
}

# How each consequential Claude Code tool maps to an Arcezia action. The default
# domain is filesystem_ops, which fits a coding agent's shell commands and file
# writes. Override the domain with ARCEZIA_DEFAULT_DOMAIN.
_DEFAULT_DOMAIN = os.environ.get("ARCEZIA_DEFAULT_DOMAIN", "filesystem_ops")

# The action type this hook sends a whole command line under (a compound or
# untypeable command, and every act of an envelope that allows `run_shell`).
# The service reads a description as a command line only for a tool declared
# to be one; the hosted service declares exactly this type (its own shell
# type), so the hook's command lines are read segment by segment there: a
# known-safe line can clear, and the words of the line can be checked against
# a signed workspace (`capability_envelope.workspace_roots`).
COMMAND_LINE_ACTION_TYPE = "run_shell"


# ── Shell commands: the program is the tool ─────────────────────────────────
#
# `Bash` is one Claude Code tool, but `git commit`, `pip install` and
# `terraform plan` are different acts with different contracts. Sent as one
# type ("run_shell") they could only be declared as one, and a declaration on
# all of the shell is a wildcard in disguise. So a command whose program is in
# this table is verified under the program's own action type; the description
# is still the whole command line. A program not in the table stays
# `run_shell`.
#
# A compound command (`a && b`, `a | b`, `a; b`) is several acts: each segment
# is verified under its own type and the strictest decision wins. A command the
# splitter cannot read safely (unbalanced quotes, substitutions) is verified
# whole as `run_shell`.
_SHELL_PROGRAMS: dict = {
    "git": {"add": "git_add", "commit": "git_commit", "push": "git_push", "pull": "git_pull",
            "fetch": "git_fetch", "status": "git_status", "log": "git_log", "diff": "git_diff",
            "show": "git_show", "branch": "git_branch", "tag": "git_tag", "remote": "git_remote",
            "stash": "git_stash", "switch": "git_switch"},
    "pip": {"install": "pip_install"}, "pip3": {"install": "pip_install"},
    "uv": {"add": "pip_install", "pip": "pip_install"}, "poetry": {"add": "pip_install"},
    "npm": {"install": "npm_install", "i": "npm_install", "ci": "npm_install", "add": "npm_install",
            "test": "run_tests", "run": "npm_run"},
    "yarn": {"add": "npm_install", "install": "npm_install", "test": "run_tests"},
    "pnpm": {"add": "npm_install", "install": "npm_install", "i": "npm_install", "test": "run_tests"},
    "pytest": "run_tests", "go": {"test": "run_tests", "build": "build"},
    "cargo": {"test": "run_tests", "build": "build"}, "make": {"test": "run_tests"},
    # A downgrade runs the migrations' reverse bodies and a destroy removes
    # what an apply created: each is its own act, so authority for the forward
    # act never covers it.
    "alembic": {"upgrade": "db_migrate", "downgrade": "db_downgrade", "revision": "db_migration_file"},
    "psql": "database_query", "mysql": "database_query", "sqlite3": "database_query",
    "terraform": {"plan": "terraform_plan", "init": "terraform_init", "validate": "terraform_validate",
                  "apply": "terraform_apply", "destroy": "terraform_destroy"},
    "aws": "aws_cli", "gcloud": "gcloud_cli", "az": "az_cli", "kubectl": "kubectl",
    "cat": "shell_read", "head": "shell_read", "tail": "shell_read", "less": "shell_read", "wc": "shell_read",
    "ls": "shell_search", "grep": "shell_search", "find": "shell_search",     # may walk a tree
    "curl": "http_request", "wget": "http_request",
}
# `aws <service> <operation>` is one act per operation, the way the allowlist
# and the IAM policy both see it.
_CLI_SUBTYPED = {"aws_cli": 2, "gcloud_cli": 2, "az_cli": 2, "kubectl": 1}
_OUTBOUND_SHELL_TYPES = {"http_request"}
# A database client, and a database MCP server, is verified in the database
# domain, not the filesystem one.
_DATABASE_TYPES = {"database_query"}
_DATABASE_MCP_PREFIXES = ("mcp__postgres__", "mcp__mysql__", "mcp__sqlite__", "mcp__supabase__", "mcp__neon__")
_SEGMENT_OPERATORS = {"&&", "||", ";", "|", "|&"}
_UNSPLITTABLE = re.compile(r"\$\(|`|<<|\beval\b|\bxargs\b|\bexec\b|\b(?:ba|z|da)?sh\s+-c\b")
# A newline, a carriage return, U+2028 and every other control or separator
# character ends a shell command (or may, to some shell) but is whitespace to
# shlex, so `git status\n./deploy.sh` read as ONE git_status act. The splitter
# does not try to model each shell's line rules: a command carrying any
# character outside printable ASCII (tab and space excepted) is not typed.
_UNTYPEABLE_CHAR = re.compile(r"[^\t\x20-\x7e]")
# A redirection or a process substitution writes a file or runs a second
# program the leading program never names: `cat k > ~/.ssh/authorized_keys` is
# a write, `cat <(curl ...)` runs curl. Either makes the segment untypeable.
_REDIRECTION = re.compile(r">|<\(")
# git options that write a file (`git log --output=~/.bashrc`, format-patch -o).
_GIT_WRITE_OPTION = re.compile(r"--output(?:-directory)?(?:=|$)|-o")


def _comment_start(command: str) -> bool:
    """True when an unquoted `#` begins a word, which a shell reads as the
    start of a comment. Everything after it is text the shell drops, and
    reading it (or not) is a guess about which shell runs the line, so such a
    command is not typed. A `#` inside a word (`x#`) or inside quotes is
    ordinary text to every shell and is left alone."""
    quote = ""
    escaped = False
    prev = " "
    for ch in command:
        if escaped:
            escaped = False
        elif quote:
            if ch == quote:
                quote = ""
            elif ch == "\\" and quote == '"':
                escaped = True
        elif ch == "\\":
            escaped = True
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#" and (prev.isspace() or prev in ";&|()<>"):
            return True
        prev = ch
    return False


def _untypeable(command: str) -> bool:
    """True when the command cannot be typed as plain program acts."""
    return bool(_UNTYPEABLE_CHAR.search(command) or _UNSPLITTABLE.search(command)
                or _comment_start(command))


# Options that make a typed program's act a different one: a delete, a write
# to a file the command line names, or a second program run. A segment that
# carries one is `run_shell`, never the plain act its program name suggests.
_FIND_ACTING = re.compile(r"-(?:delete|exec|execdir|ok|okdir|fprint0?|fprintf|fls)$")
_DESTROY_OPTION = re.compile(r"--?destroy(?:=.*)?$")
_CURL_WRITE_LONG = re.compile(
    r"--(?:output|output-dir|remote-name|remote-name-all|dump-header|cookie-jar|config|"
    r"trace|trace-ascii|stderr|etag-save|hsts|alt-svc|libcurl)(?:=.*)?$")
_WGET_WRITE_LONG = re.compile(
    r"--(?:output-document|output-file|append-output|directory-prefix|input-file)(?:=.*)?$")
_GIT_BRANCH_CHANGE = re.compile(r"--(?:delete|move|copy|force)$|-[A-Za-z]*[dDmMcCf][A-Za-z]*$")
# `git remote` / `git stash` subcommands that only read. Anything else there
# (set-url, add, remove, drop, clear, ...) changes where pushes go or loses work.
_GIT_REMOTE_READS = {None, "-v", "--verbose", "show", "get-url"}
_GIT_STASH_CHANGE = {"clear", "drop"}


def _short_cluster_has(arg: str, letters: str) -> bool:
    """`-sSLo` carries `-o`: a single-dash cluster of short options."""
    return bool(re.match(r"-[A-Za-z]", arg)) and not arg.startswith("--") and any(
        c in letters for c in arg[1:].split("=", 1)[0])


# git's documented option that removes the repository's own checks (its
# pre-commit / commit-msg / pre-push / pre-merge-commit hooks): `--no-verify`
# on any subcommand that runs hooks, and `-n`, its short form, on `commit`
# only (on `push` `-n` is a dry run). The act is then no longer the one the
# typed name stands for — the checks the repository attaches to that act are
# switched off — so the segment falls back to `run_shell` (2026-10-03, AEIB
# GC-I3).
_GIT_NO_VERIFY = re.compile(r"--no-verify$")


def _skips_repository_checks(sub: str, rest: list) -> bool:
    if any(_GIT_NO_VERIFY.match(a) for a in rest):
        return True
    return sub == "commit" and any(_short_cluster_has(a, "n") for a in rest)


def _writes_beyond_its_type(prog: str, args: list) -> bool:
    if prog == "find":
        return any(_FIND_ACTING.match(a) for a in args)
    if prog == "terraform":
        return any(_DESTROY_OPTION.match(a) for a in args)
    if prog == "curl":
        return any(_CURL_WRITE_LONG.match(a) or _short_cluster_has(a, "oODcK") for a in args)
    if prog == "wget":
        # wget's own default act is to SAVE the download to a file; it is a
        # plain request only when the body goes to stdout or it only checks.
        to_stdout = any(a in ("-O-", "-qO-", "--output-document=-") for a in args) or \
            any(a == "-O" and i + 1 < len(args) and args[i + 1] == "-" for i, a in enumerate(args))
        if not (to_stdout or "--spider" in args):
            return True
        return any((_WGET_WRITE_LONG.match(a) and a != "--output-document=-")
                   or (_short_cluster_has(a, "oaPi")) for a in args)
    if prog in ("less", "more"):
        # `+cmd` runs a command at start-up (`less +'!rm -rf ~' f`).
        return any(a.startswith("+") for a in args)
    if prog == "git" and args:
        sub, rest = args[0].lower(), args[1:]
        if sub in ("diff", "show", "log") and any(
                a.split("=", 1)[0] in ("--ext-diff", "--textconv") for a in rest):
            return True                # runs an external program
        if _skips_repository_checks(sub, rest):
            return True                # the repository's own checks do not run
        if sub == "branch":
            return any(_GIT_BRANCH_CHANGE.match(a) for a in rest)
        if sub == "remote":
            return (rest[0] if rest else None) not in _GIT_REMOTE_READS
        if sub == "stash":
            return bool(rest) and rest[0].lower() in _GIT_STASH_CHANGE
    return False


def split_shell(command: str) -> Optional[list]:
    """Top-level segments of a shell command, or None when it cannot be read
    safely (then the caller verifies the whole command as one shell act)."""
    if not command or _untypeable(command):
        return None
    lex = shlex.shlex(command, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    # shlex's default treats `#` ANYWHERE as a comment, so `git status x#;
    # rm -rf ~` lexed as one git_status act and the second program vanished.
    # A shell starts a comment only at a word start, and that case is already
    # refused as untypeable above; here `#` is always text.
    lex.commenters = ""
    try:
        tokens = list(lex)
    except ValueError:
        return None
    segments: list = [[]]
    for tok in tokens:
        if _REDIRECTION.search(tok):
            return None                # `>`, `>>`, `&>`, `2>`, `<(`, `>(`
        if tok in _SEGMENT_OPERATORS:
            segments.append([])
        elif tok in ("(", ")", "&", "{", "}"):
            return None
        else:
            segments[-1].append(tok)
    out = [" ".join(shlex.quote(t) if t != "*" else t for t in seg) for seg in segments if seg]
    return out or None


def shell_action_type(segment: str) -> str:
    """The action type for one shell segment: the program's own type when its
    kind of act is fixed, else `run_shell`. Anything it cannot type safely —
    a control character, a redirection, an option before the subcommand — is
    `run_shell`, the generic and most restrictive type."""
    if not segment or _untypeable(segment):
        return "run_shell"
    try:
        argv = shlex.split(segment, posix=True)
    except ValueError:
        return "run_shell"
    # Only a BARE program name is typed. `/tmp/x/git status` and `./cat` run
    # whatever file sits at that path, which need not be the program the name
    # suggests; the shell's own lookup is what makes `git` git.
    if not argv or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", argv[0]):
        return "run_shell"
    if any(_REDIRECTION.search(a) for a in argv):
        return "run_shell"
    prog = argv[0].lower()
    if _writes_beyond_its_type(prog, argv[1:]):
        return "run_shell"
    entry = _SHELL_PROGRAMS.get(prog)
    if entry is None:
        return "run_shell"
    if isinstance(entry, str):
        atype = entry
        if atype in _CLI_SUBTYPED:
            n = _CLI_SUBTYPED[atype]
            # The subtype is the first n arguments, and each must be a plain
            # word: `kubectl -n prod delete` is not the act `kubectl__n`. An
            # option among them means the operation is somewhere else.
            parts = argv[1:1 + n]
            if len(parts) < n or not all(
                    re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", a) for a in parts):
                return "run_shell"
            parts = [a.lower() for a in parts]
            atype = "_".join([prog] + parts).replace("-", "_")
        return atype
    # The subcommand is the FIRST argument. An option before it (`git -c`,
    # `-ccore.fsmonitor=...`, `--config-env=`, `-C dir`, `--git-dir`,
    # `--exec-path`) changes what the program runs or where, so it is not typed.
    if len(argv) < 2 or argv[1].startswith("-"):
        return "run_shell"
    sub = argv[1].lower()
    atype = entry.get(sub, "run_shell")
    if prog == "git" and any(_GIT_WRITE_OPTION.match(a) for a in argv[2:]):
        return "run_shell"             # writes a file: not the read it names
    return atype


def _absolute(path: str, cwd: Optional[str]) -> str:
    if path and cwd and not os.path.isabs(path) and not path.startswith("~"):
        return os.path.normpath(os.path.join(cwd, path))
    return path


def _inside(path: str, root: str) -> bool:
    """`path` (absolute or relative to root) lies within `root`, both taken as
    their real paths (symlinks and `..` resolved)."""
    if not path:
        return True
    p = os.path.expanduser(path)
    if not os.path.isabs(p):
        p = os.path.join(root, p)
    rp, rr = os.path.realpath(p), os.path.realpath(root)
    return rp == rr or rp.startswith(rr.rstrip(os.sep) + os.sep)


def _read_stays_inside(tool_name: str, ti: dict, cwd: Optional[str]) -> bool:
    """Every place this read tool names lies inside the working directory."""
    if not cwd or not os.path.isabs(cwd):
        return False
    if tool_name in ("Read", "NotebookRead"):
        target = ti.get("file_path") or ti.get("notebook_path")
        return bool(target) and _inside(str(target), cwd)
    if tool_name == "LS":
        return _inside(str(ti.get("path") or ""), cwd)
    if tool_name == "Grep":
        return _inside(str(ti.get("path") or ""), cwd)
    if tool_name == "Glob":
        base = str(ti.get("path") or "")
        pat = str(ti.get("pattern") or "")
        # A pattern that is absolute or climbs out names another place.
        if os.path.isabs(os.path.expanduser(pat)) or ".." in pat.replace("\\", "/").split("/"):
            return False
        return _inside(base, cwd)
    return False


def _with_real_cwd(params: Optional[dict], cwd: Optional[str]) -> Optional[dict]:
    """The call's typed parameters plus the folder the command runs in, as
    its REAL path (symlinks and `..` resolved on this machine).

    The service reads a location against a signed workspace lexically: it
    cannot see this machine, so a symlink inside the workspace that points out
    of it, or a `..`, would read as inside. Resolving here, where the files
    are, is what makes the lexical check true. The harness's own `cwd` wins
    over any argument of the same name (the agent writes the arguments). With
    no absolute cwd nothing is added: an unknown folder is not a place."""
    if not isinstance(cwd, str) or not os.path.isabs(cwd):
        return params
    out = dict(params or {})
    out["cwd"] = os.path.realpath(cwd)
    return out


def read_act(tool_name: str, tool_input: dict, cwd: Optional[str] = None,
             *, real: bool = False) -> tuple:
    """A harness read tool as the shell read it performs: (action_type,
    description, domain), e.g. `Read p` -> ("shell_read", "cat p", ...). ONE
    function for both routes a read takes: verified when it leaves the
    working directory (`map_tool_all`), and recorded as an observed act when
    it stays inside (E2) — so the service reads the two the same way.

    `real`: also name each place by its REAL path (symlinks and `..` resolved
    on this machine) when that differs. Used for the observed route:
    `src/config.txt -> .env` inside the checkout is reported as
    `cat /repo/src/config.txt /repo/.env` — both names of the one file, so a
    reading of it can only see more, never less."""
    ti = tool_input or {}
    atype, prog, keys = _READ_TOOLS[tool_name]

    def _places(a: str) -> list:
        p = _absolute(a, cwd)
        if real and p and os.path.isabs(os.path.expanduser(p)):
            rp = os.path.realpath(os.path.expanduser(p))
            return [p] if rp == p else [p, rp]
        return [p]

    args = [str(ti[k]) for k in keys if ti.get(k)]
    if tool_name in ("Read", "NotebookRead", "LS"):
        args = _places(args[0]) if args else []
        if real and not args and tool_name == "LS" and cwd:
            args = [os.path.realpath(cwd)]
    elif tool_name == "Grep":
        # Only `path` names a place on disk. `glob` is a file-name filter
        # (`*.py`): made absolute it read as a path under the cwd.
        args = [a for k in keys if ti.get(k)
                for a in ([str(ti[k])] if k != "path" else _places(str(ti[k])))]
        if real and not ti.get("path") and cwd:
            args = args[:1] + [os.path.realpath(cwd)] + args[1:]
    elif tool_name == "Glob":
        if args and ti.get("path"):
            args = _places(args[0]) + args[1:]
        elif real and cwd:
            args = [os.path.realpath(cwd)] + args
    return (atype, " ".join([prog] + [shlex.quote(a) for a in args]), _DEFAULT_DOMAIN)


def map_tool_all(tool_name: str, tool_input: dict, cwd: Optional[str] = None
                 ) -> Optional[list]:
    """
    Map a Claude Code tool call to the list of acts it performs, each as
    (action_type, action_description, domain). One entry for every tool but a
    compound shell command, which yields one per segment. None for read-only
    tools (let them run). `cwd` is the harness's working directory; a relative
    file path is made absolute with it so the real target is verified.
    """
    if tool_name in _READ_ONLY_TOOLS:
        return None

    ti = tool_input or {}
    if tool_name in _READ_TOOLS:
        # A read INSIDE the working directory runs without a call (the
        # developer put the agent there for this task); a read that reaches
        # outside it (~/.ssh, ~/.aws, /etc, a symlink out of the checkout) is
        # verified as the shell act it performs. Inside/outside is decided on
        # the real path; with no known cwd it cannot be decided, so the read
        # is verified (fail closed). Note: a secrets file inside the checkout
        # read through Read passes; `cat` of it through Bash is still verified.
        if _read_stays_inside(tool_name, ti, cwd):
            return None
        # Both names of each place (2026-10-03): `Read link/x` with `link ->
        # ~/.ssh` is verified as `cat /repo/link/x /home/u/.ssh/x`, so the
        # service reads the file the call actually reaches. Extra names can
        # only add what the reading sees.
        return [read_act(tool_name, ti, cwd, real=True)]
    if tool_name in _OUTBOUND_TOOLS:
        # The URL / query IS the action: it is what leaves the machine.
        target = ti.get("url") or ti.get("query") or ti.get("prompt") or ""
        return [(_OUTBOUND_TOOLS[tool_name], f"{tool_name} {target}".strip(), "agent_action")]
    if tool_name == "Bash":
        cmd = ti.get("command", "")
        segments = split_shell(cmd)
        if segments is None:
            # Not readable as plain segments (a substitution, a heredoc, a
            # subshell): the program at the front does not say what runs.
            return [(COMMAND_LINE_ACTION_TYPE, cmd, _DEFAULT_DOMAIN)]
        if len(segments) == 1:
            segments = [cmd]           # one act: the command as written
        acts = []
        for seg in segments:
            atype = shell_action_type(seg)
            if atype in _OUTBOUND_SHELL_TYPES:
                domain = "agent_action"
            elif atype in _DATABASE_TYPES:
                domain = "database_ops"
            else:
                domain = _DEFAULT_DOMAIN
            acts.append((atype, seg, domain))
        return acts
    if tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = _absolute(ti.get("file_path") or ti.get("notebook_path") or "", cwd)
        verb = "write_file" if tool_name == "Write" else "edit_file"
        # Include the path AND the new content, so what is verified is what
        # gets written.
        snippet = ti.get("content") or ti.get("new_string") or ""
        desc = f"{verb} {path} {snippet}".strip()
        return [(verb, desc, _DEFAULT_DOMAIN)]

    # Unknown / MCP / custom tool: still gate it — never-missed means we do not
    # silently pass an unrecognised consequential tool. Describe it generically,
    # with EVERY field.
    lowered = tool_name.lower()
    domain = "database_ops" if lowered.startswith(_DATABASE_MCP_PREFIXES) else _DEFAULT_DOMAIN
    return [(lowered, describe(tool_name, kwargs=ti, priority=ACTION_KEYS), domain)]


def map_tool(tool_name: str, tool_input: dict, cwd: Optional[str] = None
             ) -> Optional[tuple]:
    """
    Map a Claude Code tool call to ONE (action_type, action_description, domain).
    Returns None for read-only / non-consequential tools (let them run). A
    compound shell command is returned whole as `run_shell`; the hook itself
    uses `map_tool_all`, which verifies each segment.
    """
    acts = map_tool_all(tool_name, tool_input, cwd)
    if acts is None:
        return None
    if len(acts) == 1:
        return acts[0]
    return ("run_shell", (tool_input or {}).get("command", ""), _DEFAULT_DOMAIN)


def fit_to_envelope(acts: list, tool_name: str, envelope) -> list:
    """Keep an existing envelope working after the shell was split into finer
    action types (`shell_read`, `run_tests`, `npm_install`, ...).

    Every typed shell act IS a shell command, so an envelope that allows
    `run_shell` allowed it before this SDK typed it. Where the allow-list names
    `run_shell` but not the finer type, the act is sent as `run_shell`, exactly
    as an older hook sent it: the most restrictive type, with the whole command
    text, so nothing is read more loosely. An upgrade never narrows a ceiling
    the principal set. An envelope with no allow-list, or one that names the
    finer type, is untouched; nothing is widened beyond `run_shell`."""
    allowed = (envelope or {}).get("allowed_action_types") if isinstance(envelope, dict) else None
    if not isinstance(allowed, (list, tuple)) or "run_shell" not in allowed:
        return acts
    if tool_name != "Bash" and tool_name not in _READ_TOOLS:
        return acts
    names = set(allowed)
    # A finer type the principal DENIED keeps its name (2026-10-04, docs
    # validation): renamed to `run_shell` it passed under the allow-list and
    # the denial of that very tool was never read, so `denied_action_types:
    # ["git_push"]` did not stop `git push`. Keeping the name can only make
    # the call stricter (it is refused as denied).
    denied = (envelope or {}).get("denied_action_types")
    denied = set(denied) if isinstance(denied, (list, tuple)) else set()
    return [(a, d, dom) if (a in names or a in denied) else ("run_shell", d, _DEFAULT_DOMAIN)
            for a, d, dom in acts]


def _decision(permission: str, reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission,           # "allow" | "deny" | "ask"
            "permissionDecisionReason": reason,
        }
    }


# The hook's own deadline. The harness kills a hook that outlives its
# `timeout` and then treats that as a non-blocking error: the tool RUNS. So the
# hook must decide before the harness gives up — a verification still pending
# at this deadline is a deny. `settings_snippet` gives the harness a timeout
# above this one, leaving room to print the decision.
_HOOK_DEADLINE_SECONDS = 45
_HARNESS_TIMEOUT_SECONDS = 60


def run_hook(stdin_text: str, *, verifier=None, data_subject_reference=None) -> dict:
    """The hook decision, bounded by `_HOOK_DEADLINE_SECONDS`.

    The work runs on a worker thread; when it has not decided by the deadline
    (a hung network call, retries piling up) the answer is deny. The thread is
    a daemon, so a late answer is dropped with the process."""
    import threading
    box: dict = {}

    def _work() -> None:
        try:
            box["out"] = _run_hook_core(stdin_text, verifier=verifier,
                                        data_subject_reference=data_subject_reference)
        except BaseException as exc:            # noqa: BLE001 — decided below
            box["exc"] = exc

    worker = threading.Thread(target=_work, name="arcezia-hook", daemon=True)
    worker.start()
    worker.join(_HOOK_DEADLINE_SECONDS)
    if "out" in box:
        return box["out"]
    if "exc" in box:
        return _decision("deny", f"Arcezia could not verify the action (fail-closed): {box['exc']}")
    return _decision(
        "deny", f"Arcezia did not decide within {_HOOK_DEADLINE_SECONDS} seconds, so "
                f"nothing verified this action (fail-closed).")


def _run_hook_core(stdin_text: str, *, verifier=None, data_subject_reference=None) -> dict:
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

    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
    cc_session = payload.get("session_id")
    cc_session = cc_session if isinstance(cc_session, str) and cc_session else None
    acts = map_tool_all(tool_name, tool_input, cwd)
    if acts is None:
        if tool_name in _READ_TOOLS:
            if not cc_session:
                return _decision("allow", f"{tool_name} stays inside the working directory.")
            # Observe always, gate lazily (E2, 2026-10-03): the read runs
            # without a call, and is recorded so the next verified call
            # reports it — what it put in the agent's hands is then in the
            # session before anything that could send it out is decided.
            if _observe_read(cc_session, tool_name, tool_input, cwd):
                return _decision(
                    "allow", f"{tool_name} stays inside the working directory "
                             f"(recorded; reported with the next verified call).")
            # Not recordable (journal full or unwritable): verified instead,
            # as the shell read it performs. Observed or verified, never neither.
            acts = [read_act(tool_name, tool_input, cwd)]
        else:
            return _decision("allow", f"{tool_name} changes nothing and reads nothing.")
    # Only when the hook builds its own verifier: then the envelope it adapts
    # to is the one that verifier opens the session with (~/.claude/
    # arcezia.json). A caller-supplied verifier brings its own envelope, and
    # adapting to this machine's file would verify against the wrong one.
    if verifier is None:
        acts = fit_to_envelope(acts, tool_name, _load_capability_envelope())

    # E3b: a repeat of a call the service allowed, with every determining
    # input unchanged, is answered from the service's signed grant.
    _reuse = None
    if verifier is None and cc_session and _reuse_requested():
        try:
            _reuse = _reuse_lookup(payload, tool_name, tool_input, acts, cwd, cc_session)
        except Exception:
            _reuse = None                           # any doubt: verify
        if _reuse is not None and _reuse.get("hit") and _reuse.get("hold"):
            h = _reuse["hold"]
            if h["hold"] == "BLOCK":
                return _decision("deny", f"Arcezia BLOCK (re-used, unchanged inputs): {h['summary']}")
            if os.environ.get("ARCEZIA_REVIEW_MODE", "ask").lower() == "deny":
                return _decision("deny", f"Arcezia REVIEW→strict-deny (re-used, unchanged inputs): {h['summary']}")
            return _decision("ask", f"Arcezia REVIEW (re-used, unchanged inputs): {h['summary']}")
        if _reuse is not None and _reuse.get("hit"):
            return _decision(
                "allow", "Arcezia ALLOW (the service's signed verdict for this exact call, "
                         "reused: every input it depended on is unchanged).")
        if _reuse is not None:
            _hook_state.reuse_mark_pending(_session_dir(), cc_session)

    # CONSTRUCTING the verifier is part of verifying. It was outside
    # this try, so an outage while ~/.claude/arcezia.json carries a
    # capability_envelope (start_session raises ArceziaUnavailableError), a bad
    # ARCEZIA_API_URL scheme or a mistyped ARCEZIA_ON_ERROR (ValueError) all
    # escaped run_hook as a traceback. The harness reads a non-zero, non-2 exit
    # as a NON-BLOCKING error and runs the tool — a construction failure was a
    # fail-open. Same try, so every failure becomes a deny.
    own_verifier = verifier is None
    try:
        if verifier is None:
            verifier = _default_verifier(payload)
            if verifier is None:
                # No API key configured — an honest absence, not a failure. Do
                # not silently allow a consequential tool; put it to the human.
                return _decision(
                    "ask", "Arcezia not configured (set ARCEZIA_API_KEY); manual review.")

        if data_subject_reference is not None and callable(
            getattr(verifier, "set_data_subject", None)
        ):
            verifier.set_data_subject(data_subject_reference)

        # Typed hook tool_input, forwarded to your registered checks.
        # The verifier contract predates action_parameters, and a user-supplied
        # verifier with a strict .verify signature would raise TypeError on the
        # extra kwarg — which the fail-closed handler below would convert into a
        # DENY, breaking a working setup. Pass it only when the verifier's
        # signature accepts it (named or **kwargs); otherwise omit — behaviour is
        # then exactly the pre-change contract.
        _extra: dict = {}
        _takes_observed = False
        _takes_default = False
        try:
            import inspect as _inspect
            _sig_params = _inspect.signature(verifier.verify).parameters
            _var_kw = any(p.kind is _inspect.Parameter.VAR_KEYWORD for p in _sig_params.values())
            if "action_parameters" in _sig_params or _var_kw:
                _extra["action_parameters"] = _with_real_cwd(scalar_params(tool_input), cwd)
            _takes_observed = "observed_prior_acts" in _sig_params or _var_kw
            _takes_default = "domain_is_default" in _sig_params or _var_kw
        except (TypeError, ValueError):
            pass  # unintrospectable verifier — omit the kwarg, never break the call

        # The reads this session let run since its last verified call (E2),
        # reported with the FIRST act of this call and marked received only
        # once a verify carrying them came back from the service.
        _obs_gen, _obs_upto, _observed = (
            _hook_state.unreported(_session_dir(), cc_session)
            if (cc_session and _takes_observed) else (0, 0, []))

        # One tool call may be several acts (a compound shell command). Each is
        # verified on its own; the strictest decision is the tool call's.
        worst: Optional[dict] = None
        _certs: list = []
        _allowed: list = []
        for _i, (action_type, action_description, domain) in enumerate(acts):
            _kw = dict(_extra)
            if own_verifier and _takes_default:
                # The hook's domain is its default for the tool name, not a
                # choice: a tool the account's contract covers is checked
                # under that contract (2026-10-04).
                _kw["domain_is_default"] = True
            if _i == 0 and _observed:
                _kw["observed_prior_acts"] = list(_observed)
            try:
                cert = verifier.verify(
                    action_type=action_type,
                    action_description=action_description,
                    domain=domain,
                    **_kw,
                )
            except Exception as exc:
                # A remembered session the service no longer knows (404
                # session-not-found): forget it, open a fresh one, and ask once
                # more. Any other failure — a 409 lock, a 402, a 429, a network
                # error — denies below and KEEPS the stored session: replacing
                # it would lose what the session has already seen. A second
                # failure denies.
                if not (own_verifier and cc_session and _stored_session(cc_session)
                        and _is_session_not_found(exc)):
                    raise
                _forget_session(cc_session)
                verifier = _default_verifier(payload)
                cert = verifier.verify(
                    action_type=action_type,
                    action_description=action_description,
                    domain=domain,
                    **_kw,
                )
            if _i == 0 and _observed and not getattr(cert, "degraded", False):
                _hook_state.mark_reported(_session_dir(), cc_session, _obs_gen, _obs_upto)
            _certs.append(cert)
            # The call this act will run, as it was sent: with the default
            # domain the service chose the rule set, so the reply's is expected.
            decision = _decide(cert, call_of(
                action_type, None if _kw.get("domain_is_default") else domain,
                action_description, _kw.get("action_parameters")))
            _allowed.append(decision["hookSpecificOutput"]["permissionDecision"] == "allow")
            if len(acts) > 1:
                out = decision["hookSpecificOutput"]
                out["permissionDecisionReason"] = (
                    f"[{action_description[:60]}] " + out["permissionDecisionReason"])
            if worst is None or _STRICTNESS[decision["hookSpecificOutput"]["permissionDecision"]] \
                    > _STRICTNESS[worst["hookSpecificOutput"]["permissionDecision"]]:
                worst = decision
        # One Arcezia session per Claude Code session: remember the one this
        # call ran under (and the envelope and rules it was opened with) so
        # the next call continues it.
        sid = getattr(verifier, "session_id", None)
        if own_verifier and cc_session and isinstance(sid, str) and sid:
            config = _session_config_digest()
            if _stored_record(cc_session) != (sid, config):
                _store_session(cc_session, sid, config=config)
        if _reuse is not None and own_verifier and cc_session:
            _reuse_record(_reuse, acts, _certs, getattr(verifier, "session_id", None), cc_session,
                          allowed=_allowed)
        return worst
    except Exception as exc:  # fail-closed default surfaces here
        return _decision("deny", f"Arcezia could not verify the action (fail-closed): {exc}")


_STRICTNESS = {"allow": 0, "ask": 1, "deny": 2}


def _is_session_not_found(exc: BaseException) -> bool:
    """True for the service's answers that the stored session is gone: 409
    `session_expired` (a session that carried an envelope or session rules is
    never re-opened bare), and the older 404 session-not-found. The hook then
    forgets it and opens a new session, which carries the envelope and rules."""
    code = getattr(exc, "status_code", None)
    text = str(exc).lower()
    if code == 409:
        return "session_expired" in text
    if code == 404:
        return "session_not_found" in text or "session not found" in text
    return False


def _decide(cert, call: Optional[dict] = None) -> dict:
    """Verdict → harness permission decision, for one verified act.

    ``call`` is the act as it was sent (``_common.call_of``); an ALLOW is
    allowed only on a pass naming it, or with no pass because there was no
    session (``_common.pass_hold_reason``)."""
    if cert.block:
        return _decision("deny", f"Arcezia BLOCK: {cert.summary}")
    if cert.degraded:
        return _decision("deny", f"Arcezia DENY (degraded cert — unverified): {cert.summary}")
    if not cert.is_clean():
        # The server did not report whether fabricated evidence was found. An
        # unreported check is not a passed one, and this hook is a gate, so the
        # unknown denies.
        return _decision(
            "deny",
            f"Arcezia DENY (not cleared: {cert.fabrication_status}): {cert.summary}")
    if cert.review:
        # Default: "ask" (prompt the human — their keystroke is the approval).
        # Strict mode (ARCEZIA_REVIEW_MODE=deny): REVIEW halts HARD — the agent
        # must change the action or come back with the missing approval. This
        # only moves decisions toward blocking; it is a local policy choice for
        # high-security deployments.
        if os.environ.get("ARCEZIA_REVIEW_MODE", "ask").lower() == "deny":
            return _decision("deny", f"Arcezia REVIEW→strict-deny (attach the missing approval or check, then retry): {cert.summary}")
        return _decision("ask", f"Arcezia REVIEW (approval required): {cert.summary}")
    # Allow is POSITIVE, not "everything the branches above did not catch". The
    # chain used to end in a bare `return _decision("allow", ...)`, so a verdict
    # that is neither ALLOW nor BLOCK nor REVIEW — a renamed value, an empty
    # string, a lowercase "allow" from some future server — satisfied no branch
    # and landed on allow. `cert.allow` is the conjunction (verdict is the
    # literal "ALLOW", fabrication not detected, no cross-step block), and the
    # other surfaces read the same way.
    if cert.allow:
        held = pass_hold_reason(cert, call)
        if held is not None:
            return _decision("deny", f"Arcezia {held} {cert.summary}")
        return _decision("allow", f"Arcezia ALLOW: {cert.summary}")
    return _decision(
        "deny",
        f"Arcezia DENY — the response carried no recognised verdict "
        f"({cert.verdict!r}), so nothing authorised this action: {cert.summary}")


# ── One Arcezia session per Claude Code session ─────────────────────────────
#
# The harness runs this hook as a fresh process for every tool call, so the
# client used to open a fresh session each time and nothing carried between
# calls, so a later step could not be judged in the light of an earlier one.
# Claude Code names its own
# session in the hook input; the Arcezia session opened for it is kept here,
# under a hash of that name, and re-attached on every later call. A stale entry
# (the service no longer knows the session) is dropped and a new one opened.
_SESSION_DIR = os.path.expanduser("~/.claude/arcezia-sessions")
_SESSION_DIR_AT_IMPORT = _SESSION_DIR


def _session_dir() -> str:
    """The session folder, resolved at call time (a test or a caller may set
    `_SESSION_DIR`; otherwise the current home's)."""
    if _SESSION_DIR != _SESSION_DIR_AT_IMPORT:
        return _SESSION_DIR
    return os.path.expanduser("~/.claude/arcezia-sessions")


def _observe_read(cc_session_id: str, tool_name: str, tool_input: dict,
                  cwd: Optional[str]) -> bool:
    """Record one in-workspace read in this session's journal (E2): the shell
    read it performs, its places named by their real paths."""
    try:
        atype, desc, domain = read_act(tool_name, tool_input, cwd, real=True)
    except Exception:
        return False
    return _hook_state.record_read(_session_dir(), cc_session_id, {
        "tool": tool_name, "action_type": atype, "action_description": desc, "domain": domain})


def _session_store_path(cc_session_id: str, api_key: Optional[str] = None) -> str:
    """One file per (API key, Claude Code session). The key is part of the
    name so a session opened under one key is never re-attached under another
    (another account, or a rotated key); neither value appears in clear."""
    if api_key is None:
        api_key = os.environ.get("ARCEZIA_API_KEY", "").strip()
    digest = hashlib.sha256(
        (api_key + "\0" + cc_session_id).encode("utf-8")).hexdigest()[:32]
    return os.path.join(_session_dir(), f"{digest}.json")


def _stored_record(cc_session_id: str, api_key: Optional[str] = None
                   ) -> Optional[tuple]:
    """(arcezia_session_id, config digest) as stored, or None."""
    try:
        with open(_session_store_path(cc_session_id, api_key)) as f:
            rec = json.load(f)
        sid = rec.get("arcezia_session_id") if isinstance(rec, dict) else None
        if not (isinstance(sid, str) and sid):
            return None
        config = rec.get("config")
        return sid, (config if isinstance(config, str) else None)
    except (OSError, ValueError):
        return None


def _stored_session(cc_session_id: str, api_key: Optional[str] = None) -> Optional[str]:
    rec = _stored_record(cc_session_id, api_key)
    return rec[0] if rec else None


def _store_session(cc_session_id: str, arcezia_session_id: str,
                   api_key: Optional[str] = None, config: Optional[str] = None) -> None:
    """Written to a temporary file and renamed into place, so two hooks
    running at once never leave a torn file behind (a torn file reads as no
    session, and the next call would open a fresh one without its history)."""
    import tempfile
    try:
        os.makedirs(_session_dir(), mode=0o700, exist_ok=True)
        path = _session_store_path(cc_session_id, api_key)
        fd, tmp = tempfile.mkstemp(dir=_session_dir(), prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump({"arcezia_session_id": arcezia_session_id, "config": config}, f)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
    except OSError:
        pass                      # best effort: the next call opens a new session


def _forget_session(cc_session_id: str, api_key: Optional[str] = None) -> None:
    try:
        os.remove(_session_store_path(cc_session_id, api_key))
    except OSError:
        pass


# A text block that is nothing but tagged elements (`<command-name>/clear
# </command-name>`, `<ide_opened_file>...</ide_opened_file>`,
# `<local-command-stdout>...`) is the harness wrapping a command or the IDE's
# context, not something the developer typed. Read by shape, not by a list of
# tag names.
_WRAPPER_BLOCK = re.compile(r"\s*(?:<([A-Za-z][\w-]*)>.*?</\1>\s*)+", re.S)


def _is_harness_wrapper(text: str) -> bool:
    return bool(_WRAPPER_BLOCK.fullmatch(text))


def _task_from_transcript(transcript_path: Optional[str], limit: int = 2000) -> str:
    """The developer's first message of this Claude Code session, read from the
    transcript the harness names — the session's stated purpose, sent as the
    task."""
    if not transcript_path or not os.path.exists(transcript_path):
        return ""
    try:
        with open(transcript_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(rec, dict) or rec.get("type") != "user":
                    continue
                # Records the harness writes in the user's name: meta notes
                # (the local-command caveat), a compaction summary, a record
                # shown in the transcript only. None is the developer's prompt.
                if rec.get("isMeta") or rec.get("isCompactSummary") or \
                        rec.get("isVisibleInTranscriptOnly"):
                    continue
                msg = rec.get("message") or {}
                content = msg.get("content") if isinstance(msg, dict) else None
                if isinstance(content, str):
                    content = [{"type": "text", "text": content}]
                if not isinstance(content, list):
                    continue
                text = " ".join(
                    b.get("text", "").strip() for b in content
                    if isinstance(b, dict) and b.get("type") == "text"
                    and isinstance(b.get("text"), str)
                    and not _is_harness_wrapper(b["text"])).strip()
                if text:
                    return text[:limit]
    except OSError:
        return ""
    return ""


def _load_capability_envelope() -> dict | None:
    """Load capability_envelope from ~/.claude/arcezia.json if it exists.

    Production pattern: human defines authority scope in a config file.
    The hook reads it at startup and injects into the session.

    A file that is NOT there is an honest absence: no envelope was declared, and
    the session opens without one. A file that IS there and cannot be read is a
    different fact, and it used to produce the same value — `except Exception:
    return None`. An envelope's axes set False are DENIALS, so silently dropping
    an unreadable one WIDENS authority: the hook would then verify against no
    declared scope at all and never say so. Unreadable is not empty. It
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


def _load_principal_rules() -> dict | None:
    """Your own restrictions for every session the hook opens: the
    `principal_rules` key of ~/.claude/arcezia.json (the same file as the
    envelope), in the form `start_session(principal_rules=...)` takes. An
    unreadable file raises, exactly as for the envelope: a rule that is
    silently dropped widens what the agent may do."""
    config_path = os.path.expanduser("~/.claude/arcezia.json")
    if not os.path.exists(config_path):
        return None
    try:
        with open(config_path) as f:
            cfg = json.load(f)
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            f"{config_path} exists but could not be read ({exc}); its session "
            f"rules cannot be dropped silently. Fix or remove the file.") from exc
    if not isinstance(cfg, dict):
        raise RuntimeError(f"{config_path} is not a JSON object.")
    rules = cfg.get("principal_rules")
    if rules is not None and not isinstance(rules, dict):
        raise RuntimeError(f"{config_path}: principal_rules must be a JSON object.")
    return rules


def _grant_file() -> str:
    """Where `arcezia grant-workspace` writes the signed grant (the hook's
    config folder, the same as arcezia.json)."""
    return os.path.expanduser("~/.claude/arcezia-workspace-grant.json")


def _load_workspace_grant(now: Optional[float] = None) -> Optional[str]:
    """The signed workspace grant `arcezia grant-workspace` wrote, when it is
    present and not expired by this machine's clock; else None, and sessions
    open without roots (the behaviour before grants).

    Only the SIGNED GRANT is read. The hook never reads, loads or asks for a
    private key: the agent can read anything the hook can, so the key stays
    with the principal (OS keychain / a passphrase-protected file), and the
    grant carries its own signature. A missing or unreadable file only means
    no roots — a grant can clear a location, never hold one, so dropping it
    cannot widen anything."""
    try:
        with open(_grant_file()) as f:
            rec = json.load(f)
    except (OSError, ValueError):
        return None
    token = rec.get("grant") if isinstance(rec, dict) else None
    if not isinstance(token, str) or token.count(".") != 1:
        return None
    try:
        from arcezia.signing import read_grant_claims
        exp = read_grant_claims(token).get("exp")
    except Exception:
        return None
    if not isinstance(exp, int) or exp <= (time.time() if now is None else now):
        return None
    return token


def _session_config_digest() -> Optional[str]:
    """A digest of the envelope, rules and workspace grant a new session
    would be opened with, or None when there are none. Stored beside the
    session so a session opened under other ones (or none) is never
    re-attached."""
    envelope = _load_capability_envelope()
    rules = _load_principal_rules()
    grant = _load_workspace_grant()
    if not envelope and not rules and not grant:
        return None
    blob = json.dumps({"envelope": envelope, "principal_rules": rules,
                       **({"workspace_grant": grant} if grant else {})},
                      sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _hook_task(payload: Optional[dict]) -> str:
    """The task this hook sends: TASK / ARCEZIA_TASK, else (unless
    ARCEZIA_TASK_FROM_TRANSCRIPT=0) the developer's first prompt of this
    Claude Code session (at most 2,000 characters)."""
    task = os.environ.get("TASK", os.environ.get("ARCEZIA_TASK", "")).strip()
    from_transcript = os.environ.get("ARCEZIA_TASK_FROM_TRANSCRIPT", "1").strip().lower()
    if not task and from_transcript not in ("0", "false", "no", "off"):
        task = _task_from_transcript((payload or {}).get("transcript_path"))
    return task


# ── Reusing a signed ALLOW (E3b, 2026-10-03) ─────────────────────────────────
#
# A repeat of a call whose every determining input is unchanged gets the same
# verdict, so the hook may answer it from a grant the SERVICE signed for that
# exact call (server/reuse_grant.py), without a round trip. Off unless the
# developer turns it on (ARCEZIA_HOOK_REUSE=1) AND pins the service's public
# key (ARCEZIA_SERVICE_PUBLIC_KEY or `service_public_key` in arcezia.json, from
# GET /v1/audit/public_key) — and the service issues grants only when its
# owner set a window. Only an ALLOW is ever reused; a hold is always re-asked;
# no credential is consumed or made.
#
# Owner design (2026-10-03), superseding a first version that bound a time
# window: no window and no tuned constant. The reuse key is the whole input
# vector. The hook's key (`_reuse_key`) holds what it recomputes on every
# call — the act, the tool, the real cwd, the repository's state (HEAD,
# working-tree status, the files the command names), the session config, the
# API key and URL, the task, the typed parameters, this SDK's version — and
# the grant binds the rest: the session id, the service's session state
# version and the account's contract version (both as last returned to this
# hook), the values of the facts the decision used, the engine build, and the
# envelope's own expiry (compared with this machine's clock). The service
# grants only when every fact is recomputable from that vector.

def _reuse_requested() -> bool:
    return os.environ.get("ARCEZIA_HOOK_REUSE", "").strip().lower() in ("1", "true", "yes", "on")


def _pinned_service_key() -> Optional[bytes]:
    """The service's Ed25519 public key (raw 32 bytes) the developer pinned,
    or None. Never fetched: a key the hook fetched could be one the agent
    put in its way."""
    import base64
    raw = os.environ.get("ARCEZIA_SERVICE_PUBLIC_KEY", "").strip()
    if not raw:
        try:
            with open(os.path.expanduser("~/.claude/arcezia.json")) as f:
                cfg = json.load(f)
            raw = str((cfg or {}).get("service_public_key") or "").strip() if isinstance(cfg, dict) else ""
        except (OSError, ValueError):
            raw = ""
    if not raw:
        return None
    try:
        key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except Exception:
        return None
    return key if len(key) == 32 else None


def _sha(obj) -> str:
    if isinstance(obj, str):
        return hashlib.sha256(obj.encode()).hexdigest()
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                     default=str).encode()).hexdigest()


def _repo_fingerprint(cwd: Optional[str], descriptions: list) -> str:
    """The working tree the call acts on: git HEAD and `git status
    --porcelain` (every modified, staged and untracked path), plus size and
    mtime of every existing path the command line names. Anything that
    cannot be read is recorded as such, so it can only make a key differ."""
    import subprocess
    parts: dict = {"cwd": os.path.realpath(cwd) if cwd else None}
    if cwd and os.path.isdir(cwd):
        for name, argv in (("head", ["git", "rev-parse", "HEAD"]),
                           ("status", ["git", "status", "--porcelain=v1", "-z"])):
            try:
                r = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=5)
                parts[name] = [r.returncode, _sha(r.stdout.decode("utf-8", "replace"))]
            except Exception as exc:                # noqa: BLE001
                parts[name] = ["unreadable", type(exc).__name__]
    files = []
    for d in descriptions:
        try:
            words = shlex.split(d)
        except ValueError:
            words = d.split()
        for w in words[1:]:
            p = _absolute(os.path.expanduser(w), cwd) if cwd else os.path.expanduser(w)
            try:
                st = os.stat(p)
            except OSError:
                continue
            files.append([os.path.realpath(p), st.st_size, st.st_mtime_ns])
    parts["files"] = sorted(files)
    return _sha(parts)


def _reuse_key(tool_name: str, act: tuple, *, cwd, repo_fp: str, task: str,
               action_parameters, config: Optional[str], cc_session: str,
               arcezia_session: str) -> str:
    try:
        from arcezia import __version__ as _sdk
    except Exception:                               # pragma: no cover
        _sdk = "?"
    return _sha({
        "tool": tool_name, "act": list(act), "cwd": os.path.realpath(cwd) if cwd else None,
        "repo": repo_fp, "task": _sha(task), "ap": action_parameters or {},
        "config": config, "cc": cc_session, "sid": arcezia_session,
        "key": _sha(os.environ.get("ARCEZIA_API_KEY", "").strip()),
        "url": os.environ.get("ARCEZIA_API_URL", "https://api.arcezia.com"),
        "domain_default": _DEFAULT_DOMAIN, "sdk": _sdk,
    })


def _grant_matches(grant, pub: bytes, *, act: tuple, task: str, action_parameters,
                   arcezia_session: str, state, contract, epoch=None,
                   now: Optional[float] = None) -> bool:
    """The service signed this grant, for this call, in the session state and
    contract version the hook last saw, and its envelope has not expired."""
    import base64
    if not (isinstance(grant, dict) and isinstance(grant.get("payload"), dict)
            and isinstance(grant.get("signature"), str) and state and contract):
        return False
    p = grant["payload"]
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        sig = base64.urlsafe_b64decode(grant["signature"] + "=" * (-len(grant["signature"]) % 4))
        Ed25519PublicKey.from_public_bytes(pub).verify(
            sig, json.dumps(p, sort_keys=True, separators=(",", ":"), default=str).encode())
    except Exception:
        return False
    at, desc, dom = act
    now = time.time() if now is None else now
    env_exp = p.get("env_exp")
    return (p.get("v") == 3 and p.get("verdict") == "ALLOW"
            and p.get("approval") is False                      # U2: never an approval-consuming one
            and isinstance(epoch, int) and p.get("rep") == epoch  # U2: no newer epoch seen
            and isinstance(p.get("lim"), str)
            and p.get("sid") == arcezia_session and p.get("state") == state
            and p.get("cv") == contract and isinstance(p.get("fdg"), str)
            and p.get("at") == at and p.get("dom") == dom and p.get("adg") == _sha(desc or "")
            and p.get("apd") == _sha(action_parameters or {}) and p.get("tdg") == _sha(task or "")
            and (env_exp is None or (isinstance(env_exp, (int, float)) and now < env_exp)))


def _reuse_lookup(payload: dict, tool_name: str, tool_input: dict, acts: list,
                  cwd: Optional[str], cc_session: str) -> Optional[dict]:
    """The inputs of a reuse decision, and whether every act of this call has
    a valid grant (`hit`). None when reuse cannot apply at all."""
    pub = _pinned_service_key()
    if pub is None:
        return None
    config = _session_config_digest()
    stored = _stored_record(cc_session)
    task = _hook_task(payload)
    ap = _with_real_cwd(scalar_params(tool_input), cwd)
    ctx = {"pub": pub, "config": config, "task": task, "ap": ap, "cwd": cwd,
           "tool": tool_name, "repo": _repo_fingerprint(cwd, [d for _a, d, _dm in acts]),
           "hit": False}
    if not stored or stored[1] != config:
        return ctx                               # a new session would be opened
    if _hook_state.unreported(_session_dir(), cc_session)[2]:
        return ctx                               # unreported reads change the state
    cache = _hook_state.reuse_load(_session_dir(), cc_session)
    if cache.get("pending"):
        return ctx                               # an earlier answer was never recorded
    holds: list = []
    for act in acts:
        k = _reuse_key(tool_name, act, cwd=cwd, repo_fp=ctx["repo"], task=task,
                       action_parameters=ap, config=config, cc_session=cc_session,
                       arcezia_session=stored[0])
        g = (cache.get("grants") or {}).get(k)
        if isinstance(g, dict) and g.get("hold") in ("REVIEW", "BLOCK"):
            # U3: a hold under the identical vector is re-used as a hold.
            holds.append(g)
            continue
        if not _grant_matches(g, pub, act=act, task=task, action_parameters=ap,
                              arcezia_session=stored[0], state=cache.get("state"),
                              contract=cache.get("contract"), epoch=cache.get("epoch")):
            return ctx
    ctx["hit"] = True
    if holds:
        ctx["hold"] = max(holds, key=lambda h: h["hold"] == "BLOCK")
    return ctx


def _reuse_record(ctx: dict, acts: list, certs: list, sid, cc_session: str,
                  *, allowed: Optional[list] = None) -> None:
    """After a verified call: remember the service's state version, and the
    grants it signed for acts of this call, keyed by every input.

    ``allowed[i]`` is whether this hook allowed act i. A grant is kept only for
    an act the hook allowed: an ALLOW held here (its pass withheld, or bound
    to another call) must not come back later as a re-used ALLOW."""
    if not certs or len(certs) != len(acts) or not isinstance(sid, str) or not sid:
        return
    raws = [getattr(c, "raw", None) or {} for c in certs]
    state = raws[-1].get("session_state") if isinstance(raws[-1], dict) else None
    contract = raws[-1].get("contract_version") if isinstance(raws[-1], dict) else None
    epochs = [r.get("revocation_epoch") for r in raws if isinstance(r, dict)]
    epoch = max((e for e in epochs if isinstance(e, int)), default=None)
    if any(not isinstance(e, int) for e in epochs):
        epoch = None                              # an answer without an epoch: unknown
    grants: dict = {}
    if allowed is None or len(allowed) != len(acts):
        allowed = [False] * len(acts)
    for act, raw, cert, ok in zip(acts, raws, certs, allowed):
        k = _reuse_key(ctx["tool"], act, cwd=ctx["cwd"], repo_fp=ctx["repo"], task=ctx["task"],
                       action_parameters=ctx["ap"], config=ctx["config"], cc_session=cc_session,
                       arcezia_session=sid)
        if (state and isinstance(raw, dict) and raw.get("session_state") == state
                and not getattr(cert, "degraded", False)
                and (getattr(cert, "block", False) or getattr(cert, "review", False))):
            # U3: a hold is re-usable as a hold under the identical vector.
            grants[k] = {"hold": "BLOCK" if cert.block else "REVIEW",
                         "summary": str(getattr(cert, "summary", ""))[:500]}
            continue
        if not ok:
            continue
        g = raw.get("reuse_grant") if isinstance(raw, dict) else None
        if not (isinstance(g, dict) and isinstance(g.get("payload"), dict)):
            continue
        if not state or g["payload"].get("state") != state:
            continue
        if not _grant_matches(g, ctx["pub"], act=act, task=ctx["task"], action_parameters=ctx["ap"],
                              arcezia_session=sid, state=state, contract=contract, epoch=epoch):
            continue
        grants[k] = g
    _hook_state.reuse_update(_session_dir(), cc_session,
                             state=state if isinstance(state, str) else None, grants=grants,
                             contract=contract if isinstance(contract, str) else None,
                             epoch=epoch)


def _default_verifier(payload: Optional[dict] = None):
    api_key = os.environ.get("ARCEZIA_API_KEY", "").strip()
    if not api_key:
        return None
    payload = payload or {}
    from arcezia.client import Arcezia
    task = _hook_task(payload)
    az = Arcezia(
        api_key=api_key,
        task=task,
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

    # Load capability_envelope and principal_rules from config (the
    # human-defined authority scope and the user's own restrictions).
    envelope = _load_capability_envelope()
    rules = _load_principal_rules()
    grant = _load_workspace_grant()
    if grant:
        az.set_workspace_grant(grant)
    config = _session_config_digest()
    cc_session = payload.get("session_id")
    cc_session = cc_session if isinstance(cc_session, str) and cc_session else None
    stored = _stored_record(cc_session) if cc_session else None
    if stored and stored[1] == config:
        az.attach_session(stored[0])
    elif envelope or rules:
        # Every session this hook opens carries the envelope and the rules —
        # including the one that replaces a session opened under other ones.
        kwargs: dict = {"capability_envelope": envelope}
        if rules is not None:
            kwargs["principal_rules"] = rules
        az.start_session(**kwargs)
    # Without either, the first verification opens the session in the same
    # round trip; run_hook records it for the next call either way.
    return az


# ── settings.json install helper ──────────────────────────────────────────────

def _hook_command() -> str:
    """The command Claude Code should run for the hook.

    It used to be the bare string ``python -m arcezia.integrations.claude_code
    hook``. ``python`` is resolved by the harness's PATH, not by the
    interpreter arcezia is installed into, so a venv install plus a system
    ``python`` gave ``ModuleNotFoundError`` → exit 1, and a machine with no
    ``python`` on PATH gave exit 127. Both are non-blocking errors to the
    harness: the tool runs. Name the interpreter, or the console script
    that already carries it, so the hook cannot be missing at run time.
    """
    return _hook_command_for("hook")


def _hook_command_for(sub: str) -> str:
    import shlex
    import shutil
    console = shutil.which("arcezia-hook")
    if console:
        return f"{shlex.quote(console)} {sub}"
    return f"{shlex.quote(sys.executable)} -m arcezia.integrations.claude_code {sub}"


_HOOK_COMMAND = _hook_command()
# E3c: at Claude Code session start, open the warm connection the hook's
# calls will ride (the local helper; see _conn_helper.py).
_WARM_COMMAND = _hook_command_for("warm")
_WARM_TIMEOUT_SECONDS = 10


def _warm_entry() -> dict:
    return {"type": "command", "command": _WARM_COMMAND, "timeout": _WARM_TIMEOUT_SECONDS}


def _helper_enabled() -> bool:
    """The local connection helper (E3c) is on unless ARCEZIA_HOOK_HELPER=0.
    It only carries requests; with it off or unreachable the hook calls the
    API directly, as before."""
    return os.environ.get("ARCEZIA_HOOK_HELPER", "1").strip().lower() not in ("0", "false", "no", "off")

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
                {"matcher": "*", "hooks": [_hook_entry()]}
            ],
            "SessionStart": [
                {"hooks": [_warm_entry()]}
            ],
        }
    }


def _hook_entry() -> dict:
    """One hook entry. `timeout` is above the hook's own deadline: the hook
    denies at its deadline, so the harness never kills it undecided (a killed
    hook is a non-blocking error, and the tool would run)."""
    return {"type": "command", "command": _HOOK_COMMAND, "timeout": _HARNESS_TIMEOUT_SECONDS}


def install(settings_path: Optional[str] = None) -> str:
    """
    Merge the PreToolUse hook into the user's Claude Code settings.json.
    Returns the path written. Idempotent — does not duplicate the hook.

    Refuses rather than overwrites when the existing file cannot be parsed.
    A ``json.JSONDecodeError`` used to be swallowed into ``settings = {}``,
    which turned the merge into a FULL OVERWRITE: the user's
    ``permissions.deny`` list — a security control — plus every other hook and
    every env var were destroyed with no warning and no backup. A
    comment, a trailing comma, a BOM or a truncated previous write was enough.
    So: on a parse error we raise and name the path, and on every real write we
    copy the original to a timestamped ``.bak-`` first.
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
    ours = [h for entry in pre for h in entry.get("hooks", [])
            if isinstance(h, dict) and _is_arcezia_hook(h.get("command"))]
    if not ours:
        pre.append({"matcher": "*", "hooks": [_hook_entry()]})
    for h in ours:
        # An entry written before the deadline existed has no timeout, or one
        # the hook's deadline does not fit under: give it the harness timeout.
        t = h.get("timeout")
        if not isinstance(t, (int, float)) or t <= _HOOK_DEADLINE_SECONDS:
            h["timeout"] = _HARNESS_TIMEOUT_SECONDS
    start = hooks.setdefault("SessionStart", [])
    if not any(isinstance(h, dict) and _is_arcezia_hook(h.get("command"))
               for entry in start if isinstance(entry, dict) for h in entry.get("hooks", [])):
        start.append({"hooks": [_warm_entry()]})
    if original is not None:
        import time
        backup = path.with_name(f"{path.name}.bak-{int(time.time())}")
        backup.write_text(original)
    path.write_text(json.dumps(settings, indent=2))
    return str(path)


# A read-only route that needs the admin role — the same role that registers
# probe webhooks and declarations. GET /v1/declarations does not need it (any
# verify key reads its own), so a 200 there said nothing about write access.
_ADMIN_PROBE_PATH = "/v1/siem/dlq"


def _key_has_admin_role(api_key: str) -> Optional[bool]:
    """True / False when the service said which; None when it could not tell.

    The role check runs before the route's own work, so any answer past it (a
    200, or a 503 from the queue behind it) means the role passed; a 403
    `insufficient_role` means it did not; anything else is unknown."""
    import urllib.error
    import urllib.request
    req = urllib.request.Request(
        os.environ.get("ARCEZIA_API_URL", "https://api.arcezia.com").rstrip("/") + _ADMIN_PROBE_PATH,
        headers={"Authorization": f"Bearer {api_key}", "User-Agent": "arcezia-hook/install"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return True if r.status == 200 else None
    except urllib.error.HTTPError as exc:
        if exc.code == 503:
            return True
        if exc.code == 403:
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            return False if "insufficient_role" in body else None
        return None
    except Exception:
        return None


def _warn_if_key_can_write_evidence() -> None:
    """The key in the agent's environment should only verify. A key with the
    admin role can also register probe webhooks and declarations — the
    agent could then answer its own questions. Said once, at install."""
    api_key = os.environ.get("ARCEZIA_API_KEY", "").strip()
    if not api_key:
        return
    can_write = _key_has_admin_role(api_key)
    if can_write is None:
        print("NOTE: could not determine whether ARCEZIA_API_KEY has the owner or admin role "
              "(the service did not say). Such a key can also register checks, so an agent "
              "that can read it could answer its own questions. Keep check secrets and your "
              "signing key on a machine the agent cannot read.", file=sys.stderr)
        return
    if can_write:
        print("WARNING: ARCEZIA_API_KEY has the owner or admin role. The agent runs with this key "
              "in its environment and could register checks that answer its own questions. Keep "
              "check secrets and your signing key on a machine the agent cannot read.",
              file=sys.stderr)


def main(argv: Optional[list[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if argv and argv[0] == "install":
        written = install()
        print(f"Arcezia PreToolUse hook installed → {written}")
        print("Set ARCEZIA_API_KEY (and optionally TASK) in your environment.")
        _warn_if_key_can_write_evidence()
        return 0
    if argv and argv[0] == "print-config":
        print(json.dumps(settings_snippet(), indent=2))
        return 0
    api_url = os.environ.get("ARCEZIA_API_URL", "https://api.arcezia.com")
    if argv and argv[0] == "warm":
        # SessionStart: open the helper's connection now. Never blocks the
        # session and never fails it.
        if _helper_enabled():
            try:
                from arcezia.integrations import _conn_helper
                _conn_helper.warm(api_url)
            except Exception:
                pass
        return 0
    if _helper_enabled():
        # This process's requests ride the helper's warm connection when it
        # is up; when it is not, they go direct and one is started for the
        # next call (E3c).
        try:
            from arcezia import client as _client
            from arcezia.integrations import _conn_helper
            if _conn_helper.ensure_started(api_url):
                _client._HELPER_API_URL = api_url
        except Exception:
            pass
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
