"""`arcezia` command line: principal-side actions (2026-10-01).

    arcezia grant-workspace <root> [<root> ...] --for <duration>
    arcezia grant-workspace --revoke [--grant-id <id>]

Run it on the PRINCIPAL's side, as the person. The agent can read anything
the Claude Code hook can read, so the principal's Ed25519 private key must
never be where the hook (or the agent) reads it. This command therefore loads
the key only from:

  1. the OS keychain — macOS `security` (generic password, service
     `arcezia-signing-key`, account `--key-name`, default "default"), or the
     Linux secret service through the `keyring` package when it is installed;
  2. otherwise a passphrase-protected key file (encrypted PKCS#8 PEM) whose
     path and passphrase are asked for at the terminal.

It never reads a key from the hook's config folder (~/.claude), from an
environment variable, or from the grant file, and it refuses a key file that
is inside the hook's config folder or is not passphrase-protected.

What it writes to the hook's config folder is ONLY the signed grant
(~/.claude/arcezia-workspace-grant.json): the account id, the roots, the
window, the grant id and the signature. A grant grants exactly those roots for
that window to sessions of that account; anyone who reads it (the agent
included) can present it and gains nothing the principal did not grant.

Store the key once, e.g. on macOS:

    security add-generic-password -s arcezia-signing-key -a default -w <base64url private key>
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import subprocess
import sys
import time
from typing import Optional

KEYCHAIN_SERVICE = "arcezia-signing-key"


def hook_config_dir() -> str:
    """The Claude Code hook's config folder (read by the hook, so by the agent)."""
    return os.path.expanduser("~/.claude")


def grant_file() -> str:
    return os.path.join(hook_config_dir(), "arcezia-workspace-grant.json")

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class CLIError(Exception):
    pass


def parse_duration(text: str) -> int:
    """Seconds in `30m`, `8h`, `2d`, `1w`, `3600s`. Refuses anything else."""
    m = re.fullmatch(r"\s*(\d+)\s*([smhdw])\s*", text or "")
    if not m or int(m.group(1)) <= 0:
        raise CLIError(f"--for takes a duration like 30m, 8h or 24h (at most 24 hours); got {text!r}")
    return int(m.group(1)) * _UNITS[m.group(2)]


def _inside(path: str, folder: str) -> bool:
    path, folder = os.path.realpath(path), os.path.realpath(folder)
    return path == folder or path.startswith(folder.rstrip(os.sep) + os.sep)


# ── The principal's key: keychain, or a passphrase-protected file ─────────────

def _key_from_macos_keychain(name: str) -> Optional[str]:
    if sys.platform != "darwin":
        return None
    try:
        out = subprocess.run(
            ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", name, "-w"],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    secret = (out.stdout or "").strip()
    return secret if out.returncode == 0 and secret else None


def _key_from_secret_service(name: str) -> Optional[str]:
    try:
        import keyring  # type: ignore
    except Exception:
        return None
    try:
        secret = keyring.get_password(KEYCHAIN_SERVICE, name)
    except Exception:
        return None
    return secret.strip() if isinstance(secret, str) and secret.strip() else None


def _key_from_protected_file(path: str, passphrase: str):
    """An Ed25519 private key from an ENCRYPTED PKCS#8 PEM file."""
    if _inside(path, hook_config_dir()):
        raise CLIError(f"{path} is inside {hook_config_dir()}, which the hook (and so the agent) "
                       "reads. Keep the private key somewhere the agent cannot read.")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:  # pragma: no cover
        raise CLIError("reading a key file needs the 'cryptography' package") from exc
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as exc:
        raise CLIError(f"could not read the key file: {exc}") from exc
    if not passphrase:
        raise CLIError("the key file must be passphrase-protected; no passphrase was given")
    try:
        key = serialization.load_pem_private_key(data, password=passphrase.encode("utf-8"))
    except TypeError as exc:
        raise CLIError("the key file is not passphrase-protected; encrypt it "
                       "(PKCS#8 PEM with a passphrase)") from exc
    except ValueError as exc:
        raise CLIError(f"the key file could not be decrypted: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise CLIError("the key file does not hold an Ed25519 private key")
    return key


def load_signing_key(name: str = "default", *, prompt=input, secret_prompt=getpass.getpass):
    """The principal's Ed25519 private key: keychain first, then a
    passphrase-protected file named at the terminal. Never the hook's config,
    never the environment."""
    from arcezia.signing import _load_private_key
    for source in (_key_from_macos_keychain, _key_from_secret_service):
        secret = source(name)
        if secret:
            try:
                return _load_private_key(secret)
            except Exception as exc:
                raise CLIError(f"the key stored under {KEYCHAIN_SERVICE}/{name} is not an "
                               f"Ed25519 private key: {exc}") from exc
    _no_terminal = CLIError(
        f"no signing key in the keychain (service {KEYCHAIN_SERVICE}, name {name!r}), and no "
        "terminal to ask for a key file. Run the command in a terminal, or store the key "
        "in the keychain first.")
    try:
        path = prompt("No signing key in the keychain. Path to your passphrase-protected "
                      "Ed25519 key file: ").strip()
    except EOFError:
        raise _no_terminal from None
    if not path:
        raise CLIError("no signing key: store one in the keychain or give a key file")
    path = os.path.expanduser(path)
    try:
        passphrase = secret_prompt("Passphrase: ")
    except EOFError:
        raise _no_terminal from None
    return _key_from_protected_file(path, passphrase)


# ── The grant file ────────────────────────────────────────────────────────────

def write_grant_file(token: str, claims: dict, path: Optional[str] = None) -> str:
    """Write ONLY the signed grant (and its readable claims) to the hook's
    config folder, atomically."""
    import tempfile
    path = path or grant_file()
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    record = {"grant": token, "grant_id": claims["gid"], "account_id": claims["acct"],
              "roots": claims["roots"], "not_before": claims["nbf"], "expires_at": claims["exp"]}
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".grant-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(record, f, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return path


def read_grant_file(path: Optional[str] = None) -> Optional[dict]:
    path = path or grant_file()
    try:
        with open(path) as f:
            rec = json.load(f)
    except (OSError, ValueError):
        return None
    return rec if isinstance(rec, dict) and isinstance(rec.get("grant"), str) else None


def _account_id(args) -> int:
    if args.account_id is not None:
        return int(args.account_id)
    api_key = os.environ.get("ARCEZIA_API_KEY", "").strip()
    if not api_key:
        raise CLIError("pass --account-id (the numeric id POST /v1/session returns as "
                       "api_key_id), or set ARCEZIA_API_KEY to an owner/admin key to look it up")
    from arcezia.client import Arcezia
    acct = Arcezia(api_key=api_key, api_url=os.environ.get("ARCEZIA_API_URL")).token_key_status().get(
        "api_key_id")
    if not isinstance(acct, int):
        raise CLIError("the service did not report this key's account id; pass --account-id")
    return acct


def grant_workspace(args, *, key_loader=load_signing_key, now: Optional[int] = None) -> dict:
    from arcezia.signing import mint_workspace_grant, read_grant_claims
    if not args.roots:
        raise CLIError("name at least one workspace folder")
    if not args.duration:
        raise CLIError("--for <duration> is required (e.g. --for 8h)")
    seconds = parse_duration(args.duration)
    from arcezia.signing import WORKSPACE_GRANT_MAX_SECONDS
    if seconds > WORKSPACE_GRANT_MAX_SECONDS:
        raise CLIError(f"a workspace grant can last at most 24 hours; --for {args.duration} is longer. "
                       "Use --for 24h or less, and grant it again when it ends.")
    roots = []
    for r in args.roots:
        real = os.path.realpath(os.path.expanduser(r))
        if not os.path.isdir(real):
            raise CLIError(f"{r!r} is not a folder")
        if real == os.path.sep:
            raise CLIError("the root '/' is not a workspace")
        roots.append(real)
    acct = _account_id(args)
    key = key_loader(args.key_name)
    nbf = int(time.time()) if now is None else int(now)
    token = mint_workspace_grant(key, roots, api_key_id=acct, not_before=nbf,
                                 expires_at=nbf + seconds)
    claims = read_grant_claims(token)
    path = write_grant_file(token, claims, args.out or None)
    return {"grant_id": claims["gid"], "roots": claims["roots"], "expires_at": claims["exp"],
            "written": path}


def revoke_workspace(args, *, client=None) -> dict:
    path = args.out or grant_file()
    rec = read_grant_file(path) or {}
    gid = args.grant_id or rec.get("grant_id")
    if not gid:
        raise CLIError(f"no grant id: pass --grant-id, or keep {path} to revoke the grant it holds")
    exp = rec.get("expires_at") if rec.get("grant_id") == gid else None
    # The local file goes first: no new session presents it, even if the
    # service cannot be reached.
    if rec.get("grant_id") == gid:
        try:
            os.remove(path)
        except OSError:
            pass
    if client is None:
        api_key = os.environ.get("ARCEZIA_API_KEY", "").strip()
        if not api_key:
            raise CLIError("set ARCEZIA_API_KEY (an owner/admin key) so the service can revoke "
                           "the grant for sessions already open")
        from arcezia.client import Arcezia
        client = Arcezia(api_key=api_key, api_url=os.environ.get("ARCEZIA_API_URL"))
    out = client.revoke_workspace_grant(gid, expires_at=exp if isinstance(exp, int) else None)
    return {"grant_id": gid, "revoked": bool((out or {}).get("ok")), "local_file_removed": True}


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(prog="arcezia")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("grant-workspace",
                       help="sign the agent's workspace folders (principal side)")
    g.add_argument("roots", nargs="*")
    g.add_argument("--for", dest="duration")
    g.add_argument("--revoke", action="store_true")
    g.add_argument("--grant-id")
    g.add_argument("--account-id", type=int)
    g.add_argument("--key-name", default="default")
    g.add_argument("--out", help=argparse.SUPPRESS)
    args = p.parse_args(argv)
    try:
        if args.revoke:
            if args.roots or args.duration:
                raise CLIError("--revoke takes no folders and no --for")
            print(json.dumps(revoke_workspace(args), indent=1))
        else:
            print(json.dumps(grant_workspace(args), indent=1))
    except CLIError as exc:
        print(f"arcezia: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
