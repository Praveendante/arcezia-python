"""A warm HTTPS connection shared by short-lived hook processes (E3c, 2026-10-03).

Claude Code runs the hook as a new process for every tool call, so every
verdict paid a fresh TCP + TLS handshake (measured live: ~310 ms on a reused
connection from India to us-east4, ~530 ms with a new handshake per call). This
helper is a small local process that keeps ONE kept-alive connection to the
API and forwards the hook's requests over a Unix domain socket.

Security, stated once:
  * The socket lives in a directory only this user can enter (0700, owned by
    this uid — refused otherwise), the socket itself is 0600, and when the OS
    can say who connected (SO_PEERCRED / LOCAL_PEERCRED) a different uid is
    refused. Another local user cannot reach it.
  * The helper holds no API key. Each request carries its own Authorization
    header, which is forwarded and never written anywhere.
  * It forwards only to the ONE API base it was started for, and only paths
    under /v1/: a request cannot point it at another host.
  * TLS is the standard library's default context (certificate and hostname
    verified). Nothing a request carries can change that.
  * It exits after an idle period, and the hook falls back to a direct request
    whenever the helper cannot be reached — the helper can only make a call
    faster, never decide one.

Started on demand by the hook (`ensure_started`) and warmed at Claude Code
session start (`arcezia-hook warm`, a SessionStart hook).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Optional
from urllib.parse import urlparse

IDLE_SECONDS = int(os.environ.get("ARCEZIA_HELPER_IDLE", "900") or 900)
_MAX_FRAME = 8 * 1024 * 1024
_START_GRACE = 10.0


class HelperUnavailable(Exception):
    """The helper could not be reached; nothing was sent through it."""


# ── where the socket lives ───────────────────────────────────────────────────

def _run_dir() -> str:
    base = os.environ.get("XDG_RUNTIME_DIR")
    if base and os.path.isdir(base):
        return os.path.join(base, "arcezia")
    return os.path.join(os.path.expanduser("~"), ".claude", "arcezia-run")


def _private_dir() -> Optional[str]:
    """The run directory, created 0700 if missing; None when it exists but
    another user owns it or others can enter it."""
    d = _run_dir()
    try:
        os.makedirs(d, mode=0o700, exist_ok=True)
        st = os.stat(d)
    except OSError:
        return None
    if st.st_uid != os.getuid() or (st.st_mode & 0o077):
        return None
    return d


def base_of(api_url: str) -> str:
    u = urlparse(api_url)
    scheme = (u.scheme or "https").lower()
    port = u.port or (443 if scheme == "https" else 80)
    return f"{scheme}://{(u.hostname or '').lower()}:{port}"


def socket_path(api_url: str) -> Optional[str]:
    d = _private_dir()
    if d is None:
        return None
    tag = hashlib.sha256(base_of(api_url).encode()).hexdigest()[:12]
    path = os.path.join(d, f"h-{tag}.sock")
    # A Unix socket path is short (104 bytes on macOS, 108 on Linux): a
    # longer one cannot be bound, so there is no helper and calls go direct.
    return path if len(path.encode()) <= 100 else None


# ── framing ──────────────────────────────────────────────────────────────────

def _send(sock: socket.socket, obj: dict) -> None:
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("helper closed the connection")
        buf += chunk
    return buf


def _recv(sock: socket.socket) -> dict:
    (n,) = struct.unpack(">I", _recv_exact(sock, 4))
    if n > _MAX_FRAME:
        raise ValueError("frame too large")
    return json.loads(_recv_exact(sock, n).decode())


# ── client side (the hook process) ───────────────────────────────────────────

def request(api_url: str, method: str, url: str, headers: dict, body: Optional[bytes],
            timeout: float) -> tuple:
    """Send one request through the helper. Raises HelperUnavailable when the
    helper cannot be reached (nothing was sent); raises ConnectionError when the helper
    took the request but the API could not be reached (ConnectionError, a
    network error like a direct call's)."""
    if base_of(url) != base_of(api_url):
        raise HelperUnavailable("another host")
    path = socket_path(api_url)
    if path is None or not os.path.exists(path):
        raise HelperUnavailable("no helper")
    u = urlparse(url)
    rel = (u.path or "/") + (("?" + u.query) if u.query else "")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout + 5)
    try:
        try:
            s.connect(path)
        except OSError as exc:
            raise HelperUnavailable(str(exc)) from exc
        _send(s, {"method": method, "path": rel, "headers": headers,
                  "body": base64.b64encode(body).decode() if body is not None else None,
                  "timeout": timeout})
        resp = _recv(s)
    finally:
        s.close()
    if "error" in resp:
        raise ConnectionError(f"via helper: {resp['error']}")
    return int(resp["status"]), base64.b64decode(resp.get("body") or "")


def ensure_started(api_url: str) -> bool:
    """True when a helper is listening; otherwise start one in the background
    (at most once per grace period) and return False — this call goes direct."""
    path = socket_path(api_url)
    if path is None:
        return False
    if os.path.exists(path):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            s.connect(path)
            return True
        except OSError:
            pass
        finally:
            s.close()
    marker = path + ".starting"
    try:
        if time.time() - os.stat(marker).st_mtime < _START_GRACE:
            return False
    except OSError:
        pass
    try:
        with open(marker, "w"):
            pass
        os.chmod(marker, 0o600)
        subprocess.Popen(
            [sys.executable, "-m", "arcezia.integrations._conn_helper", "serve", api_url],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True)
    except OSError:
        pass
    return False


# ── server side (the helper process) ─────────────────────────────────────────

def _peer_uid(conn: socket.socket) -> Optional[int]:
    try:
        if hasattr(socket, "SO_PEERCRED"):                       # Linux
            raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            return struct.unpack("3i", raw)[1]
        if sys.platform == "darwin":                             # LOCAL_PEERCRED
            raw = conn.getsockopt(0, 0x001, 4 + 4 + 2 + 16 * 4 + 2)
            return struct.unpack_from("I", raw, 4)[0]
    except OSError:
        return None
    return None


def serve(api_url: str, *, idle: float = IDLE_SECONDS, ready: "threading.Event | None" = None) -> int:
    """Run the helper for `api_url` until idle. Returns 0."""
    from arcezia import _keepalive
    path = socket_path(api_url)
    if path is None:
        return 1
    base = base_of(api_url)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if os.path.exists(path):
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.connect(path)
                return 0                          # another helper already serves
            except OSError:
                os.unlink(path)                   # stale
            finally:
                probe.close()
        old = os.umask(0o177)
        try:
            srv.bind(path)
        finally:
            os.umask(old)
        os.chmod(path, 0o600)
        srv.listen(16)
        srv.settimeout(0.5)
    except OSError:
        srv.close()
        return 1
    finally:
        try:
            os.remove(path + ".starting")
        except OSError:
            pass
    if ready is not None:
        ready.set()
    last = [time.monotonic()]
    me = os.getuid()

    def _handle(conn: socket.socket) -> None:
        try:
            uid = _peer_uid(conn)
            if uid is not None and uid != me:
                return
            req = _recv(conn)
            rel = req.get("path") or ""
            if not (isinstance(rel, str) and rel.startswith("/v1/")) or "\\" in rel:
                _send(conn, {"error": "path refused"})
                return
            method = str(req.get("method") or "GET").upper()
            if method not in ("GET", "POST", "DELETE"):
                _send(conn, {"error": "method refused"})
                return
            body = base64.b64decode(req["body"]) if req.get("body") is not None else None
            headers = {str(k): str(v) for k, v in (req.get("headers") or {}).items()}
            timeout = float(req.get("timeout") or 30.0)
            try:
                status, raw = _keepalive.request(method, base + rel, headers, body, timeout)
            except Exception as exc:              # noqa: BLE001 — reported to the caller
                _send(conn, {"error": f"{type(exc).__name__}: {exc}"})
                return
            _send(conn, {"status": status, "body": base64.b64encode(raw).decode()})
        except Exception:
            pass
        finally:
            last[0] = time.monotonic()
            conn.close()

    try:
        while time.monotonic() - last[0] < idle:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            last[0] = time.monotonic()
            threading.Thread(target=_handle, args=(conn,), daemon=True).start()
    finally:
        srv.close()
        try:
            os.unlink(path)
        except OSError:
            pass
        _keepalive.reset()
    return 0


def warm(api_url: str, timeout: float = 5.0) -> bool:
    """Start the helper if needed and open its connection now (a GET of the
    health route), so the first tool call of a session pays no handshake."""
    if not ensure_started(api_url):
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(0.05)
            p = socket_path(api_url)
            if p and os.path.exists(p):
                break
    try:
        request(api_url, "GET", api_url.rstrip("/") + "/v1/health",
                {"User-Agent": "arcezia-hook/warm"}, None, timeout)
        return True
    except Exception:
        return False


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "serve":
        raise SystemExit(serve(sys.argv[2]))
    raise SystemExit(2)
