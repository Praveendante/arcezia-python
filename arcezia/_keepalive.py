"""Persistent HTTPS connections for the stdlib transport.

``urllib.request.urlopen`` opens a new TCP + TLS connection for every call.
For a verdict that is the whole cost: from a client far from the API the
handshake is two round trips before the request is even sent, roughly 300 ms,
against about 40 ms of work on the server. Re-establishing a connection to
the same host is re-making a distinction already made ("this peer is
Arcezia, this channel is private"), and its forced cost is zero: make it
once and keep the channel.

One ``http.client`` connection per (scheme, host, port), guarded by a lock so
the SDK stays safe to call from threads. A request that fails on a connection
the server has quietly closed (idle keep-alive timeout) is retried once on a
fresh connection — that is the only retry here; policy retries live in the
caller. Every other error propagates unchanged.
"""
from __future__ import annotations

import http.client
import socket
import threading
from urllib.parse import urlparse

_CONNS: dict[tuple[str, str, int], http.client.HTTPConnection] = {}
_LOCKS: dict[tuple[str, str, int], threading.Lock] = {}
_REGISTRY_LOCK = threading.Lock()

_STALE = (
    http.client.RemoteDisconnected,
    http.client.BadStatusLine,
    http.client.CannotSendRequest,
    http.client.ResponseNotReady,
    ConnectionResetError,
    BrokenPipeError,
)


def _key(url: str) -> tuple[str, str, int, str]:
    u = urlparse(url)
    scheme = (u.scheme or "https").lower()
    port = u.port or (443 if scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    return scheme, (u.hostname or "").lower(), port, path


def _open(scheme: str, host: str, port: int, timeout: float) -> http.client.HTTPConnection:
    if scheme == "https":
        return http.client.HTTPSConnection(host, port, timeout=timeout)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def request(method: str, url: str, headers: dict, body: bytes | None, timeout: float) -> tuple[int, bytes]:
    """Send one request over the kept connection for ``url``'s host.

    Returns (status, raw body). Raises the underlying socket/HTTP error when
    the request cannot be completed even on a fresh connection.
    """
    scheme, host, port, path = _key(url)
    k = (scheme, host, port)
    with _REGISTRY_LOCK:
        lock = _LOCKS.setdefault(k, threading.Lock())
    with lock:
        for attempt in (0, 1):
            conn = _CONNS.get(k)
            fresh = conn is None
            if fresh:
                conn = _open(scheme, host, port, timeout)
                _CONNS[k] = conn
            else:
                conn.timeout = timeout
                if conn.sock is not None:
                    conn.sock.settimeout(timeout)
            try:
                conn.request(method, path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
                if resp.getheader("Connection", "").lower() == "close":
                    _drop(k)
                return resp.status, data
            except _STALE + (socket.timeout, OSError) as exc:
                _drop(k)
                # A stale kept connection fails on the FIRST attempt only; a
                # fresh one that fails is a real network error and propagates.
                if fresh or attempt == 1 or isinstance(exc, socket.timeout):
                    raise
        raise RuntimeError("unreachable")  # pragma: no cover


def _drop(k: tuple[str, str, int]) -> None:
    conn = _CONNS.pop(k, None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass


def reset() -> None:
    """Close every kept connection (tests; fork-safety after os.fork)."""
    with _REGISTRY_LOCK:
        for k in list(_CONNS):
            _drop(k)
