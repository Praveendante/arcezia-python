"""Mint the signed tokens Arcezia verifies against your registered key.

Register an Ed25519 public key once (``Arcezia.register_token_key``, which
never silently replaces a different key; ``Arcezia.token_key_status`` says
which key is registered and gives the ``api_key_id`` for ``acct``); keep the
private key with the PERSON or system that grants authority, never in the
agent's process. Then a capability envelope can be presented signed, so the
server can tell the principal's declaration from anything the agent's process
could have composed on its own.

Requires the ``cryptography`` package (``pip install cryptography``); the SDK
itself stays dependency-free and this module imports it lazily.
"""
from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Any, Optional


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def action_binding(action_type: str, domain: str, action_description: str = "",
                   action_parameters: Optional[dict] = None) -> str:
    """The digest an approval carries in ``act`` to approve ONE action.

    Identical to the value the service returns as ``action_binding`` on every
    verdict, so the simplest flow is: verify → REVIEW → show the person →
    ``mint_token(..., action=cert.raw["action_binding"])`` → attach → re-verify.
    An approval bound this way covers that exact call — tool, domain,
    description and typed parameters — and nothing else.
    """
    import hashlib
    canon = json.dumps(
        {
            "type": action_type or "",
            "domain": domain or "",
            "description": action_description or "",
            "parameters": dict(action_parameters or {}),
        },
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


def public_key_b64(public_key: Any) -> str:
    """A public key in the form ``POST /v1/account/token_key`` takes.

    Accepts the base64url text, the 32 raw bytes, or a ``cryptography``
    ``Ed25519PublicKey``. Raises ``ValueError`` if it is not 32 bytes.
    """
    if hasattr(public_key, "public_bytes_raw"):
        raw = public_key.public_bytes_raw()
    elif isinstance(public_key, str):
        text = public_key.strip()
        try:
            raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        except Exception as exc:
            raise ValueError("public key is not valid base64url") from exc
    elif isinstance(public_key, (bytes, bytearray)):
        raw = bytes(public_key)
    else:
        raise TypeError("public key must be base64url text, 32 raw bytes, or an Ed25519PublicKey")
    if len(raw) != 32:
        raise ValueError(f"an Ed25519 public key is 32 raw bytes; got {len(raw)}")
    return _b64(raw)


def public_key_fingerprint(public_key: Any) -> str:
    """The fingerprint ``Arcezia.token_key_status()`` reports for a key.

    First 16 hex characters of SHA-256 over the 32 raw public-key bytes, so
    you can check which key is registered without sending or storing it.
    """
    import hashlib
    text = public_key_b64(public_key)
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    return hashlib.sha256(raw).hexdigest()[:16]


def _load_private_key(private_key: Any):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:  # pragma: no cover
        raise ImportError("arcezia.signing needs the 'cryptography' package: pip install cryptography") from exc
    if isinstance(private_key, Ed25519PrivateKey):
        return private_key
    if isinstance(private_key, str):
        raw = base64.urlsafe_b64decode(private_key + "=" * (-len(private_key) % 4))
    else:
        raw = bytes(private_key)
    if len(raw) != 32:
        raise ValueError("an Ed25519 private key is 32 raw bytes (base64url or bytes)")
    return Ed25519PrivateKey.from_private_bytes(raw)


def mint_token(private_key: Any, *, api_key_id: int, token_type: str,
               session_id: Optional[str] = None, ttl_seconds: int = 300,
               action: Optional[str] = None, extra: Optional[dict] = None,
               role: Optional[str] = None) -> str:
    """``<base64url payload>.<base64url signature>`` as the server expects.

    ``role`` (a user approval only): the role of the person approving, for a
    contract rule ``"require": ["approval:<role>"]`` — for example
    ``role="supervising_lawyer"``. A role approval covers one call, so it
    needs ``action`` (the verdict's ``action_binding``)."""
    if role is not None:
        import re as _re
        if token_type != "user":
            raise ValueError("only a user approval carries a role")
        if not isinstance(role, str) or not _re.fullmatch(r"[a-z][a-z0-9_]{0,31}", role):
            raise ValueError("a role is lower_snake_case: a letter first, at most 32 characters")
        if not action:
            raise ValueError("a role approval is bound to one call: pass action=<the verdict's action_binding>")
    claims: dict[str, Any] = {
        "acct": int(api_key_id),
        "sid": session_id,
        "typ": token_type,
        "jti": secrets.token_urlsafe(16),
        "exp": int(time.time()) + int(ttl_seconds),
    }
    if action is not None:
        claims["act"] = action
    if role is not None:
        claims["role"] = role
    if extra:
        claims.update(extra)
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    key = _load_private_key(private_key)
    return f"{payload}.{_b64(key.sign(payload.encode('ascii')))}"


def mint_envelope_token(private_key: Any, envelope: dict, *, api_key_id: int,
                        ttl_seconds: int = 300) -> str:
    """A signed capability envelope for ``start_session`` / the first ``verify``.

    The envelope travels INSIDE the signed payload (claim ``env``), so what the
    server enforces is exactly what was signed. Single-use: each token opens
    one session.
    """
    if not isinstance(envelope, dict):
        raise TypeError("envelope must be a dict")
    return mint_token(private_key, api_key_id=api_key_id, token_type="envelope",
                      session_id=None, ttl_seconds=ttl_seconds, extra={"env": envelope})


# The service refuses a grant whose window is longer than this (400
# workspace_grant_rejected, reason "lifetime").
WORKSPACE_GRANT_MAX_SECONDS = 24 * 3600


def mint_workspace_grant(private_key: Any, roots: list, *, api_key_id: int,
                         expires_at: int, not_before: Optional[int] = None,
                         grant_id: Optional[str] = None) -> str:
    """A signed WORKSPACE GRANT: the principal's statement that ``roots`` are
    the agent's work folders from ``not_before`` until ``expires_at`` (unix
    seconds), bound to this account (``acct``) and named by ``gid``.

    Unlike an envelope token it names no session and is reusable until it
    lapses: a replay inside the same account, roots and window grants nothing
    the principal did not already grant. It ends at ``expires_at``, when it is
    revoked by id, or when the account's signing key is replaced.

    ``roots`` must be absolute folders (pass real paths); ``/`` is refused.
    """
    import posixpath
    if not isinstance(roots, (list, tuple)) or not roots:
        raise ValueError("a workspace grant needs at least one absolute folder")
    norm = []
    for r in roots:
        if not isinstance(r, str) or not r.strip().startswith("/"):
            raise ValueError(f"workspace root {r!r} is not an absolute path")
        n = posixpath.normpath("/" + r.strip().lstrip("/"))
        if n == "/":
            raise ValueError("the root '/' is not a workspace")
        if any(seg.startswith("~") or "$" in seg or any(ch in seg for ch in "*?[]{}")
               for seg in n.split("/")):
            raise ValueError(f"workspace root {r!r} does not name one folder")
        norm.append(n)
    nbf = int(time.time()) if not_before is None else int(not_before)
    if int(expires_at) <= nbf:
        raise ValueError("a workspace grant must end after it begins")
    if int(expires_at) - nbf > WORKSPACE_GRANT_MAX_SECONDS:
        raise ValueError("a workspace grant may last at most 24 hours (the service refuses longer ones)")
    claims: dict[str, Any] = {
        "acct": int(api_key_id),
        "sid": None,
        "typ": "workspace_grant",
        "gid": grant_id or secrets.token_urlsafe(16),
        "roots": list(dict.fromkeys(norm)),
        "nbf": nbf,
        "exp": int(expires_at),
    }
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    key = _load_private_key(private_key)
    return f"{payload}.{_b64(key.sign(payload.encode('ascii')))}"


def read_grant_claims(token: str) -> dict:
    """The claims of a grant token, UNVERIFIED (for display and local expiry
    checks only; the service verifies the signature)."""
    seg = token.split(".", 1)[0]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


# ── Supplied facts (2026-10-04) ──────────────────────────────────────────────
#
# A check registered with ``fact_mode="supplied"`` may be answered by your
# integration itself and sent with the request, instead of the service calling
# your check endpoint. The fact is signed with your FACT signing key: an
# Ed25519 key you register with ``POST /v1/account/fact_key``, different from
# your approval key. Keep it with the system that evaluates the fact, never in
# the agent's process: a fact the agent could have signed is worth no more
# than the agent's own claim. A supplied fact can never approve a call or lift
# a limit, and it never overrules what the call itself shows.


def supplied_fact_message(session_binding_id: str, counter: int, action_binding: str,
                          fact: str, answer: dict) -> bytes:
    """The bytes a supplied fact's signature covers. Identical to the
    service's `probe_webhooks.supplied_fact_message`."""
    canon = json.dumps(answer, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return (f"arcezia-supplied-fact-v1\n{session_binding_id}\n{int(counter)}\n"
            f"{action_binding}\n{fact}\n{canon}").encode("utf-8")


def sign_supplied_fact(fact_private_key: Any, *, session_binding_id: str, counter: int,
                       action_binding: str, fact: str, answer: dict) -> dict:
    """One entry for ``verify(..., session_id=..., supplied_facts=[...])``.

    * ``fact_private_key``: your fact signing key (Ed25519). Not your approval
      key: the service refuses a fact signed with the approval key.
    * ``session_binding_id``: returned when the session is opened.
    * ``counter``: unique within the session; any order, each value accepted
      once (``SuppliedFactSigner`` keeps it for you).
    * ``action_binding``: this call's binding (``action_binding(...)``).
    * ``answer``: what your check endpoint would return, e.g.
      ``{"grounded": True, "value": True}``.
    """
    if not isinstance(answer, dict):
        raise TypeError("answer must be a dict, as a check endpoint would return")
    if not isinstance(counter, int) or isinstance(counter, bool) or counter < 0:
        raise ValueError("counter must be a non-negative integer")
    if not isinstance(session_binding_id, str) or not session_binding_id:
        raise ValueError("session_binding_id is the value returned when the session was opened")
    key = _load_private_key(fact_private_key)
    sig = key.sign(supplied_fact_message(session_binding_id, counter, action_binding, fact,
                                         answer))
    return {"fact": fact, "answer": answer, "session_binding_id": session_binding_id,
            "counter": counter, "signature": _b64(sig)}


class SuppliedFactSigner:
    """Signs supplied facts for ONE session, keeping the counter unique.

        signer = SuppliedFactSigner(fact_key, session["session_binding_id"])
        item = signer.sign(action_binding("run_sql", "database_ops", sql),
                           "verified_recent_backup", {"grounded": True, "value": True})
        client.verify(..., session_id=sid, supplied_facts=[item])

    Thread-safe: calls made in parallel each get their own counter, and the
    service accepts them in any order.
    """

    def __init__(self, fact_private_key: Any, session_binding_id: str, start: int = 0):
        import itertools
        import threading
        self._key = _load_private_key(fact_private_key)
        self._sb = session_binding_id
        self._lock = threading.Lock()
        self._next = itertools.count(int(start))

    def sign(self, action_binding: str, fact: str, answer: dict) -> dict:
        with self._lock:
            n = next(self._next)
        return sign_supplied_fact(self._key, session_binding_id=self._sb, counter=n,
                                  action_binding=action_binding, fact=fact, answer=answer)


def sign_check_reply(signing_key: str, nonce: str, raw_body: bytes) -> str:
    """The ``X-Arcezia-Answer-Signature`` header value for a check endpoint's
    reply: ``nonce`` is the request's ``nonce`` (body field, also the
    ``X-Arcezia-Nonce`` header), ``raw_body`` the exact reply bytes."""
    import hashlib
    import hmac
    mac = hmac.new(signing_key.encode(), b"arcezia-check-answer-v1\n" + nonce.encode()
                   + b"\n" + bytes(raw_body), hashlib.sha256).hexdigest()
    return f"sha256={mac}"
