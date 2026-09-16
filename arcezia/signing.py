"""Mint the signed tokens Arcezia verifies against your registered key.

Register an Ed25519 public key once (``POST /v1/account/token_key``); keep the
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
               action: Optional[str] = None, extra: Optional[dict] = None) -> str:
    """``<base64url payload>.<base64url signature>`` as the server expects."""
    claims: dict[str, Any] = {
        "acct": int(api_key_id),
        "sid": session_id,
        "typ": token_type,
        "jti": secrets.token_urlsafe(16),
        "exp": int(time.time()) + int(ttl_seconds),
    }
    if action is not None:
        claims["act"] = action
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
