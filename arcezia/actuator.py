"""Refuse to act without a valid single-use pass — for the service that acts.

The framework adapters check the verdict inside the agent's process. That is a
consistency check, not a lock: an agent that can reach the tool directly never
meets it. The lock is the service that performs the action (the database
proxy, the payments service, the mail relay) refusing unless it is handed a
pass the verifier issued for exactly this call, and spending that pass once.

    from arcezia.actuator import require_pass, PassRefused

    def handle_transfer(request):
        try:
            require_pass(request.headers.get("X-Arcezia-Pass"),
                         "send_payment", "payment_ops", request.description,
                         {"amount": request.amount, "to": request.payee},
                         api_key=os.environ["ARCEZIA_API_KEY"])
        except PassRefused as refused:
            return 403, str(refused)
        return do_the_transfer(request)

The call named here is the one the service is about to perform, computed from
its own request — not copied from the agent's certificate. The pass passes only
if the verifier issued it for that call, under those rules, and it has not been
used. Anything else — no pass, a pass for another call, an expired or spent
pass, a network failure, an answer that does not confirm the binding — raises
``PassRefused``, and the service does not act.

Two ways to check, or both:

* ``mode="online"`` (default): ``POST /v1/validate_credential``. Single use is
  global — the service spends the pass. Use the API key the agent's
  verifications ran under; a pass is validated only by the key whose session
  it was issued in.
* ``mode="offline"``: no call home and no secret. The pass carries an Ed25519
  signature (``esig``) the service makes when a pass-signing key is
  configured; check it against public keys you pinned out of band
  (``fetch_pass_keys`` reads them and keeps only the fingerprints you pinned).
  Offline accepts only a pass that names THIS service (``audience`` — the
  agent sends it with ``verify(..., audience=...)``), so a pass is valid at one
  place and the local single-use register (``UsedPasses``) is complete for it.
* ``mode="both"``: offline first (refuses a forged or misdirected pass without
  a round trip), then online (spends it centrally).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
from typing import Any, Iterable, Optional

from arcezia.signing import action_binding

__all__ = ["require_pass", "PassRefused", "UsedPasses", "fetch_pass_keys", "pass_kid"]


class PassRefused(RuntimeError):
    """The pass did not authorise this call. Do not act.

    ``reason`` is a short code (the verifier's, when it answered with one:
    ``action_binding_mismatch``, ``credential_already_used``,
    ``credential_expired`` …; or ``no_pass``, ``unreachable``,
    ``not_bound``). ``answer`` is the verifier's reply when there was one.
    """

    def __init__(self, reason: str, message: str, answer: Optional[dict] = None):
        self.reason = reason
        self.answer = answer
        super().__init__(message)


def _token_of(credential: Any) -> Optional[str]:
    if isinstance(credential, str):
        return credential or None
    if isinstance(credential, dict):
        t = credential.get("token")
        return t if isinstance(t, str) and t else None
    cred = getattr(credential, "credential", None)        # an ArceziaCertificate
    if isinstance(cred, dict):
        t = cred.get("token")
        return t if isinstance(t, str) and t else None
    return None


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def pass_kid(public_key: str) -> str:
    """Key id of a base64url Ed25519 public key (first 16 hex of SHA-256)."""
    return hashlib.sha256(_unb64(public_key)).hexdigest()[:16]


def _canonical(claims: dict) -> bytes:
    # The service's one serialization (server/pass_keys.py `canonical`).
    return json.dumps(claims, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _decode(token: str) -> Optional[dict]:
    if not token.startswith("arc_cred_"):
        return None
    raw = token[len("arc_cred_"):]
    if "=" in raw:                      # one encoding per pass, as the service
        return None
    try:
        out = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode())
    except Exception:
        return None
    return out if isinstance(out, dict) else None


class UsedPasses:
    """The actuator's local single-use register, for offline checks.

    Each spent pass is remembered until it expires (its own ``expires_at``; no
    other window). A pass issued before this register existed is refused:
    a predecessor — this service before a restart — may already have spent it.
    Pass ``durable=True`` only for a register whose memory survives restarts
    (subclass and keep ``claim`` atomic, e.g. Redis ``SET NX``).
    """

    durable = False

    def __init__(self) -> None:
        self.started_at = int(time.time())
        self._seen: dict = {}
        self._lock = threading.Lock()

    def claim(self, nonce: str, issued_at: int, expires_at: int, now: float) -> bool:
        """True exactly once per pass; False if spent here or possibly before."""
        if not self.durable and issued_at <= self.started_at:
            return False
        with self._lock:
            for n in [n for n, exp in self._seen.items() if exp < now]:
                del self._seen[n]
            if nonce in self._seen:
                return False
            self._seen[nonce] = expires_at
            return True


def fetch_pass_keys(fingerprints: Iterable[str], *, api_key: Optional[str] = None,
                    api_url: Optional[str] = None, client: Any = None) -> list:
    """The service's pass keys whose SHA-256 fingerprint you pinned.

    Reads ``GET /v1/account/pass_keys`` and returns only keys whose full
    fingerprint is in ``fingerprints`` (taken from your dashboard or account
    page, out of band). A key that is not pinned is never returned: a key
    fetched at run time could be one the agent put in its way.
    """
    pinned = {f.strip().lower() for f in fingerprints if isinstance(f, str) and f.strip()}
    if client is None:
        from arcezia.client import Arcezia
        client = Arcezia(api_key=api_key, task="", api_url=api_url)
    doc = client.pass_keys()
    out = []
    for k in (doc or {}).get("keys") or []:
        pk = k.get("public_key") if isinstance(k, dict) else None
        if isinstance(pk, str):
            try:
                fp = hashlib.sha256(_unb64(pk)).hexdigest()
            except Exception:
                continue
            if fp in pinned:
                out.append(pk)
    return out


def _offline(token: str, action_type: str, domain: str, description: str,
             parameters: Optional[dict], *, pass_keys, audience, used, now) -> dict:
    claims = _decode(token)
    if claims is None:
        raise PassRefused("invalid_format", "Refused: the pass is not well formed.")
    claims.pop("sig", None)
    esig = claims.pop("esig", None)
    if not (isinstance(esig, str) and esig and isinstance(claims.get("kid"), str)):
        raise PassRefused("unsigned", "Refused: the pass carries no offline signature, so "
                                      "it can only be checked online.")
    keys = {pass_kid(k): k for k in (pass_keys or []) if isinstance(k, str) and k}
    pub = keys.get(claims["kid"])
    if pub is None:
        raise PassRefused("unknown_key", "Refused: the pass was signed with a key you have "
                                         "not pinned.")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(_unb64(pub)).verify(_unb64(esig), _canonical(claims))
    except Exception:
        raise PassRefused("invalid_signature", "Refused: the pass's signature does not verify.")
    if not isinstance(claims.get("expires_at"), int) or now > claims["expires_at"]:
        raise PassRefused("credential_expired", "Refused: the pass has expired.")
    if not (isinstance(audience, str) and audience):
        raise PassRefused("no_audience", "Refused: offline checking needs this service's id "
                                         "(audience).")
    aud = claims.get("aud")
    if not (isinstance(aud, str) and hmac.compare_digest(aud, audience)):
        raise PassRefused("audience_mismatch", "Refused: the pass was not issued to be spent "
                                               "at this service.")
    if claims.get("action_type") != action_type:
        raise PassRefused("action_type_mismatch", "Refused: the pass is for another tool.")
    digest = hashlib.sha256((description or "").encode()).hexdigest()
    if not hmac.compare_digest(str(claims.get("adg") or ""), digest):
        raise PassRefused("action_digest_mismatch", "Refused: the pass is for another call.")
    act = claims.get("act")
    if not (isinstance(act, str) and hmac.compare_digest(
            act, action_binding(action_type, domain, description or "", parameters))):
        raise PassRefused("action_binding_mismatch", "Refused: the pass is for another call.")
    if used is None or not used.claim(str(claims.get("nonce")), int(claims.get("issued_at") or 0),
                                      claims["expires_at"], now):
        raise PassRefused("credential_already_used", "Refused: the pass was already spent "
                                                     "here, or may have been before this "
                                                     "service started.")
    return {"ok": True, "offline": True, "call_bound": True, "action_bound": True,
            "audience": aud, "kid": claims["kid"], "session_id": claims.get("session_id"),
            "expires_at": claims["expires_at"]}


def require_pass(
    credential: Any,
    action_type: str,
    domain: str,
    action_description: str,
    action_parameters: Optional[dict] = None,
    *,
    api_key: Optional[str] = None,
    api_url: Optional[str] = None,
    client: Any = None,
    resource_id: Optional[str] = None,
    mode: str = "online",
    pass_keys: Optional[Iterable[str]] = None,
    used: Optional[UsedPasses] = None,
    clock=time.time,
) -> dict:
    """Return the verifier's answer when the pass authorises THIS call; raise
    ``PassRefused`` otherwise. Fail-closed: every error refuses.

    credential:  the pass — the ``arc_cred_…`` string, the ``credential`` dict
                 from a verdict, or the certificate itself.
    action_type, domain, action_description, action_parameters:
                 the call this service is about to perform, exactly as it was
                 sent for verification (the same tool name, rules, description
                 and typed arguments). Computed by the service from its own
                 request.
    api_key / api_url, or client:
                 how to reach the verifier. ``client`` is an existing
                 ``Arcezia`` instance; otherwise one is built from the key.
    resource_id: this service's id. Recorded with the spent pass online; it
                 is also the ``audience`` a pass must name to pass offline, and
                 a pass that names an audience is refused online at any other.
    mode:        ``"online"``, ``"offline"`` or ``"both"`` (see the module).
    pass_keys:   offline: the pinned base64url public keys (``fetch_pass_keys``).
    used:        offline: this service's ``UsedPasses`` register — one per
                 service, kept for its lifetime.

    The pass is spent by a successful check, so call this once, immediately
    before acting. A retry after a lost answer is refused as already used —
    the safe direction.
    """
    if mode not in ("online", "offline", "both"):
        raise ValueError("mode must be 'online', 'offline' or 'both'")
    token = _token_of(credential)
    if token is None:
        raise PassRefused("no_pass", "Refused: no single-use pass was presented for "
                                     "this call, so nothing authorises it.")
    if not (isinstance(action_type, str) and action_type and isinstance(domain, str) and domain):
        raise PassRefused("no_call", "Refused: the call to check the pass against was "
                                     "not named (tool and rules are required).")
    offline = None
    if mode in ("offline", "both"):
        offline = _offline(token, action_type, domain, action_description, action_parameters,
                           pass_keys=pass_keys, audience=resource_id, used=used, now=clock())
        if mode == "offline":
            return offline
    binding = action_binding(action_type, domain, action_description or "", action_parameters)
    digest = hashlib.sha256((action_description or "").encode()).hexdigest()
    try:
        if client is None:
            from arcezia.client import Arcezia
            client = Arcezia(api_key=api_key, task="", api_url=api_url)
        answer = client.validate_credential(
            token, action_type=action_type, action_digest=digest,
            resource_id=resource_id, action_binding=binding)
    except Exception as exc:                                # noqa: BLE001 — every failure refuses
        raise PassRefused("unreachable", f"Refused: the pass could not be checked "
                                         f"({type(exc).__name__}: {exc}).") from exc
    if not isinstance(answer, dict) or answer.get("ok") is not True:
        err = answer.get("error") if isinstance(answer, dict) else None
        raise PassRefused(str(err or "refused"),
                          f"Refused by the verifier: {err or 'no reason given'}.",
                          answer if isinstance(answer, dict) else None)
    if answer.get("call_bound") is not True or answer.get("action_bound") is not True:
        # An answer that does not say the pass was checked against this call
        # (a verifier that ignores the binding) is not a yes for this call.
        raise PassRefused("not_bound", "Refused: the verifier did not confirm the pass "
                                       "was issued for this exact call.", answer)
    return answer
