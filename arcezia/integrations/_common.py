"""Shared helpers for the framework integrations."""
from __future__ import annotations

import warnings
from typing import Any, Callable, Iterable, Optional, Sequence


# ── The one action description ────────────────────────────────────────────────
#
# Describe every argument of a tool call, and mark any truncation, so a long
# call is never read as a shorter, safer action than the one that executes.
# Every adapter uses this one function and this one budget.
DESCRIBE_BUDGET = 32768

# Every argument is guaranteed this many characters before any argument is
# clipped, so one huge value cannot crowd out a small one.
MIN_ARG_CHARS = 512

# Appended whenever text was clipped, so the clip is visible.
TRUNCATION_MARKER = "[TRUNCATED"

# Argument names that usually CARRY the action rather than qualify it. Only an
# ordering hint: every argument is described either way, but on a call large
# enough for the fair share to bite, these sit at the head of the string. It is
# not an allowlist and nothing is dropped for being absent from it.
ACTION_KEYS = (
    "command", "cmd", "sql", "query", "statement", "script",
    "path", "file_path", "filepath", "filename", "notebook_path",
    "content", "new_string", "body", "data", "payload",
    "url", "endpoint", "to", "recipient", "recipients", "subject",
)


# The text of the fail_open-inside-an-adapter warning, kept as one string so
# the message a user reads and the message the test pins are the same object.
FAIL_OPEN_ADAPTER_WARNING = (
    "Arcezia: this client is set on_error='fail_open', but a framework adapter "
    "will still REFUSE the certificate that setting produces. During an outage "
    "fail_open makes verify() return a SYNTHETIC ALLOW — nothing was verified, "
    "it carries no credential, and cert.degraded is True — and every adapter "
    "(guard / guard_callable, az.gate(), and each framework toolkit) raises "
    "ArceziaUnavailableError on a degraded certificate rather than running the "
    "tool. That refusal is deliberate and is not being changed: a synthetic "
    "verdict is not a verification, so opting into fail_open on the client is "
    "not on its own enough to execute an unverified tool. The practical "
    "consequence is that fail_open does NOT keep an adapter-wrapped agent "
    "running through an outage; it only changes what verify() returns to code "
    "that calls it directly. If you need an outage to be survivable here, "
    "catch ArceziaUnavailableError around the guarded call and decide there. "
    "See the 'WHAT HAPPENS WHEN ARCEZIA IS UNREACHABLE' table in the Arcezia "
    "class docstring."
)


def _clip(text: str, budget: int) -> str:
    """Clip ``text`` to ``budget`` and say so when anything was dropped.

    Appends ``" [TRUNCATED n]"`` (n = characters dropped). The result, marker
    included, fits within ``budget``.
    """
    if len(text) <= budget:
        return text
    keep = budget
    for _ in range(3):                       # converges in two; third is slack
        marker = f" {TRUNCATION_MARKER} {len(text) - keep}]"
        keep = max(budget - len(marker), 0)
    return f"{text[:keep]} {TRUNCATION_MARKER} {len(text) - keep}]"


def describe(
    action_type: str,
    args: Sequence[Any] = (),
    kwargs: Optional[dict] = None,
    *,
    priority: Iterable[str] = (),
    budget: int = DESCRIBE_BUDGET,
) -> str:
    """Render a tool call as the action description sent for verification.

    ALL positional and keyword arguments are included — the shape is
    ``action_type(arg0, arg1, key=value, …)`` — and nothing is dropped
    silently: every clip carries ``[TRUNCATED n]``, n = characters dropped.

    The budget is shared fairly across the arguments: an argument shorter than
    its equal share is never clipped, and the room it does not use goes to the
    long ones.

    ``priority`` moves the keys that usually carry the action itself
    (``command``, ``sql``, …) to the front of the string.
    """
    kwargs = kwargs or {}
    prio = [k for k in priority if k in kwargs]
    rest = [k for k in kwargs if k not in prio]

    parts: list[str] = [repr(a) for a in args]
    parts += [f"{k}={kwargs[k]!r}" for k in prio + rest]
    if not parts:
        return action_type

    # Budget for the argument text: whatever the wrapper `name(...)` leaves.
    overhead = len(action_type) + 2 + 2 * (len(parts) - 1)
    room = max(budget - overhead, len(parts) * 8)

    total = sum(len(p) for p in parts)
    if total > room:
        # Max-min fair share: hand every part its equal slice, give back what
        # the short ones do not use, repeat until nothing more is freed.
        remaining = room
        unresolved = list(range(len(parts)))
        share = {}
        while unresolved:
            equal = max(remaining // len(unresolved), MIN_ARG_CHARS)
            fits = [i for i in unresolved if len(parts[i]) <= equal]
            if not fits:
                for i in unresolved:
                    share[i] = max(remaining // len(unresolved), 1)
                break
            for i in fits:
                share[i] = len(parts[i])
                remaining -= len(parts[i])
                unresolved.remove(i)
            if remaining <= 0:
                for i in unresolved:
                    share[i] = 1
                break
        parts = [_clip(p, share.get(i, len(p))) for i, p in enumerate(parts)]

    return _clip(f"{action_type}({', '.join(parts)})", budget)


# ── The single-use pass ───────────────────────────────────────────────────────
#
# On an ALLOW the service hands out a single-use pass (`cert.credential`) bound
# to the call it decided about. When it allows but will not stand behind the
# ALLOW it withholds the pass and says why (`credential_withheld`). Exactly one
# of those reasons leaves the call runnable here: "no_session" — an advisory
# check made without a session, where there is no session key to sign a pass
# with. Every other reason (an integrity failure, a plan that did not clear,
# rejected evidence) is the service declining, and no reason at all is an
# unexplained absence. Neither is permission.
ADVISORY_WITHHELD = "no_session"


def call_of(action_type: str, domain: Optional[str], description: str,
            parameters: Optional[dict] = None) -> dict:
    """The call about to run, as the pass check reads it.

    ``domain=None`` means the service chose the rule set (the caller sent its
    default and asked the service to use a covering contract's instead); the
    domain the reply was decided under is then the expected one.
    """
    return {"action_type": action_type, "domain": domain,
            "description": description, "parameters": parameters}


def _withheld_of(cert: Any) -> Optional[str]:
    v = getattr(cert, "credential_withheld", None)
    if not (isinstance(v, str) and v):
        raw = getattr(cert, "raw", None)
        v = raw.get("credential_withheld") if isinstance(raw, dict) else None
    return v if isinstance(v, str) and v else None


def pass_hold_reason(cert: Any, call: Optional[dict]) -> Optional[str]:
    """Why an ALLOW must not run here, in plain words; None when it may.

    An ALLOW runs only when
      (a) it carries a pass and the pass names the call about to run — its
          binding equals ``arcezia.signing.action_binding`` computed from the
          arguments that will execute; or
      (b) it carries no pass and the service said why: ``no_session``.

    Only certificates that carry the pass field are subject to this. A
    verifier object written without one (the caller's own stand-in, never a
    reply of this service: ``ArceziaCertificate`` always has the field) keeps
    the earlier contract; a reply from the service cannot select that branch.

    The in-process check is a consistency check, not containment: an agent
    that can call the tool directly never meets it. Containment is the
    actuator refusing without a valid pass — see ``arcezia.actuator``.
    """
    if not hasattr(cert, "credential"):
        return None
    cred = getattr(cert, "credential", None)
    token = cred.get("token") if isinstance(cred, dict) else None
    if isinstance(token, str) and token:
        if not isinstance(call, dict):
            return ("Held: the pass cannot be checked against the call about to "
                    "run, because the call was not given to the check.")
        domain = call.get("domain")
        if domain is None:
            ident = getattr(cert, "action_identity", None)
            domain = ident.get("domain") if isinstance(ident, dict) else None
            if not (isinstance(domain, str) and domain):
                return ("Held: the reply does not say which rules it was decided "
                        "under, so the pass cannot be matched to this call.")
        import hashlib
        import hmac
        from arcezia.signing import action_binding
        expected = action_binding(call.get("action_type") or "", domain,
                                  call.get("description") or "", call.get("parameters"))
        bound = cred.get("action_binding")
        if isinstance(bound, str) and bound:
            if hmac.compare_digest(bound, expected):
                return None
            return ("Held: the single-use pass was issued for a different call "
                    "than the one about to run.")
        # A pass from a service that signs only the description digest: it is
        # tied to this reply by the digest, and the reply names the call.
        digest = cred.get("action_digest")
        if not (isinstance(digest, str) and digest):
            return ("Held: the single-use pass does not name the call it was "
                    "issued for, so it cannot be matched to this one.")
        here = hashlib.sha256((call.get("description") or "").encode()).hexdigest()
        reply = getattr(cert, "action_binding", None)
        if (hmac.compare_digest(digest, here) and isinstance(reply, str)
                and hmac.compare_digest(reply, expected)):
            return None
        return ("Held: the single-use pass was issued for a different call "
                "than the one about to run.")
    withheld = _withheld_of(cert)
    if withheld == ADVISORY_WITHHELD:
        return None
    if withheld:
        return (f"Held: the service allowed this call but withheld its single-use "
                f"pass ({withheld}), so it did not stand behind the ALLOW.")
    return ("Held: the service allowed this call but sent no single-use pass and "
            "gave no reason. An unexplained absence is not permission.")


def refuse_unless_clean(cert: Any, call: Optional[dict] = None) -> None:
    """Raise unless the certificate positively clears the action.

    Called at every adapter's refusal point. A verdict that is not ALLOW (or a
    REVIEW the operator chose to let through with ``block_on_review=False`` or
    a ``review_handler``) is refused, and so is an ALLOW whose fabrication
    result was not reported: not reported is not the same as clean. See
    ``ArceziaCertificate.is_clean``.

    An ALLOW is also refused unless its single-use pass names ``call`` — the
    call about to run, built with ``call_of`` from the arguments that will
    execute — or the service withheld the pass only because there was no
    session. See ``pass_hold_reason``.

    ``ArceziaBlockError`` subclasses ``RuntimeError``, so an existing
    ``except RuntimeError`` around a guarded tool still catches it, and
    ``str(cert)`` names what was missing.
    """
    from arcezia.client import ArceziaBlockError
    if getattr(cert, "allow", False) is not True and getattr(cert, "review", False) is not True:
        raise ArceziaBlockError(cert)
    if not cert.is_clean():
        raise ArceziaBlockError(cert)
    if getattr(cert, "allow", False) is True:
        reason = pass_hold_reason(cert, call)
        if reason is not None:
            raise ArceziaBlockError(cert, f"[Arcezia HOLD] {reason} Nothing ran.")


def warn_if_fail_open(az: Any) -> None:
    """Say the fail_open/adapter contradiction out loud, once per client.

    An operator who sets ``on_error='fail_open'`` is buying "my agent keeps
    running when Arcezia is down". Inside an adapter they do not get it: the
    guard refuses the degraded certificate and raises. Both halves are correct
    on their own — fail_open is a real client policy, and refusing an
    unverified verdict is the fail-safe choice — but together they are a
    setting that silently does nothing where it is most likely to be set.

    The behaviour is not changed (raising is the safe half). What changes is
    that the contradiction can no longer be hit in silence: it is stated at
    construction time, where the operator is still in the code that made the
    choice, rather than discovered as a surprising exception during an
    incident.

    Warned once per client object, not once per wrapped tool: a toolkit that
    wraps forty tools would otherwise emit forty identical warnings and teach
    the reader to filter them.
    """
    if getattr(az, "_on_error", None) != "fail_open":
        return
    if getattr(az, "_arcezia_fail_open_warned", False):
        return
    try:
        az._arcezia_fail_open_warned = True
    except Exception:                                      # pragma: no cover
        pass    # a client that refuses attributes still gets the warning
    warnings.warn(FAIL_OPEN_ADAPTER_WARNING, stacklevel=3)


def coerce_az(
    az: Any = None,
    *,
    api_key: Optional[str] = None,
    task: Optional[str] = None,
    api_url: Optional[str] = None,
    capability_envelope: Optional[dict] = None,
    data_subject_reference: Optional[str] = None,
    on_error: Optional[str] = None,
):
    """
    Resolve an Arcezia client from either an existing instance or constructor
    kwargs. Lets every integration be created both ways:

        Toolkit(az)                              # pass an existing client
        Toolkit(api_key="ar_live_...", task=...) # or let it build one

    A positional ``az`` always wins; otherwise an Arcezia client is built from
    the keyword arguments.

    If ``capability_envelope`` is provided and a NEW client is created, the
    session is opened with that envelope, so the authority it declares applies
    to every verification in the session. If ``az`` is an existing client, the
    caller is responsible for having called
    ``az.start_session(capability_envelope=...)`` already.

    If ``data_subject_reference`` is provided it is set on the resolved client
    (existing or newly built), so every subsequent verification carries it.
    Record-only: it never changes a verdict.

    ``on_error`` is the outage policy for a NEWLY built client. It cannot be
    applied to an existing ``az`` — the policy is the client's, and mutating a
    client the caller may share elsewhere would silently change how some other
    tool behaves during an outage. So passing both is a conflict, and it is
    raised rather than resolved: an ``on_error`` that is quietly dropped is the
    exact defect this argument exists to fix (``DispatchGuard(on_error=...)``
    accepted the value and never used it). Passing an ``az`` whose policy
    already matches is fine — there is nothing to drop.

    Whichever way the client is resolved, a ``fail_open`` policy triggers
    ``warn_if_fail_open`` — see there for why an adapter has to say that out
    loud rather than let the operator discover it during an outage.
    """
    if az is not None:
        if data_subject_reference is not None:
            az.set_data_subject(data_subject_reference)
        if on_error is not None and getattr(az, "_on_error", on_error) != on_error:
            raise ValueError(
                f"on_error={on_error!r} was passed alongside an existing client "
                f"whose policy is {getattr(az, '_on_error', None)!r}. The outage "
                f"policy belongs to the client: build it with "
                f"Arcezia(..., on_error={on_error!r}), or drop the argument here. "
                f"It is refused rather than ignored — an ignored on_error is a "
                f"safety setting that silently does nothing."
            )
        warn_if_fail_open(az)
        return az
    from arcezia.client import Arcezia
    client = Arcezia(api_key=api_key, task=task or "", api_url=api_url,
                     **({"on_error": on_error} if on_error is not None else {}))
    warn_if_fail_open(client)
    if data_subject_reference is not None:
        client.set_data_subject(data_subject_reference)
    if capability_envelope:
        client.start_session(capability_envelope=capability_envelope)
    return client
