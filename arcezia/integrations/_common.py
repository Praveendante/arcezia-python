"""Shared helpers for the framework integrations."""
from __future__ import annotations

import warnings
from typing import Any, Callable, Optional


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


def refuse_unless_clean(cert: Any) -> None:
    """Raise unless the auxiliary danger channels POSITIVELY cleared the action.

    One helper, called at every adapter's refusal point, so "an absent
    fabrication report is not a clearance" is decided in one place rather than
    fourteen. See ``ArceziaCertificate.is_clean``.

    Why it sits BESIDE the verdict gates rather than inside them: `cert.allow`
    reads `verdict`, which is the decision and is always present, so it is left
    exactly as it was — inverting it would refuse every response from a server
    that predates the field. This is the second, additive question: did the
    evidence behind that ALLOW actually get reported? A `None` there used to
    parse as `False` and read as "checked, clean". It now reaches here as an
    unknown, and an unknown does not execute.

    Reached only after an adapter has already cleared block / review /
    degraded, so on any server that reports the flag — every current
    deployment — this changes nothing at all.

    ``ArceziaBlockError`` subclasses ``RuntimeError``, so an existing
    ``except RuntimeError`` around a guarded tool still catches it, and
    ``str(cert)`` names the missing report.
    """
    if cert.is_clean():
        return
    from arcezia.client import ArceziaBlockError
    raise ArceziaBlockError(cert)


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
