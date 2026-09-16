"""Shared helpers for the framework integrations."""
from __future__ import annotations

import warnings
from typing import Any, Callable, Iterable, Optional, Sequence


# ── The one action description ────────────────────────────────────────────────
#
# The description is the channel the engine's structural rules actually read:
# the mass-scope and DML rules parse `action_description` (sqlparse runs on it),
# and `action_parameters` is consulted only for a fixed set of key names that
# does NOT include `query` or `sql`. So a clipped description is not a shorter
# action — it is a DIFFERENT, safer-looking action, while the adapter goes on to
# execute the full, unclipped arguments. Every adapter had its own ceiling (80
# chars PER ARGUMENT in universal/autogen/openclaw, 200 or 300 total in the
# OpenAI paths, and a single key in anthropic and in ArceziaCrewTool), and each
# one authorised a destructive statement on its harmless-looking prefix (A5-5).
#
# One function, one budget, all arguments, and — the load-bearing part — an
# explicit marker whenever anything was dropped, so a clipped description
# reaches the engine as a VISIBLE UNKNOWN rather than as a clean short action.
# Per Law D the marker may only tighten: it can add danger, never remove it.
#
# [M] DESCRIBE_BUDGET = 100_000 — the server's own `action_description` bound
# (server/main.py `_sanity_bound_text`), i.e. the largest value that can never
# be rejected at the seam. Candidates measured against the benchmark corpus
# (696 action_description values across our benchmark and test corpora:
# p50 = 49, p95 = 115, max = 157 chars):
# {157, 500, 1_000, 4_000, 16_000, 32_768, 100_000} all clear the corpus, so the
# corpus alone does not separate them. Two further criteria do. (a) A budget
# must introduce no NEW clip on a path that does not clip today — the Claude
# Code hook already sends a Write/Edit's FULL file content unclipped, so the
# budget must be far above any honest description; that rules out everything
# through 16 000. (b) The SAME number must hold on both sides of the seam: the
# service-side copy of this function uses 32 768, and two budgets for one contract is two
# distinctions where the boundary made one — a description clipped at one end
# and not the other is exactly the disagreement this fix removes. 32 768 is
# therefore the argmin: above every observed case by more than two orders of
# magnitude, below the server's own 100 000-char field bound by a margin that
# leaves the marker room, and identical to the engine's.
DESCRIBE_BUDGET = 32768

# Every argument is guaranteed this many characters before ANY argument is
# clipped, so one huge value cannot starve the small one holding the target.
# [M] MIN_ARG_CHARS = 512 — the API's own per-value bound for
# `action_parameters` (`_params.MAX_VALUE_CHARS`), so an argument that survives
# whole in the typed channel also survives whole in the prose one.
MIN_ARG_CHARS = 512

# The marker the engine keys on. Kept as a named constant, not a literal, so
# the producing side and the consuming side name the same distinction.
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

    The marker is spelled exactly as the engine-side copy spells it —
    ``" [TRUNCATED n]"``, n = characters dropped — so one string identifies a clipped
    description wherever it was produced. Two spellings would be two
    distinctions for one fact.

    The RESULT — marker included — is within ``budget``: the budget must stay
    under the server's hard field bound, so a marker that pushed the string
    past it would turn every long action into a 422 instead of a verdict.
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
    """Render a tool call as the action description the engine will read.

    ALL positional and keyword arguments are included — the shape is
    ``action_type(arg0, arg1, key=value, …)`` — and nothing is dropped
    silently: every clip carries ``[TRUNCATED n]`` — the same marker text the
    engine-side copy writes, n = characters dropped.

    Budget is shared max-min fairly across the arguments: an argument shorter
    than its equal share is never clipped, and the room it does not use is
    redistributed to the long ones. That matters because the dangerous value is
    not reliably the long one — clipping ``path`` to make room for a 40 KB
    ``content`` would hide exactly the field the path rules read.

    ``priority`` orders the keys that carry the action itself (``command``,
    ``sql``, …) to the front, so on a call so large that even the fair share
    bites, the fields the structural rules parse are the ones at the head of
    the string rather than wherever the dict happened to order them.
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
    from arcezia.client import ArceziaBlockError
    # Allow is POSITIVE here too. Every adapter reaches this line by ELIMINATION
    # — "not block, not review, not degraded" — and a verdict that is none of
    # the three satisfied none of those tests and executed: a renamed value, an
    # empty string, a lowercase "allow". That is the same inversion the n8n node
    # and the MCP proxy carried (A5-3, A5-4), and this is the one place all
    # thirteen adapter call sites pass through, so it is fixed once here rather
    # than thirteen times. `cert.allow` is the conjunction the SDK already
    # defines: verdict is the literal "ALLOW", fabrication not detected, no
    # cross-step semantic block.
    #
    # `cert.review` is admitted alongside it because reaching this line on a
    # REVIEW is a DECLARED choice, not an omission: `block_on_review=False` and
    # a `review_handler` that returns True are operator channels that say "let a
    # held action through". A verdict that is none of ALLOW / BLOCK / REVIEW was
    # never declared by anyone, and that is the case being closed.
    if getattr(cert, "allow", False) is not True and getattr(cert, "review", False) is not True:
        raise ArceziaBlockError(cert)
    if cert.is_clean():
        return
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
