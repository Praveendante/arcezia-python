"""
Shared projection of typed tool-call arguments onto the bounded scalar map the
API accepts as ``action_parameters``.

Why this exists: registered probe webhooks receive ``parameters`` so they can
answer a constraint by KEY LOOKUP into the customer's own records instead of
parsing identifiers out of the free-text description. The correct source for
those keys is the framework's TYPED tool-call arguments — not model-written
prose. Every integration that has the parsed arguments in hand forwards them
through this projection.

Safety property (load-bearing): the projection is ALWAYS within the API bounds
(max 32 entries, keys <=64 chars, scalar values only, strings <=512 chars), so
forwarding parameters can never turn a working tool call into a validation
error. Non-scalar values are dropped — parameters are lookup keys, not
payloads — and non-finite floats are dropped because they do not survive JSON.
"""
from __future__ import annotations

import math

# Kept in sync with the server-side model bounds (VerifyRequest.action_parameters).
MAX_PARAMS = 32
MAX_KEY_CHARS = 64
MAX_VALUE_CHARS = 512


def scalar_params(kwargs: dict | None) -> dict | None:
    """Project ``kwargs`` onto the bounded scalar map; None when nothing scalar."""
    if not isinstance(kwargs, dict) or not kwargs:
        return None
    out: dict = {}
    for k, v in kwargs.items():
        if len(out) >= MAX_PARAMS:
            break
        if not isinstance(k, str):
            continue
        key = k[:MAX_KEY_CHARS]
        if isinstance(v, float) and not math.isfinite(v):
            continue  # NaN/inf do not survive JSON — drop rather than fail
        if v is None or isinstance(v, (bool, int, float)):
            out[key] = v
        elif isinstance(v, str):
            out[key] = v[:MAX_VALUE_CHARS]
        # dicts/lists/objects are dropped: parameters are lookup keys, not payloads
    return out or None
