"""
Typed tool-call arguments, reduced to the bounded map the API accepts as
``action_parameters``.

Your registered checks receive these as ``parameters``, so they can look an
argument up in your own records instead of reading it out of the description.

The result always fits the API's limits (at most 32 entries, keys up to 64
characters, scalar values only, strings up to 512 characters), so forwarding
arguments never turns a working tool call into a validation error. Non-scalar
values and non-finite floats are dropped.
"""
from __future__ import annotations

import math

# The API's limits for action_parameters.
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
        # dicts/lists/objects are dropped: only scalar values are forwarded
    return out or None
