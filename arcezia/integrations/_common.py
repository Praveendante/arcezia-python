"""Shared helpers for the framework integrations."""
from __future__ import annotations

from typing import Any, Callable, Optional


def coerce_az(
    az: Any = None,
    *,
    api_key: Optional[str] = None,
    task: Optional[str] = None,
    api_url: Optional[str] = None,
    capability_envelope: Optional[dict] = None,
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
    """
    if az is not None:
        return az
    from arcezia.client import Arcezia
    client = Arcezia(api_key=api_key, task=task or "", api_url=api_url)
    if capability_envelope:
        client.start_session(capability_envelope=capability_envelope)
    return client
