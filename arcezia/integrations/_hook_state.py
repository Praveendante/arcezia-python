"""Per-Claude-Code-session state of the hook, beside its session store.

Two records live here, one file each, under the same name the session store
uses (a digest of the API key and the Claude Code session id):

* the OBSERVED-READS journal (E2, 2026-10-03). A read inside the working
  directory runs without a call; it is recorded here and reported with the
  next call the hook verifies, so what it put in the agent's hands is in the
  session before anything that could send it out is decided. Logically
  append-only: an entry leaves only after the service has received it, and the
  file is bounded (an entry that cannot be recorded is never dropped silently:
  `record_read` says so and the hook verifies that read instead).

* the REUSE cache (E3b). Server-signed ALLOW grants, each bound to every input
  the verdict depends on (see `claude_code._reuse_key`). Off unless the
  service issues grants and the developer pinned the service's public key.

Every read-modify-write holds an exclusive lock on a sibling `.lock` file, and
every write is a temporary file renamed into place, so concurrent hook
processes never tear or lose an entry.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
from typing import Optional

try:                                      # POSIX
    import fcntl as _fcntl
except ImportError:                       # pragma: no cover - Windows
    _fcntl = None

# The journal's bound. Reads are deduplicated while unreported (the same read
# twice is one fact), so this is the number of DISTINCT reads between two
# verified calls the hook can hold; past it, a read is verified instead.
MAX_JOURNAL_ENTRIES = 256
# The service's own bound on one request (server: _MAX_OBSERVED_ACTS).
MAX_REPORTED_PER_CALL = 256
MAX_REUSE_ENTRIES = 256


def _digest(api_key: str, cc_session_id: str) -> str:
    return hashlib.sha256((api_key + "\0" + cc_session_id).encode("utf-8")).hexdigest()[:32]


def state_path(session_dir: str, cc_session_id: str, suffix: str,
               api_key: Optional[str] = None) -> str:
    if api_key is None:
        api_key = os.environ.get("ARCEZIA_API_KEY", "").strip()
    return os.path.join(session_dir, f"{_digest(api_key, cc_session_id)}.{suffix}.json")


@contextlib.contextmanager
def _locked(path: str):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if _fcntl is not None:
            _fcntl.flock(fd, _fcntl.LOCK_EX)
        yield
    finally:
        try:
            if _fcntl is not None:
                _fcntl.flock(fd, _fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _load(path: str, default: dict) -> dict:
    try:
        with open(path) as f:
            rec = json.load(f)
        return rec if isinstance(rec, dict) else dict(default)
    except FileNotFoundError:
        return dict(default)


def _save(path: str, rec: dict) -> None:
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(rec, f)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise


# ── Observed reads (E2) ──────────────────────────────────────────────────────

_EMPTY_JOURNAL = {"gen": 0, "sent": 0, "entries": []}


def record_read(session_dir: str, cc_session_id: str, entry: dict) -> bool:
    """Append one observed read. True when it is recorded (or already is,
    unreported); False when it could not be — the journal is full of
    unreported reads, or the file cannot be written. The caller then verifies
    the read instead: a read is either observed or verified, never neither."""
    path = state_path(session_dir, cc_session_id, "observed")
    try:
        with _locked(path):
            rec = _load(path, _EMPTY_JOURNAL)
            entries = list(rec.get("entries") or [])
            sent = int(rec.get("sent") or 0)
            if sent >= len(entries) and entries:
                # Everything recorded so far was received: start a new
                # generation (a marker from before cannot touch it).
                entries, sent = [], 0
                rec["gen"] = int(rec.get("gen") or 0) + 1
            if any(e == entry for e in entries[sent:]):
                return True
            if len(entries) - sent >= MAX_JOURNAL_ENTRIES:
                return False
            entries.append(entry)
            rec.update(entries=entries, sent=sent)
            _save(path, rec)
            return True
    except (OSError, ValueError):
        return False


def unreported(session_dir: str, cc_session_id: str) -> tuple:
    """(gen, upto, entries): the reads not yet received by the service, oldest
    first, at most one request's worth; `upto` is what to mark once a verify
    carrying them succeeded."""
    path = state_path(session_dir, cc_session_id, "observed")
    try:
        with _locked(path):
            rec = _load(path, _EMPTY_JOURNAL)
    except (OSError, ValueError):
        return 0, 0, []
    entries = list(rec.get("entries") or [])
    sent = int(rec.get("sent") or 0)
    batch = entries[sent:sent + MAX_REPORTED_PER_CALL]
    return int(rec.get("gen") or 0), sent + len(batch), batch


def mark_reported(session_dir: str, cc_session_id: str, gen: int, upto: int) -> None:
    """The service received entries [.., upto) of generation `gen`. Never
    moves the marker back, and never touches another generation."""
    path = state_path(session_dir, cc_session_id, "observed")
    try:
        with _locked(path):
            rec = _load(path, _EMPTY_JOURNAL)
            if int(rec.get("gen") or 0) != gen:
                return
            n = len(rec.get("entries") or [])
            rec["sent"] = max(int(rec.get("sent") or 0), min(upto, n))
            _save(path, rec)
    except (OSError, ValueError):
        pass                      # unmarked entries are sent again: duplicates only


# ── Reuse grants (E3b) ───────────────────────────────────────────────────────

_EMPTY_REUSE = {"state": None, "contract": None, "epoch": None, "grants": {}}


def reuse_load(session_dir: str, cc_session_id: str) -> dict:
    path = state_path(session_dir, cc_session_id, "reuse")
    try:
        with _locked(path):
            return _load(path, _EMPTY_REUSE)
    except (OSError, ValueError):
        return dict(_EMPTY_REUSE)


def reuse_update(session_dir: str, cc_session_id: str, *, state: Optional[str],
                 grants: Optional[dict] = None, contract: Optional[str] = None,
                 epoch: Optional[int] = None) -> None:
    """Record the service's session-state version and the account's contract
    version after a verified call, and any grants that call returned. A new
    version of either drops every grant issued at another: they answer a
    question about a different vector. (No time-based expiry: owner design
    2026-10-03.)"""
    path = state_path(session_dir, cc_session_id, "reuse")
    try:
        with _locked(path):
            rec = _load(path, _EMPTY_REUSE)
            kept = rec.get("grants") or {}
            seen = rec.get("epoch")
            # The newest revocation epoch ever seen (monotone): an answer with
            # an older one never lowers it, and an unknown one ends re-use.
            new_epoch = (None if epoch is None
                         else max(epoch, seen) if isinstance(seen, int) else epoch)
            if (rec.get("state") != state or rec.get("contract") != contract
                    or new_epoch is None or new_epoch != seen):
                kept = {}
            if new_epoch is not None and epoch is not None and epoch < new_epoch:
                grants = {}                       # issued under an older epoch
            for k, g in (grants or {}).items():
                kept[k] = g
            if len(kept) > MAX_REUSE_ENTRIES:
                kept = dict(list(kept.items())[-MAX_REUSE_ENTRIES:])
            _save(path, {"state": state, "contract": contract, "epoch": new_epoch,
                         "grants": kept, "pending": False})
    except (OSError, ValueError):
        pass


def reuse_mark_pending(session_dir: str, cc_session_id: str) -> None:
    """A call is about to reach the service: until its answer is recorded,
    the state the hook last saw may be stale (the service may have changed it
    and the answer been lost), so nothing is reused."""
    path = state_path(session_dir, cc_session_id, "reuse")
    try:
        with _locked(path):
            rec = _load(path, _EMPTY_REUSE)
            rec["pending"] = True
            _save(path, rec)
    except (OSError, ValueError):
        pass


def reuse_forget(session_dir: str, cc_session_id: str) -> None:
    path = state_path(session_dir, cc_session_id, "reuse")
    with contextlib.suppress(OSError):
        os.remove(path)
