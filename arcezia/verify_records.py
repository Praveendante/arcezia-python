#!/usr/bin/env python3
"""
arcezia-verify-records: check an Arcezia decision-record export offline.

    pip install "arcezia[verify]"            # or: pip install cryptography
    arcezia-verify-records export.ndjson --public-key keys.json
    arcezia-verify-records page1.ndjson page2.ndjson --public-key <base64url>
    python verify_records.py export.ndjson --public-key keys.json --json report.json

Who this is for
---------------
An auditor, examiner or insurer who has been handed an account's export and
wants to know, without trusting Arcezia or the account holder, whether the
records in it are the records that were signed, in the order they were
written, with nothing removed.

This file imports nothing from Arcezia and needs no network. It uses the Python
standard library and one cryptography package (`cryptography`, for Ed25519).
It reads the export format exactly as the account export returns it and
interprets none of the decisions inside it: it checks signatures, order and
completeness, and reports what it found.

Inputs
------
* One or more export files (NDJSON as returned by the account export: a header
  line, then one record per line; or the JSON form with a "records" list).
  Pass every page; order does not matter.
* The account's public signing key, obtained INDEPENDENTLY of the export:
  either the base64url key itself, or a JSON file holding a `public_key` /
  `keys` list (the public-key document the account holder can download).
  Without it the check can only show the file agrees with itself.
  Better still, the key's SHA-256 fingerprint, which the account holder reads
  from its dashboard or the record-keys route and gives the auditor out of
  band (--fingerprint): a key whose fingerprint does not match is not used,
  wherever it came from, and a key taken from the export that does match is
  as good as one supplied independently.
* Optionally, signed checkpoints the account holder kept outside Arcezia
  (--checkpoint). A file cannot vouch for its own completeness; a checkpoint
  held elsewhere can.
* Optionally, the signed erasure statements of a deleted account (--erasure),
  as the erasure-statements route returns them for the deletion receipt.

What is checked
---------------
Per record:
  signature    the Ed25519 signature matches the record's signed content
  agreement    the plain columns beside the signed content (verdict, domain,
               action type, session, request, chain and step ids) say the
               same thing as the signed content
  account      the record belongs to the account the export is for
  link         the record's prev_hash equals the previous record's record_hash
  approvals    the approvals a decision was made with (id, role, approver key
               fingerprint, call binding, whether it counted) are read only
               from the signed content, so they are covered by the signature
  erasure      a record whose content was erased is named, with the hash it
               carried, by a signed erasure statement
  attestation  a record signed before the public record format is exported
               without its signed bytes (they carry Arcezia-internal names):
               its `view` and a signed `view_attestation` over its id,
               account, record_hash and the SHA-256 of the view. The
               attestation signature, each of those bindings, and the plain
               columns against the view are checked (Arcezia attests only
               after recomputing the record's hash from its stored bytes;
               a record whose hash did not recompute is marked
               chain_hash_mismatch and fails); then the record's
               record_hash must be linked, record by record with no gap, to a
               signed checkpoint whose head record is in hand
Across the export:
  order        record ids strictly increase and no id appears twice
  start        the first record starts the chain, or follows a signed
               retention-removal statement that names its predecessor
  checkpoints  each signed checkpoint verifies; the export reaches at least as
               far as the strongest one; the record a checkpoint names still
               carries the hash it named; at least as many records remain as
               the checkpoint counted, less any signed removals
  removals     each signed retention-removal statement verifies
  header       each page's header signature verifies, and its account, record
               count, first and last record (id and hash) and next page match
               the records in the file (an unsigned header, from before
               headers were signed, is reported and relied on for nothing)
  erasures     each signed erasure statement verifies and names this account;
               no record in the export carries a hash different from the one
               a statement says it carried

Results
-------
Every record is PASS, PASS-ATTESTED, FAIL or UNVERIFIED.

  PASS        every check above that applies to this record succeeded
  PASS-ATTESTED
              a record signed before the public format whose signed bytes are
              not in the export: its integrity is proven by the chain (its
              record_hash links to a signed checkpoint) and its content is
              vouched for by a current signed attestation of its view. Not the
              same as PASS: you are trusting the attestation for the content,
              not checking the original signature yourself
  FAIL        a check found a contradiction: content altered, a signature
              forged, a record missing between two others, a column edited
  UNVERIFIED  nothing contradicts the record, and something needed to confirm
              it is absent: no key for its key id, an unsigned record, content
              erased, a format this checker does not implement

UNVERIFIED is never reported as FAIL, and never counted as PASS.

Exit status: 0 everything PASS or PASS-ATTESTED and the export is complete
(the RESULT line says PASS-ATTESTED when any record is); 1 at least one FAIL;
2 no FAIL, but something is UNVERIFIED or completeness is unknown; 3 the input
could not be read.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from decimal import Decimal

__all__ = ["canonicalize", "load_bundle", "load_keys", "check_bundle", "main"]

RECORD_SCHEME = "ed25519-record-v1"
CHECKPOINT_SCHEME = "ed25519-chain-checkpoint-v1"
PURGE_SCHEME = "ed25519-purge-attestation-v1"
ERASURE_SCHEME = "ed25519-erasure-attestation-v1"
HEADER_SCHEME = "ed25519-export-header-v1"
VIEW_SCHEME = "ed25519-view-attestation-v1"
# The erasure statements that name records an export can hold.
DECISION_LEDGER = "decision_record"
CANONICALIZATION = "arcezia-jcs-plain-v1"
CHAIN_START = "GENESIS"

PASS, FAIL, UNVERIFIED = "PASS", "FAIL", "UNVERIFIED"
# A record signed before the public record format: its signed bytes are not
# in the export (they carry internal names). Never reported as PASS.
PASS_ATTESTED = "PASS-ATTESTED"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# Plain columns that travel beside the signed content, and where the same fact
# sits inside the signed content. A column is checked only when the signed
# content carries the field; otherwise the column is reported as not covered.
_AGREEMENT = (
    ("verdict", ("verdict",)),
    ("fabrication_detected", ("fabrication_detected",)),
    ("domain", ("record", "domain")),
    ("action_type", ("record", "action_type")),
    ("check_type", ("record", "check_type")),
    ("chain_id", ("record", "chain_id")),
    ("step_id", ("record", "step_id")),
    ("session_id", ("record", "session_id")),
    ("request_id", ("record", "request_id")),
)


# ── Canonical bytes ──────────────────────────────────────────────────────────
# RFC 8785 (JSON Canonicalization Scheme) with one stated difference: numbers
# are written as their plain decimal expansion, never in exponent form, which
# is the form the records are stored and returned in.

_ESCAPES = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r",
            0x22: '\\"', 0x5C: "\\\\"}


def _number(value) -> str:
    d = Decimal(value) if isinstance(value, int) else Decimal(repr(value))
    if d == 0:
        return "0"
    out = format(d, "f")
    return out.rstrip("0").rstrip(".") if "." in out else out


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if cp in _ESCAPES:
            out.append(_ESCAPES[cp])
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canonicalize(value) -> str:
    """The canonical JSON text of `value` (see the note above)."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (int, float, Decimal)):
        return _number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(),
                       key=lambda kv: str(kv[0]).encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_string(str(k)) + ":" + canonicalize(v)
                              for k, v in items) + "}"
    raise TypeError(f"cannot canonicalize {type(value).__name__}")


def _signed_bytes(cert: dict, canon) -> bytes:
    body = {k: v for k, v in cert.items() if k != "record_signature"}
    if canon is None:
        # Records signed before signatures named their format: sorted keys,
        # compact separators, ASCII escapes.
        return json.dumps(body, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode()
    return canonicalize(body).encode("utf-8")


# ── Keys ─────────────────────────────────────────────────────────────────────

def _b64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _ed25519():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        print("This checker needs the 'cryptography' package: "
              "pip install cryptography", file=sys.stderr)
        raise SystemExit(3)
    return Ed25519PublicKey, InvalidSignature


def key_id_of(public_key_b64: str) -> str:
    """The key id a record names for this public key."""
    return hashlib.sha256(_b64(public_key_b64)).hexdigest()[:16]


def load_keys(arg) -> tuple[dict, list]:
    """
    {key_id: public_key_b64} from a base64url key, a path to a JSON key
    document, or an already-parsed key document. Returns (keys, problems). A
    key whose stated id does not belong to it is left out and reported: it
    would otherwise vouch for records it never signed.
    """
    problems: list[str] = []
    entries: list[dict] = []
    doc = arg
    if isinstance(arg, str):
        if os.path.exists(arg):
            with open(arg, encoding="utf-8") as fh:
                doc = json.load(fh)
        else:
            doc = {"public_key": arg.strip()}
    if isinstance(doc, dict) and isinstance(doc.get("signature"), dict):
        doc = doc["signature"]                     # an export header was passed
    if isinstance(doc, dict):
        entries.extend(e for e in (doc.get("keys") or []) if isinstance(e, dict))
        if doc.get("public_key"):
            entries.append({"key_id": doc.get("key_id"), "public_key": doc["public_key"]})
    elif isinstance(doc, list):
        entries.extend(e for e in doc if isinstance(e, dict))

    keys: dict[str, str] = {}
    for e in entries:
        pub = e.get("public_key")
        if not isinstance(pub, str):
            continue
        try:
            if len(_b64(pub)) != 32:
                raise ValueError("not 32 bytes")
        except Exception as exc:
            problems.append(f"a supplied public key is unusable ({exc})")
            continue
        derived = key_id_of(pub)
        stated = e.get("key_id")
        if stated and stated != derived:
            problems.append(f"key document says key id {stated} for a key whose "
                            f"id is {derived}; that entry was not used")
            continue
        keys[derived] = pub
    if not keys and not problems:
        problems.append("no public key was found in the key input")
    return keys, problems


# ── Loading the export ───────────────────────────────────────────────────────

def _parse_file(path: str) -> tuple[dict, list]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read().strip()
    if not text:
        return {}, []
    try:
        doc = json.loads(text)
        if isinstance(doc, dict) and isinstance(doc.get("records"), list):
            return {k: v for k, v in doc.items() if k != "records"}, doc["records"]
    except json.JSONDecodeError:
        pass
    header, records = {}, []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path} line {n} is not JSON ({exc})")
        if not isinstance(obj, dict):
            raise ValueError(f"{path} line {n} is not a JSON object")
        if "log_id" not in obj and ("signature" in obj or "checkpoints" in obj):
            header = obj
            continue
        records.append(obj)
    return header, records


def load_bundle(paths: list[str]) -> dict:
    """Every page of one account's export, merged and ordered by record id."""
    headers, records, problems, pages = [], [], [], []
    for p in paths:
        h, r = _parse_file(p)
        headers.append(h)
        pages.append({"file": os.path.basename(p), "header": h, "records": r})
        if h and isinstance(h.get("record_count"), int) and h["record_count"] != len(r):
            problems.append(f"{os.path.basename(p)}: the header says "
                            f"{h['record_count']} records and the file holds {len(r)}")
        records.extend(r)
    accounts = {(h.get("subject") or {}).get("api_key_id") for h in headers if h}
    accounts.discard(None)
    if len(accounts) > 1:
        problems.append(f"the files are exports of different accounts: {sorted(accounts)}")

    def _merge(field, ident):
        seen, out = set(), []
        for h in headers:
            for item in h.get(field) or []:
                key = item.get(ident)
                if key is None or key not in seen:
                    seen.add(key)
                    out.append(item)
        return out

    return {
        "account": next(iter(accounts)) if len(accounts) == 1 else None,
        "header_keys": [h.get("signature") for h in headers
                        if isinstance(h.get("signature"), dict)],
        "checkpoints": _merge("checkpoints", "checkpoint_id"),
        "purge_statements": _merge("purge_attestations", "purge_id"),
        "last_page_claimed": any(h.get("next_after_id") in (None, 0)
                                 for h in headers if h) or not any(headers),
        "records": sorted(records, key=lambda r: (r.get("log_id") is None,
                                                  r.get("log_id") or 0)),
        "problems": problems,
        "pages": pages,
    }


# ── Signatures ───────────────────────────────────────────────────────────────

def _verify(pub_b64: str, signature: str, payload: bytes) -> bool:
    Ed25519PublicKey, InvalidSignature = _ed25519()
    try:
        Ed25519PublicKey.from_public_bytes(_b64(pub_b64)).verify(_b64(signature), payload)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def check_signature(cert: dict, keys: dict) -> tuple[str, str]:
    sig = cert.get("record_signature")
    if not isinstance(sig, dict) or sig.get("scheme") != RECORD_SCHEME:
        # Never signed: written before records were signed (no
        # record_signature), or stored while no signing key was configured
        # (scheme "unsigned"). Nothing can confirm it, nothing contradicts it.
        if isinstance(sig, dict) and sig.get("scheme") == "unsigned":
            return UNVERIFIED, ("the record carries no signature (stored while "
                                "no signing key was configured)")
        return UNVERIFIED, "the record carries no signature"
    key_id = sig.get("key_id")
    pub = keys.get(key_id)
    if pub is None:
        return UNVERIFIED, (f"no key was supplied for key id {key_id}; a missing "
                            f"key is not evidence of alteration")
    canon = sig.get("canonicalization")
    if canon not in (CANONICALIZATION, None):
        return UNVERIFIED, f"signed in a format this checker does not implement ({canon})"
    if _verify(pub, sig.get("signature") or "", _signed_bytes(cert, canon)):
        return PASS, f"signature matches (key {key_id})"
    return FAIL, "signature does not match the record's content: altered or forged"


def _detached(sig: dict, payload: dict, keys: dict, scheme: str) -> tuple[str, str]:
    if not isinstance(sig, dict) or not sig.get("signature"):
        return UNVERIFIED, "carries no signature, so it proves nothing"
    if sig.get("scheme") != scheme:
        return UNVERIFIED, f"signature scheme {sig.get('scheme')!r} is not one this checker reads"
    pub = keys.get(sig.get("key_id"))
    if pub is None:
        return UNVERIFIED, f"no key was supplied for key id {sig.get('key_id')}"
    if _verify(pub, sig["signature"], canonicalize(payload).encode("utf-8")):
        return PASS, "signature matches"
    return FAIL, "signature does not match the stated values: altered or forged"


def check_checkpoint(cp: dict, keys: dict) -> tuple[str, str]:
    return _detached(cp.get("signature") or {}, {
        "api_key_id": cp.get("api_key_id"),
        "max_log_id": cp.get("max_log_id"),
        "row_count": cp.get("row_count"),
        "head_record_hash": cp.get("head_record_hash"),
        "as_of": cp.get("as_of"),
    }, keys, CHECKPOINT_SCHEME)


def check_purge_statement(st: dict, keys: dict) -> tuple[str, str]:
    return _detached(st.get("signature") or {}, {
        "api_key_id": st.get("api_key_id"),
        "purged_count": st.get("purged_count"),
        "purged_through_id": st.get("purged_through_id"),
        "purged_through_hash": st.get("purged_through_hash"),
        "cutoff": st.get("cutoff"),
        "archive_sha256": st.get("archive_sha256"),
    }, keys, PURGE_SCHEME)


def check_erasure_statement(st: dict, keys: dict) -> tuple[str, str]:
    return _detached(st.get("signature") or {}, {
        "ledger": st.get("ledger"),
        "api_key_id": st.get("api_key_id"),
        "log_ids": st.get("log_ids"),
        "record_hashes": st.get("record_hashes"),
        "legal_basis": st.get("legal_basis"),
        "request_ref": st.get("request_ref"),
    }, keys, ERASURE_SCHEME)


def _header_payload(h: dict) -> dict:
    page = h.get("page") if isinstance(h.get("page"), dict) else {}
    period = h.get("period") if isinstance(h.get("period"), dict) else {}
    return {
        "scheme": HEADER_SCHEME,
        "api_key_id": (h.get("subject") or {}).get("api_key_id"),
        "period_from": period.get("from"),
        "period_to": period.get("to"),
        "after_id": page.get("after_id"),
        "record_count": h.get("record_count"),
        "first_log_id": page.get("first_log_id"),
        "last_log_id": page.get("last_log_id"),
        "first_record_hash": page.get("first_record_hash"),
        "last_record_hash": page.get("last_record_hash"),
        "next_after_id": h.get("next_after_id"),
        "generated_at": h.get("generated_at"),
    }


def check_header(page: dict, keys: dict) -> tuple[str, str]:
    """One page's header: its signature, then its claims against the file."""
    h, recs = page.get("header") or {}, page.get("records") or []
    if not h:
        return UNVERIFIED, "the file has no header line"
    status, reason = _detached(h.get("header_signature") or {}, _header_payload(h),
                               keys, HEADER_SCHEME)
    if status != PASS:
        return status, "header " + reason
    pg = h.get("page") or {}
    first, last = (recs[0] if recs else {}), (recs[-1] if recs else {})
    wrong = []
    if h.get("record_count") != len(recs):
        wrong.append(f"it counts {h.get('record_count')} records and the file holds {len(recs)}")
    if (pg.get("first_log_id"), pg.get("first_record_hash")) != (first.get("log_id"), first.get("record_hash")):
        wrong.append("its first record is not the file's first record")
    if (pg.get("last_log_id"), pg.get("last_record_hash")) != (last.get("log_id"), last.get("record_hash")):
        wrong.append("its last record is not the file's last record")
    if wrong:
        return FAIL, "the signed header does not match the file: " + "; ".join(wrong)
    return PASS, "header signature matches and agrees with the file"


def check_view_attestation(rec: dict, keys: dict, account) -> tuple[str, str]:
    """A withheld record's view attestation: its signature, then that it names
    THIS record (id, account, record_hash) and THIS view (SHA-256 of its
    canonical bytes). Any disagreement is a FAIL."""
    view, att = rec.get("view"), rec.get("view_attestation")
    if not isinstance(view, dict):
        return UNVERIFIED, "the record's content is withheld and no view is present"
    if not isinstance(att, dict):
        return UNVERIFIED, ("the record's content is withheld and it carries no view "
                            "attestation (the server could not check its stored signature)")
    payload = {"scheme": VIEW_SCHEME, "log_id": att.get("log_id"),
               "api_key_id": att.get("api_key_id"), "record_hash": att.get("record_hash"),
               "view_sha256": att.get("view_sha256"), "attested_at": att.get("attested_at")}
    status, reason = _detached(att.get("signature") or {}, payload, keys, VIEW_SCHEME)
    if status != PASS:
        return status, "view attestation " + reason
    wrong = []
    if att.get("log_id") != rec.get("log_id"):
        wrong.append(f"it names record {att.get('log_id')}")
    if account is not None and att.get("api_key_id") != account:
        wrong.append(f"it names account {att.get('api_key_id')}")
    if att.get("record_hash") != rec.get("record_hash"):
        wrong.append("it names a different record_hash")
    if hashlib.sha256(canonicalize(view).encode("utf-8")).hexdigest() != att.get("view_sha256"):
        wrong.append("the view is not the view it attests")
    if wrong:
        return FAIL, "the signed view attestation does not match the record: " + "; ".join(wrong)
    return PASS, (f"view attestation matches (key {(att.get('signature') or {}).get('key_id')}, "
                  f"attested {att.get('attested_at')})")


def load_erasure_statements(paths: list[str]) -> list[dict]:
    """Erasure statements: the route's response, a list, or one per line."""
    out = []
    for path in paths or []:
        with open(path, encoding="utf-8") as fh:
            text = fh.read().strip()
        try:
            doc = json.loads(text)
            items = doc if isinstance(doc, list) else [doc]
        except json.JSONDecodeError:
            items = [json.loads(line) for line in text.splitlines() if line.strip()]
        for obj in items:
            if isinstance(obj, dict) and isinstance(obj.get("statements"), list):
                out.extend(x for x in obj["statements"] if isinstance(x, dict))
            elif isinstance(obj, dict) and "log_ids" in obj:
                out.append(obj)
    return out


def fingerprint_of(public_key_b64: str) -> str:
    """The full SHA-256 (hex) of a public key: what the account holder reads
    from its dashboard and gives the auditor out of band."""
    return hashlib.sha256(_b64(public_key_b64)).hexdigest()


def filter_keys(keys: dict, fingerprints) -> tuple[dict, list]:
    """Keep only keys whose full fingerprint was supplied out of band."""
    want = {f.strip().lower() for f in fingerprints or [] if f and f.strip()}
    kept, problems = {}, []
    for kid, pub in keys.items():
        if fingerprint_of(pub) in want:
            kept[kid] = pub
        else:
            problems.append(f"key {kid} (fingerprint {fingerprint_of(pub)}) does not "
                            f"match any fingerprint supplied; it was not used")
    return kept, problems


def load_checkpoints(paths: list[str]) -> list[dict]:
    """Checkpoints kept outside Arcezia: a bare checkpoint, an event wrapping
    one under "checkpoint", a list, or one per line."""
    out = []
    for path in paths or []:
        with open(path, encoding="utf-8") as fh:
            text = fh.read().strip()
        try:
            doc = json.loads(text)
            items = doc if isinstance(doc, list) else [doc]
        except json.JSONDecodeError:
            items = [json.loads(line) for line in text.splitlines() if line.strip()]
        for obj in items:
            if isinstance(obj, dict) and isinstance(obj.get("checkpoint"), dict):
                obj = obj["checkpoint"]
            if isinstance(obj, dict) and "max_log_id" in obj:
                out.append(obj)
    return out


# ── The whole check ──────────────────────────────────────────────────────────

def _dig(obj, path):
    for p in path:
        if not isinstance(obj, dict) or p not in obj:
            return False, None
        obj = obj[p]
    return True, obj


def _is_erased(rec: dict) -> bool:
    """A record reduced to its links: ids and hashes kept, content gone."""
    return (not rec.get("certificate") and rec.get("record_hash") is not None
            and rec.get("verdict") is None and rec.get("timestamp") is None)


def _agreement(rec, content, account, checks, fails, what="the signed content") -> list:
    """Plain columns against the checked content, and the account binding.
    Returns the columns the content does not carry."""
    disagree, uncovered = [], []
    for column, path in _AGREEMENT:
        if column not in rec:
            continue
        present, signed = _dig(content, path)
        if not present:
            uncovered.append(column)
        elif signed != rec[column]:
            disagree.append(f"{column} (column {rec[column]!r}, signed {signed!r})")
    if disagree:
        checks["agreement"] = FAIL
        fails.append(f"plain columns disagree with {what}: " + "; ".join(disagree))
    else:
        checks["agreement"] = PASS
    present, signed_account = _dig(content, ("record", "api_key_id"))
    if present and account is not None and signed_account != account:
        checks["account"] = FAIL
        fails.append(f"signed for account {signed_account}, exported as account {account}")
    elif present:
        checks["account"] = PASS
    return uncovered


def _chain_anchors(bundle, keys, external) -> list:
    """max_log_id of every signed checkpoint that verifies, names this account,
    and whose head record is in hand carrying the hash it recorded."""
    account = bundle.get("account")
    hashes = {r.get("log_id"): r.get("record_hash") for r in bundle.get("records") or []}
    out = []
    for cp in (external or bundle.get("checkpoints") or []):
        status, _r = check_checkpoint(cp, keys)
        head = cp.get("max_log_id")
        if (status == PASS and (account is None or cp.get("api_key_id") == account)
                and head in hashes and hashes[head] == cp.get("head_record_hash")):
            out.append(int(head))
    return out


def check_bundle(bundle: dict, keys: dict, *, external_checkpoints=None,
                 partial: bool = False, erasure_statements=None) -> dict:
    account = bundle.get("account")
    results, exceptions = [], list(bundle.get("problems") or [])
    input_failed = bool(exceptions)

    # Each page's signed header. A FAIL fails the export. An unsigned header
    # (exports made before headers were signed) is reported UNVERIFIED and
    # does not lower the result: no PASS here rests on a header claim. The
    # records, their links, the checkpoints and the statements are each
    # signed; the header's count is compared with the file regardless; and
    # its "last page" claim can only turn an unknown end into a FAIL, never
    # into a PASS. Stripping the signature therefore hides nothing.
    headers = []
    for page in bundle.get("pages") or []:
        if not page.get("header"):
            continue
        status, reason = check_header(page, keys)
        headers.append({"file": page.get("file"), "status": status, "reason": reason})

    # Signed erasure statements (a deleted account): which hash each erased
    # record carried. Only statements over the decision-record ledger name
    # records an export holds.
    erasures, erased_hash = [], {}
    for st in erasure_statements or []:
        status, reason = check_erasure_statement(st, keys)
        if status == PASS and account is not None and st.get("api_key_id") != account:
            status, reason = FAIL, "names a different account"
        erasures.append({"statement_id": st.get("statement_id"), "ledger": st.get("ledger"),
                         "status": status, "reason": reason,
                         "records": len(st.get("log_ids") or [])})
        if status == PASS and st.get("ledger") == DECISION_LEDGER:
            for lid, h in zip(st.get("log_ids") or [], st.get("record_hashes") or []):
                erased_hash[lid] = (h, st.get("statement_id"))

    # Signed removal statements: which chain starts are explained.
    statements = []
    for st in bundle.get("purge_statements") or []:
        status, reason = check_purge_statement(st, keys)
        if status == PASS and account is not None and st.get("api_key_id") != account:
            status, reason = FAIL, "names a different account"
        statements.append({"purge_id": st.get("purge_id"), "status": status,
                           "reason": reason, "removed": st.get("purged_count"),
                           "through_id": st.get("purged_through_id"),
                           "through_hash": st.get("purged_through_hash")})
    valid_starts = {s["through_hash"]: s["through_id"] for s in statements
                    if s["status"] == PASS and s["through_hash"]}

    prev_hash, prev_id, seen, attested_ids = None, None, set(), set()
    for i, rec in enumerate(bundle.get("records") or []):
        log_id = rec.get("log_id")
        cert = rec.get("certificate")
        if isinstance(cert, str):
            try:
                cert = json.loads(cert)
            except json.JSONDecodeError:
                cert = None
        checks, fails, unverified, rec_note = {}, [], [], None
        approvals, approvals_unsigned = None, False

        # order
        if not isinstance(log_id, int):
            fails.append("the record has no usable id")
        elif log_id in seen:
            fails.append(f"record id {log_id} appears more than once")
        seen.add(log_id)

        erased = _is_erased(rec)
        named = erased_hash.get(log_id)
        if named is not None and rec.get("record_hash") != named[0]:
            checks["erasure"] = FAIL
            fails.append(f"signed erasure statement {named[1]} says this record "
                         f"carried a different hash")
        elif named is not None:
            checks["erasure"] = PASS
            rec_note = (f"erased under signed erasure statement {named[1]}, "
                        f"which names this record and its hash")
        if erased and named is not None:
            pass        # content gone; the signed statement accounts for it
        elif erased:
            checks["signature"] = UNVERIFIED
            unverified.append("content erased; only the record's links remain, "
                              "and no signed erasure statement supplied names it")
        elif "certificate_withheld" in rec or "view_attestation" in rec:
            # Signed before the public format: the signed bytes stay with
            # Arcezia (they carry internal names). What can be checked here is
            # the signed view attestation and, after every record is read, the
            # chain from this record to a signed checkpoint.
            status, reason = check_view_attestation(rec, keys, account)
            checks["attestation"] = status
            (fails if status == FAIL else unverified if status == UNVERIFIED
             else []).append(reason)
            if rec.get("integrity") == "signature_mismatch":
                fails.append("the export states this record's stored bytes do not "
                             "match its signature")
            if rec.get("integrity") == "chain_hash_mismatch":
                fails.append("the export states this record's stored record_hash "
                             "does not recompute from its stored bytes: the chain "
                             "column was altered")
            if status == PASS:
                attested_ids.add(log_id)
                _agreement(rec, rec.get("view"), account, checks, fails,
                           what="the attested view")
                rec_note = ("content withheld (signed before the public format); "
                            "checked through the signed view attestation and the chain")
        elif not isinstance(cert, dict) or not cert:
            checks["signature"] = UNVERIFIED
            unverified.append("the record carries no signed content")
        else:
            status, reason = check_signature(cert, keys)
            checks["signature"] = status
            (fails if status == FAIL else unverified if status == UNVERIFIED
             else []).append(reason)
            if status == FAIL and rec.get("vocabulary_note"):
                # Exports made before 2026-10-07 rewrote the field names of
                # older SIGNED records inside the signed object. That is still
                # a FAIL here (the bytes in hand are not the signed bytes, and
                # a note anyone can add must never excuse a mismatch), but the
                # cause is named so the holder knows to export again: current
                # exports ship such a record with a signed view attestation.
                fails.append("the export says it renamed this signed record's "
                             "fields for publication; a current export carries a "
                             "signed view attestation for it instead")

            uncovered = _agreement(rec, cert, account, checks, fails)
            if "view" in rec:
                # Presentation BESIDE the signed object. Never verified, never
                # used for any check above: the certificate is what was signed.
                uncovered.append("view")
            if uncovered:
                rec_note = "not covered by the signature: " + ", ".join(uncovered)
            # Approvals are read from the signed content only.
            present, appr = _dig(cert, ("record", "approvals"))
            if present and checks.get("signature") == PASS:
                approvals = appr
            elif present:
                approvals_unsigned = True

        # link
        rh, ph = rec.get("record_hash"), rec.get("prev_hash")
        if rh is None:
            checks["link"] = UNVERIFIED
            unverified.append("written before records were linked; no ordering claim")
        elif not (isinstance(rh, str) and _HEX64.match(rh)):
            checks["link"] = FAIL
            fails.append("record_hash is not a 64-character hash")
        elif prev_hash is None:
            if ph == CHAIN_START:
                checks["link"] = PASS
            elif ph in valid_starts and isinstance(log_id, int) and log_id > valid_starts[ph]:
                checks["link"] = PASS
            elif partial:
                checks["link"] = UNVERIFIED
                unverified.append("the first record here follows records not in "
                                  "this export (partial export)")
            else:
                checks["link"] = FAIL
                fails.append("the first record follows a record that is not here, "
                             "and no signed removal statement accounts for it")
        elif ph != prev_hash:
            checks["link"] = FAIL
            fails.append(f"does not link to record {prev_id}: a record between "
                         f"them is missing, or one of them was altered")
        else:
            checks["link"] = PASS
        if rh is not None:
            prev_hash, prev_id = rh, log_id

        status = FAIL if fails else UNVERIFIED if unverified else PASS
        signed_at = None
        shown = cert if isinstance(cert, dict) and cert else (
            rec.get("view") if log_id in attested_ids else None)
        if isinstance(shown, dict):
            signed_at = (shown.get("record") or {}).get("signed_at")
        results.append({
            "log_id": log_id,
            "status": status,
            "signed_at": signed_at,
            "verdict": shown.get("verdict") if isinstance(shown, dict) else None,
            "checks": checks,
            "reasons": fails + unverified,
            **({"note": rec_note} if rec_note else {}),
            **({"approvals": approvals} if approvals else {}),
            **({"approvals_note": "approvals present but the signature did not "
                                  "verify, so they are not reported"}
               if approvals_unsigned else {}),
        })

    # Completeness
    completeness = _completeness(bundle, keys, results, statements,
                                 external_checkpoints or [], partial)

    # Attested records: PASS-ATTESTED only when the chain carries them to a
    # signed checkpoint — every record after them up to that checkpoint's
    # head is here and links (a gap or edit there is already a FAIL), and the
    # head still carries the hash the checkpoint signed.
    if attested_ids:
        anchors = _chain_anchors(bundle, keys, external_checkpoints)
        by_id = {r["log_id"]: r for r in results}
        ordered = sorted(i for i in by_id if isinstance(i, int))
        for lid in attested_ids:
            r = by_id.get(lid)
            if r is None or r["status"] != PASS:
                continue
            covered = any(
                a >= lid and all(by_id[j]["checks"].get("link") == PASS
                                 for j in ordered if lid < j <= a)
                for a in anchors)
            if covered:
                r["status"] = PASS_ATTESTED
                r["reasons"] = [
                    "integrity proven by the chain: its record_hash is linked, "
                    "record by record, to a signed checkpoint; content vouched for "
                    "by a signed view attestation (its signed bytes are not in the "
                    "export)"]
            else:
                r["status"] = UNVERIFIED
                r["reasons"] = ["the view attestation matches, but no signed checkpoint "
                                "at or after this record is reachable through unbroken "
                                "links in this export"]

    counts = {PASS: 0, PASS_ATTESTED: 0, FAIL: 0, UNVERIFIED: 0}
    for r in results:
        counts[r["status"]] += 1
    any_fail = (counts[FAIL] or completeness["status"] == FAIL
                or any(s["status"] == FAIL for s in statements)
                or any(c["status"] == FAIL for c in completeness["checkpoints"])
                or any(h["status"] == FAIL for h in headers)
                or any(e["status"] == FAIL for e in erasures))
    all_clear = (not any_fail and not input_failed and counts[UNVERIFIED] == 0
                 and completeness["status"] == PASS
                 and all(s["status"] == PASS for s in statements)
                 and all(e["status"] == PASS for e in erasures))
    return {
        "account": account,
        "records": results,
        "counts": counts,
        "removal_statements": statements,
        "headers": headers,
        "erasure_statements": erasures,
        "completeness": completeness,
        "input_problems": exceptions,
        "time_note": ("the signed time inside each record; the export's plain "
                      "'timestamp' column is not covered by the signature"),
        "result": (FAIL if (any_fail or input_failed) else
                   (PASS_ATTESTED if counts[PASS_ATTESTED] else PASS) if all_clear
                   else UNVERIFIED),
    }


def _completeness(bundle, keys, results, statements, external, partial) -> dict:
    account = bundle.get("account")
    source = "kept outside the export" if external else "carried inside the export"
    pool = external or (bundle.get("checkpoints") or [])
    cps, best = [], None
    hashes = {rec.get("log_id"): rec.get("record_hash") for rec in bundle.get("records") or []}
    for cp in pool:
        status, reason = check_checkpoint(cp, keys)
        if status == PASS and account is not None and cp.get("api_key_id") != account:
            status, reason = FAIL, "names a different account"
        entry = {"checkpoint_id": cp.get("checkpoint_id"), "status": status,
                 "reason": reason, "max_log_id": cp.get("max_log_id"),
                 "row_count": cp.get("row_count"), "as_of": cp.get("as_of")}
        if status == PASS:
            head = cp.get("max_log_id")
            if head in hashes and hashes[head] != cp.get("head_record_hash"):
                entry["status"] = FAIL
                entry["reason"] = (f"record {head} no longer carries the hash this "
                                   f"checkpoint recorded for it")
            elif best is None or int(cp.get("max_log_id") or 0) > int(best.get("max_log_id") or 0):
                best = cp
        cps.append(entry)

    out = {"source": source, "checkpoints": cps}
    if any(c["status"] == FAIL for c in cps):
        out.update(status=FAIL, detail="a checkpoint contradicts the export")
        return out
    if best is None:
        out.update(status=UNVERIFIED, detail=(
            "no signed checkpoint could be verified, so whether records were "
            "removed from the end of the export is unknown"))
        return out
    anchor = int(best.get("max_log_id") or 0)
    ids = [r["log_id"] for r in results if isinstance(r["log_id"], int)]
    top = max(ids) if ids else 0
    if top < anchor:
        if partial or not bundle.get("last_page_claimed"):
            out.update(status=UNVERIFIED, detail=(
                f"the export stops at record {top}; a signed checkpoint shows the "
                f"account reached record {anchor}. Fetch the remaining pages."))
        else:
            out.update(status=FAIL, detail=(
                f"the export stops at record {top}, but a signed checkpoint taken "
                f"{best.get('as_of')} shows the account reached record {anchor}. "
                f"Records after {top} existed and are not here."))
        return out
    removed = sum(int(s.get("removed") or 0) for s in statements if s["status"] == PASS)
    held = sum(1 for i in ids if i <= anchor and hashes.get(i) is not None)
    floor = int(best.get("row_count") or 0) - removed
    if not partial and held < floor:
        out.update(status=FAIL, detail=(
            f"the signed checkpoint counted {best.get('row_count')} records up to "
            f"record {anchor}; with {removed} removed under signed statements, at "
            f"least {floor} should be here, and {held} are"))
        return out
    out.update(status=PASS, detail=(
        f"the export reaches record {top}, at or beyond the strongest signed "
        f"checkpoint (record {anchor}, {source})"))
    if not external:
        out["caution"] = ("these checkpoints travelled inside the export; one "
                          "kept outside Arcezia (--checkpoint) is stronger evidence")
    return out


# ── Report ───────────────────────────────────────────────────────────────────

def _print_report(rep: dict, key_note: str, quiet: bool) -> None:
    w = print
    w(f"account        : {rep['account']}")
    w(f"keys           : {key_note}")
    for kid, fp in (rep.get("keys") or {}).get("fingerprints_sha256", {}).items():
        w(f"  key {kid}  sha256 {fp}  (compare with the account holder's)")
    w(f"records        : {len(rep['records'])}")
    w(f"times shown    : {rep['time_note']}")
    for p in rep["input_problems"]:
        w(f"INPUT PROBLEM  : {p}")
    w("")
    for r in rep["records"]:
        if quiet and r["status"] in (PASS, PASS_ATTESTED):
            continue
        w(f"  record {r['log_id']!s:>8}  {r['status']:<10}  signed {r['signed_at'] or '-'}"
          f"  verdict {r['verdict'] or '-'}")
        for reason in r["reasons"]:
            if r["status"] != PASS:
                w(f"{'':22}- {reason}")
        if r.get("note") and not quiet:
            w(f"{'':22}note: {r['note']}")
        if r.get("approvals") and not quiet:
            for a in r["approvals"]:
                w(f"{'':22}approval: {a.get('kind')} id {a.get('approval_id')} "
                  f"role {a.get('role')} approver key {a.get('approver_key')} "
                  f"bound to {a.get('bound_to')} counted {a.get('counted')}"
                  + (f" ({a.get('not_counted')})" if a.get("not_counted") else ""))
    if rep["removal_statements"]:
        w("\nsigned retention-removal statements:")
        for s in rep["removal_statements"]:
            w(f"  statement {s['purge_id']!s:>5}  {s['status']:<10}  {s['removed']} record(s) "
              f"through record {s['through_id']}: {s['reason']}")
    if rep.get("headers"):
        w("\nexport headers:")
        for h in rep["headers"]:
            w(f"  {h['file']}  {h['status']:<10}  {h['reason']}")
    if rep.get("erasure_statements"):
        w("\nsigned erasure statements:")
        for e in rep["erasure_statements"]:
            w(f"  statement {e['statement_id']!s:>5}  {e['status']:<10}  {e['ledger']}, "
              f"{e['records']} record(s): {e['reason']}")
    c = rep["completeness"]
    w(f"\ncheckpoints ({c['source']}):")
    if not c["checkpoints"]:
        w("  none")
    for cp in c["checkpoints"]:
        w(f"  checkpoint {cp['checkpoint_id']!s:>5}  {cp['status']:<10}  up to record "
          f"{cp['max_log_id']}, {cp['row_count']} record(s), as of {cp['as_of']}: {cp['reason']}")
    w(f"\ncompleteness   : {c['status']}  {c['detail']}")
    if c.get("caution"):
        w(f"                 ({c['caution']})")
    n = rep["counts"]
    w(f"\nPASS {n[PASS]}   PASS-ATTESTED {n[PASS_ATTESTED]}   FAIL {n[FAIL]}   "
      f"UNVERIFIED {n[UNVERIFIED]}")
    w(f"RESULT         : {rep['result']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="arcezia-verify-records",
        description="Check an Arcezia decision-record export offline: "
                    "signatures, order, and completeness.")
    ap.add_argument("export", nargs="+", help="export file(s): every page of one account's export")
    ap.add_argument("--public-key", help="the account's public signing key (base64url), "
                    "or a JSON key document, obtained independently of the export")
    ap.add_argument("--checkpoint", action="append", default=[],
                    help="a signed checkpoint kept outside Arcezia (repeatable)")
    ap.add_argument("--partial", action="store_true",
                    help="the export deliberately covers only part of the account's "
                         "history; start and end are then reported, not failed")
    ap.add_argument("--use-export-keys", action="store_true",
                    help="no independent key: use the keys printed in the export "
                         "header (shows only that the file agrees with itself)")
    ap.add_argument("--fingerprint", action="append", default=[],
                    help="the SHA-256 fingerprint of the account's record-signing key, "
                         "given to you by the account holder out of band (repeatable); "
                         "keys that do not match are not used")
    ap.add_argument("--erasure", action="append", default=[],
                    help="signed erasure statements of a deleted account (repeatable)")
    ap.add_argument("--json", metavar="PATH", help="also write the full report as JSON")
    ap.add_argument("--quiet", action="store_true", help="list only records that are not PASS")
    args = ap.parse_args(argv)

    try:
        bundle = load_bundle(args.export)
        external = load_checkpoints(args.checkpoint)
        erasures = load_erasure_statements(args.erasure)
    except (OSError, ValueError) as exc:
        print(f"cannot read the input: {exc}", file=sys.stderr)
        return 3

    if args.public_key:
        try:
            keys, problems = load_keys(args.public_key)
        except (OSError, ValueError) as exc:
            print(f"cannot read the key: {exc}", file=sys.stderr)
            return 3
        key_note = f"{len(keys)} key(s) supplied independently of the export"
    elif args.use_export_keys:
        keys, problems = {}, []
        for hk in bundle["header_keys"]:
            k, p = load_keys(hk)
            keys.update(k)
            problems += p
        key_note = ("taken from the export itself: this shows only that the "
                    "file agrees with itself")
    else:
        print("Supply the account's public key with --public-key (obtained "
              "independently of the export), or pass --use-export-keys for a "
              "self-consistency check only.", file=sys.stderr)
        return 3
    if not keys:
        print("no usable public key: " + "; ".join(problems), file=sys.stderr)
        return 3
    if args.fingerprint:
        # A key that does not match the fingerprint the account holder gave
        # out of band is not used, wherever it came from. The records it would
        # have checked are then UNVERIFIED (no key), never PASS.
        keys, fp_problems = filter_keys(keys, args.fingerprint)
        problems += fp_problems
        key_note = ((f"{len(keys)} key(s) matched a fingerprint supplied out of band"
                     + (" (keys read from the export)" if args.use_export_keys else ""))
                    if keys else "no key matched the fingerprint supplied out of band")
        for msg in fp_problems:
            print(f"key: {msg}", file=sys.stderr)
        problems = [p for p in problems if p not in fp_problems]
    bundle["problems"] = list(bundle["problems"]) + problems

    rep = check_bundle(bundle, keys, external_checkpoints=external, partial=args.partial,
                       erasure_statements=erasures)
    rep["keys"] = {"source": key_note, "key_ids": sorted(keys),
                   "fingerprints_sha256": {k: fingerprint_of(v) for k, v in sorted(keys.items())}}
    if args.use_export_keys and not args.fingerprint and rep["result"] in (PASS, PASS_ATTESTED):
        rep["result"] = UNVERIFIED
    _print_report(rep, key_note, args.quiet)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=2, sort_keys=True)
    return {PASS: 0, PASS_ATTESTED: 0, FAIL: 1, UNVERIFIED: 2}[rep["result"]]


if __name__ == "__main__":
    raise SystemExit(main())
