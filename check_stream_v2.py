#!/usr/bin/env python3
"""check_stream_v2.py — production-grade completeness verifier.

DRAFT prototype. Read-only against the real log; never appends anything.

Evolves the design's check_stream.py into a verifier whose primary output is a
single machine-readable status per (issuer, stream), suitable for a monitor to
consume and alert on:

    ok         no violations; density + chain + freshness all hold
    gap        a hole in the sequence, a broken prev-hash chain, or an
               out-of-order leaf (V1.2 / V1.3 / V1.6)
    duplicate  two signed claims share (issuer, stream, seq) — a self-contained
               misbehavior proof (V1.4)
    overclaim  a signed statement or run-receipt contradicts the covered log:
               COUNT_OVERCLAIM / COUNT_UNDERCLAIM / TIP_MISMATCH /
               STATEMENT_ROLLBACK / RECEIPT_NON_INCLUSION / RECEIPT_UNDERCOUNT
               (V3.2 / V3.3 / V4.2 / V4.3)
    stale      the stream's latest statement is older than its declared
               deadline T — a liveness flag, not a misbehavior proof (V3.4)

Severity order (worst wins): duplicate > overclaim > gap > stale > ok.

Typed claims (enrollment / statement / receipt) are read from the log itself by
claimType when present, exactly as they would be in production; side files
(--statements / --receipts / --enrollment) can supply counterparty-held or
not-yet-deployed objects for testing and audit.

Canonicalization, hashing, did:key, and signature verification all come from
stream_lib, so the verifier and the emitter agree byte-for-byte on leaf bytes.

Exit codes: 0 = ok, 1 = any non-ok status, 2 = usage/fetch error.
"""
from __future__ import annotations

import argparse
import base64
import json
import subprocess
import time
import sys
from datetime import datetime, timezone

import stream_lib as sl

# --- status model ------------------------------------------------------------
STATUS_ORDER = ["ok", "stale", "gap", "overclaim", "duplicate"]  # worst last

# maps every internal violation code to its coarse monitor status
CODE_STATUS = {
    "GAP": "gap",
    "CHAIN_BREAK": "gap",
    "ORDER_VIOLATION": "gap",
    "LATE_REPAIR": "ok",
    "ISSUER_CHANGE": "gap",
    "DUP_SEQ": "duplicate",
    "ENROLLMENT_FORK": "duplicate",
    "COUNT_OVERCLAIM": "overclaim",
    "COUNT_UNDERCLAIM": "overclaim",
    "TIP_MISMATCH": "overclaim",
    "STATEMENT_ROLLBACK": "overclaim",
    "RECEIPT_NON_INCLUSION": "overclaim",
    "RECEIPT_UNDERCOUNT": "overclaim",
    "BAD_SIG": "overclaim",
    "STALE": "stale",
}

DEFAULT_STALE_CHECKPOINTS = 200
DEFAULT_STALE_SECONDS = 7 * 86400


def worst(a: str, b: str) -> str:
    return a if STATUS_ORDER.index(a) >= STATUS_ORDER.index(b) else b


class StreamResult:
    """Machine-readable verification result for one (issuer, stream)."""

    def __init__(self, issuer, stream):
        self.issuer = issuer
        self.stream = stream
        self.status = "ok"
        self.records = 0
        self.max_seq = None
        self.tip_hash = None
        self.findings = []        # [{severity, code, msg}]
        self.info = []            # human-readable ok notes
        self.proofs = []          # exportable, re-verifiable misbehavior proofs

    def viol(self, code, msg, proof=None):
        st = CODE_STATUS.get(code, "overclaim")
        self.status = worst(self.status, st)
        self.findings.append({"severity": st, "code": code, "msg": msg})
        if proof is not None:
            self.proofs.append({"code": code, "evidence": proof})

    def note(self, msg):
        self.info.append(msg)

    def to_dict(self):
        return {
            "issuer": self.issuer,
            "stream": self.stream,
            "status": self.status,
            "records": self.records,
            "max_seq": self.max_seq,
            "tip_hash": self.tip_hash,
            "findings": self.findings,
            "info": self.info,
            "misbehavior_proofs": self.proofs,
        }


# --- log I/O -----------------------------------------------------------------
def _curl(url, ua, attempts=3, timeout=30):
    """One page fetch with retries. A single slow response is not an incident;
    only a repeated failure is worth waking someone for."""
    last = None
    for i in range(attempts):
        out = subprocess.run(
            ["curl", "-s", "--max-time", str(timeout), "-A", ua, url],
            capture_output=True)
        if out.returncode == 0:
            return out
        last = out.returncode
        if i + 1 < attempts:
            time.sleep(3 * (3 ** i))  # 3s, then 9s
    raise RuntimeError(
        f"fetch failed after {attempts} attempts (last curl exit {last}): {url}")


def fetch_leaves(log_url, ua="markovian-check-stream/2.0"):
    """Read-only paginated fetch of all leaves. Returns list of b64 strings."""
    leaves, start = [], 0
    while True:
        out = _curl(f"{log_url}/leaves?start={start}", ua)
        if not out.stdout.strip():
            break
        page = json.loads(out.stdout)
        got = page.get("leaves", [])
        leaves.extend(got)
        end = page.get("end", start + len(got))
        if not got or end <= start:
            break
        start = end
        if len(got) < 256:  # short page = final page
            break
    return leaves


def parse_leaf(b64):
    raw = base64.b64decode(b64)
    try:
        obj = json.loads(raw)
    except Exception:
        return raw, None
    return raw, obj if isinstance(obj, dict) else None


def _core_of(obj):
    if obj and "core" in obj and isinstance(obj["core"], dict):
        return obj["core"], obj.get("issuer_sig")
    return obj, None


# claim types that carry stream/seq-shaped fields but are NOT stream records
# (a run-receipt has stream+seq; a receipt logged as evidence must not be
# mistaken for the numbered record it points at).
NON_CLAIM_TYPES = {sl.RECEIPT_TYPE, sl.STATEMENT_TYPE, sl.ENROLLMENT_TYPE,
                   sl.ROTATION_TYPE}


def stream_claim_view(obj):
    """Normalize legacy signal-commit/v1 and enveloped stream-claim/v1 to one view."""
    if obj is None:
        return None
    core, sig = _core_of(obj)
    if not isinstance(core, dict) or core.get("claimType") in NON_CLAIM_TYPES:
        return None
    claim = core.get("claim")
    if not isinstance(claim, dict) or "stream" not in claim or "seq" not in claim:
        return None
    prev = claim.get("prev_claim_hash")
    if prev is None and isinstance(obj.get("prior"), list) and obj["prior"]:
        prev = obj["prior"][0]  # legacy: chain hash outside the (absent) sig
    return {"issuer": core.get("issuer"), "stream": claim["stream"],
            "seq": claim["seq"], "prev": prev,
            "claimType": core.get("claimType"), "core": core, "sig": sig}


# --- verification ------------------------------------------------------------
def verify_stream(leaves_b64, issuer, stream, *, statements=None, receipts=None,
                  enrollment=None, checkpoint_size=None, now=None,
                  follow_rotation=True,
                  stale_checkpoints=DEFAULT_STALE_CHECKPOINTS,
                  stale_seconds=DEFAULT_STALE_SECONDS):
    """Verify one (issuer, stream). Returns a StreamResult.

    statements / receipts / enrollment: optional side-channel objects. When
    None, the verifier also harvests any such typed leaves from the log itself.
    """
    res = StreamResult(issuer, stream)
    now = now or datetime.now(timezone.utc)
    if checkpoint_size is None:
        checkpoint_size = len(leaves_b64)

    # single pass over the log: rotations, this stream's claims, typed leaves
    rotations = []          # (idx, old_did, new_did)
    onlog_statements = []
    onlog_receipts = []
    onlog_enrollments = []  # (idx, envelope)
    raw_records = []        # (idx, view, raw)
    for i, b in enumerate(leaves_b64):
        raw, obj = parse_leaf(b)
        if obj is None:
            continue
        core, _ = _core_of(obj)
        ct = core.get("claimType") if isinstance(core, dict) else None
        if ct == sl.ROTATION_TYPE and follow_rotation:
            c = core.get("claim", {})
            rotations.append((i, c.get("old_did"), c.get("new_did")))
        elif ct == sl.STATEMENT_TYPE:
            onlog_statements.append(obj)
        elif ct == sl.RECEIPT_TYPE:
            onlog_receipts.append(obj)
        elif ct == sl.ENROLLMENT_TYPE:
            onlog_enrollments.append((i, obj))
        v = stream_claim_view(obj)
        if v and v["stream"] == stream:
            raw_records.append((i, v, raw))

    # accepted issuer identities across on-log rotations
    def issuer_chain(did):
        chain, cur = [did], did
        for _, old, new in rotations:
            if old == cur:
                chain.append(new)
                cur = new
        return chain

    accepted = issuer_chain(issuer) if follow_rotation else [issuer]
    records = [{"idx": i, "seq": v["seq"], "prev": v["prev"],
                "leaf_hash": sl.sha256_hex(raw), "issuer": v["issuer"],
                "view": v, "raw": raw}
               for i, v, raw in raw_records if v["issuer"] in accepted]

    if not records:
        res.note(f"no claims for issuer={issuer} stream={stream}")
        return res

    res.records = len(records)
    res.note(f"{len(records)} claims (issuer chain: {' -> '.join(accepted)})")

    # --- enrollment (V1.5 / V2.x): resolve current declared surface ----------
    enr = enrollment
    if enr is None and onlog_enrollments:
        # chain-tip resolution via `supersedes`; fork => ENROLLMENT_FORK
        by_parent = {}
        idx_by_hash = {}
        for idx, e in onlog_enrollments:
            core, _ = _core_of(e)
            if core.get("issuer") not in accepted:
                continue
            h = sl.leaf_hash(e)
            idx_by_hash[h] = e
            parent = core.get("claim", {}).get("supersedes")
            by_parent.setdefault(parent, []).append((idx, e, h))
        for parent, kids in by_parent.items():
            if len(kids) > 1:
                res.viol("ENROLLMENT_FORK",
                         f"{len(kids)} enrollments supersede the same parent",
                         proof=[k[1] for k in kids])
        # tip = an enrollment not superseded by any other
        superseded = {c.get("claim", {}).get("supersedes")
                      for e in idx_by_hash.values()
                      for c, _ in [_core_of(e)]}
        tips = [e for h, e in idx_by_hash.items() if h not in superseded]
        if tips:
            enr = tips[-1]

    declared = None
    if enr is not None:
        core, sig = _core_of(enr)
        if sig and not sl.verify_envelope(enr):
            res.viol("BAD_SIG", "enrollment signature failed (V2.1)")
        declared = {s["stream"]: s
                    for s in core.get("claim", {}).get("streams", [])}
        if stream not in declared:
            res.findings.append({"severity": "ok", "code": "UNDECLARED_STREAM",
                                 "msg": f"'{stream}' not in enrollment; gaps here "
                                 "do not count against the declared surface"})
        else:
            pol = declared[stream]
            stale_checkpoints = pol.get("statement_every_checkpoints",
                                        stale_checkpoints)
            stale_seconds = pol.get("statement_every_seconds", stale_seconds)
            res.note(f"enrollment declares '{stream}' "
                     f"(T = {stale_checkpoints} checkpoints / {stale_seconds}s)")

    # --- signatures (V1.1) ---------------------------------------------------
    unsigned = signed_ok = 0
    for r in records:
        sig = r["view"]["sig"]
        if sig is None:
            unsigned += 1
            continue
        if not sl.verify_envelope({"core": r["view"]["core"], "issuer_sig": sig}):
            res.viol("BAD_SIG", f"seq {r['seq']}: issuer_sig failed (V1.1)")
        else:
            signed_ok += 1
    if unsigned:
        res.findings.append({"severity": "ok", "code": "UNSIGNED",
                             "msg": f"{unsigned} legacy leaves carry no issuer_sig "
                             "(density/chain checkable; dup-seq not self-proving)"})
    if signed_ok:
        res.note(f"{signed_ok} issuer signatures verified (ed25519/did:key)")

    # --- duplicates (V1.4) ---------------------------------------------------
    by_seq = {}
    for r in records:
        by_seq.setdefault(r["seq"], []).append(r)
    for seq, rs in sorted(by_seq.items()):
        if len(rs) > 1:
            hashes = {r["leaf_hash"] for r in rs}
            proof = None
            if len(hashes) > 1 and all(r["view"]["sig"] for r in rs):
                proof = [json.loads(r["raw"]) for r in rs]
            res.viol("DUP_SEQ",
                     f"seq {seq} appears {len(rs)}x "
                     f"({'conflicting bodies' if len(hashes) > 1 else 'identical'})"
                     + (" — self-contained misbehavior proof exported" if proof else ""),
                     proof=proof)

    # --- density (V1.2) ------------------------------------------------------
    seqs = sorted(by_seq)
    lo, hi = seqs[0], seqs[-1]
    res.max_seq = hi
    res.tip_hash = by_seq[hi][0]["leaf_hash"]
    missing = sorted(set(range(lo, hi + 1)) - set(seqs))
    if missing:
        show = ", ".join(map(str, missing[:10])) + \
            (f", ... (+{len(missing) - 10})" if len(missing) > 10 else "")
        res.viol("GAP", f"missing seq: {show} (range {lo}..{hi})")
    else:
        res.note(f"density OK: seq {lo}..{hi} dense, no gaps")
    if lo != 1:
        res.findings.append({"severity": "ok", "code": "START_OFFSET",
                             "msg": f"stream starts at seq {lo}, not 1 "
                             "(prefix before first observed leaf unverifiable)"})

    # --- chaining (V1.3) + order (V1.6) --------------------------------------
    chain_ok = order_ok = True
    order_viols = []
    prev_r = None
    for seq in seqs:
        r = by_seq[seq][0]
        if prev_r is not None:
            if seq == prev_r["seq"] + 1 and r["prev"] is not None:
                if r["prev"] != prev_r["leaf_hash"]:
                    chain_ok = False
                    res.viol("CHAIN_BREAK",
                             f"seq {seq}: prev_claim_hash {r['prev'][:16]}... != "
                             f"sha256(seq {prev_r['seq']} leaf) "
                             f"{prev_r['leaf_hash'][:16]}...")
            if r["idx"] < prev_r["idx"]:
                order_viols.append(
                    f"seq {seq} at log index {r['idx']} before "
                    f"seq {prev_r['seq']} at {prev_r['idx']}")
        prev_r = r
    if chain_ok:
        res.note("prev-hash chain OK (each claim commits sha256 of its predecessor)")
    if order_viols:
        if chain_ok and not missing:
            # Late re-publication, not backdating: with the sequence dense and
            # the prev-hash chain verifying ACROSS the out-of-order boundary,
            # the late-appended entries are exactly the bytes the already-
            # committed later entries pinned. An operator cannot use this path
            # to invent history -- only to restore it. Stays on the record.
            res.findings.append({
                "severity": "ok", "code": "LATE_REPAIR",
                "msg": (f"{len(order_viols)} out-of-order boundary(ies) from "
                        "late re-publication; density and chain verify, so the "
                        "late entries are the ones the pre-existing chain "
                        "committed to (repair, not backdating): "
                        + "; ".join(order_viols))})
        else:
            order_ok = False
            for v in order_viols:
                res.viol("ORDER_VIOLATION", v)
    if order_ok and not order_viols:
        res.note("log order consistent with seq order")

    # --- statements (V3.2 / V3.3 / V3.4) -------------------------------------
    stmts = list(statements) if statements is not None else []
    stmts += onlog_statements
    # keep this stream + accepted issuer, order by checkpoint_size
    stmts = [s for s in stmts
             if _core_of(s)[0].get("claim", {}).get("stream") == stream
             and _core_of(s)[0].get("issuer") in accepted]
    stmts.sort(key=lambda s: _core_of(s)[0]["claim"].get("checkpoint_size", 0))

    latest_stmt = None
    prev_count = prev_cp = -1
    for s in stmts:
        core, sig = _core_of(s)
        c = core["claim"]
        if sig and not sl.verify_envelope(s):
            res.viol("BAD_SIG", "statement signature failed")
            continue
        K, cp = c.get("count"), c.get("checkpoint_size")
        covered = [r for r in records if r["idx"] < cp]
        M = max((r["seq"] for r in covered), default=0)
        if K > M:
            res.viol("COUNT_OVERCLAIM",
                     f"statement@cp{cp} signs count {K} but only seq<= {M} "
                     "on-log in covered prefix — withheld suffix or false count",
                     proof={"statement": s, "observed_max_seq": M})
        elif K < M:
            res.viol("COUNT_UNDERCLAIM",
                     f"statement@cp{cp} signs count {K} but seq {M} is on-log",
                     proof={"statement": s,
                            "onlog_claim": json.loads(by_seq[M][0]["raw"])})
        else:
            tip = by_seq[K][0]["leaf_hash"] if K in by_seq else None
            if c.get("tip_hash") != tip:
                res.viol("TIP_MISMATCH",
                         f"statement@cp{cp} tip_hash != sha256(seq {K} leaf)",
                         proof={"statement": s, "expected_tip": tip})
            else:
                res.note(f"statement@cp{cp}: count {K} and tip consistent")
        if K < prev_count or cp < prev_cp:
            res.viol("STATEMENT_ROLLBACK",
                     f"statement@cp{cp} count {K} rolls back {prev_count}",
                     proof={"statements": [latest_stmt, s]})
        prev_count, prev_cp = K, cp
        latest_stmt = s

    # staleness (V3.4)
    if latest_stmt is not None:
        c = _core_of(latest_stmt)[0]["claim"]
        cp_age = max(0, checkpoint_size - c["checkpoint_size"])
        t_s = datetime.fromisoformat(
            _core_of(latest_stmt)[0]["issuedAt"].replace("Z", "+00:00"))
        wall_age = (now - t_s).total_seconds()
        if cp_age > stale_checkpoints or wall_age > stale_seconds:
            res.viol("STALE",
                     f"stream STALE: latest statement at checkpoint "
                     f"{c['checkpoint_size']} ({cp_age} checkpoints behind "
                     f"{checkpoint_size}; {wall_age / 86400:.1f}d old; "
                     f"T={stale_checkpoints}cp/{stale_seconds / 86400:.0f}d). "
                     "Liveness flag, not misbehavior proof.")
        else:
            res.note(f"freshness OK: latest statement {cp_age} checkpoints old "
                     f"(deadline {stale_checkpoints})")
    elif declared and stream in declared and enr is not None:
        t_e = datetime.fromisoformat(
            _core_of(enr)[0]["issuedAt"].replace("Z", "+00:00"))
        age = (now - t_e).total_seconds()
        if age > stale_seconds:
            res.viol("STALE",
                     f"declared stream has no statement and enrollment is "
                     f"{age / 86400:.1f}d old (deadline {stale_seconds / 86400:.0f}d)")
        else:
            res.findings.append({"severity": "ok", "code": "NO_STATEMENT_YET",
                                 "msg": "declared stream has no statement yet; "
                                 "within deadline"})
    else:
        res.findings.append({"severity": "ok", "code": "NO_STATEMENTS",
                             "msg": "no stream-statements: suffix withholding NOT "
                             "checkable — density/chain verified for published records"})

    # --- receipts (V4.2 / V4.3) ----------------------------------------------
    recs = list(receipts) if receipts is not None else []
    recs += onlog_receipts
    for rec in recs:
        core, sig = _core_of(rec)
        c = core.get("claim", {})
        if c.get("stream") != stream or core.get("issuer") not in accepted:
            continue
        if sig and not sl.verify_envelope(rec):
            res.viol("BAD_SIG", "receipt signature failed")
            continue
        n, cp_by = c.get("seq"), c.get("checkpoint_by")
        deadline = c.get("deadline_at")
        due = checkpoint_size >= cp_by or (
            deadline and now >= datetime.fromisoformat(
                deadline.replace("Z", "+00:00")))
        if not due:
            res.note(f"receipt for seq {n}: not yet due "
                     f"(checkpoint_by {cp_by}, now {checkpoint_size})")
            continue
        included = n in by_seq and by_seq[n][0]["idx"] < cp_by
        if not included:
            res.viol("RECEIPT_NON_INCLUSION",
                     f"receipt promised seq {n} by checkpoint {cp_by}; not on-log "
                     f"in that prefix (max on-log seq {hi})",
                     proof={"receipt": rec, "onlog_max_seq": hi})
        else:
            res.note(f"receipt for seq {n}: included at index "
                     f"{by_seq[n][0]['idx']} (< {cp_by}) OK")
        if latest_stmt is not None:
            sc = _core_of(latest_stmt)[0]["claim"]
            if sc["checkpoint_size"] >= cp_by and sc["count"] < n:
                res.viol("RECEIPT_UNDERCOUNT",
                         f"receipt promised seq {n}; statement at checkpoint "
                         f"{sc['checkpoint_size']} swears count {sc['count']} < {n} "
                         "— self-contained misbehavior proof (two sigs, same key)",
                         proof={"receipt": rec, "statement": latest_stmt})
    return res


# --- CLI ---------------------------------------------------------------------
def _print_human(res: StreamResult):
    print(f"== stream check: issuer={res.issuer}")
    print(f"==               stream={res.stream}")
    for m in res.info:
        print(f"   ok    {m}")
    for f in res.findings:
        if f["severity"] == "ok":
            print(f"   note  [{f['code']}] {f['msg']}")
    for f in res.findings:
        if f["severity"] != "ok":
            print(f"   FAIL  [{f['code']}] {f['msg']}")
    if res.proofs:
        print(f"   {len(res.proofs)} misbehavior proof(s) exportable (--json to emit)")
    print(f"== STATUS: {res.status.upper()}  "
          f"({sum(1 for f in res.findings if f['severity'] != 'ok')} violation(s))")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--issuer", required=True)
    ap.add_argument("--stream", required=True)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--log", help="log base URL (read-only /leaves fetch)")
    src.add_argument("--leaves-file",
                     help="JSON file: list of b64 leaves, or {leaves:[...]}")
    ap.add_argument("--statements", help="JSON file: list of stream-statement/v1")
    ap.add_argument("--receipts", help="JSON file: list of run-receipt/v1")
    ap.add_argument("--enrollment", help="JSON file: stream-enrollment/v1")
    ap.add_argument("--checkpoint-size", type=int,
                    help="current witnessed checkpoint size (default: leaf count)")
    ap.add_argument("--now", help="override wall clock (ISO8601) for staleness")
    ap.add_argument("--stale-checkpoints", type=int, default=DEFAULT_STALE_CHECKPOINTS)
    ap.add_argument("--stale-seconds", type=int, default=DEFAULT_STALE_SECONDS)
    ap.add_argument("--no-rotation", action="store_true")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    try:
        if args.log:
            leaves = fetch_leaves(args.log.rstrip("/"))
        else:
            d = json.load(open(args.leaves_file))
            leaves = d["leaves"] if isinstance(d, dict) else d
    except Exception as e:
        print(f"fetch error: {e}", file=sys.stderr)
        return 2

    def load(path):
        return json.load(open(path)) if path else None

    now = (datetime.fromisoformat(args.now.replace("Z", "+00:00"))
           if args.now else None)
    res = verify_stream(
        leaves, args.issuer, args.stream,
        statements=load(args.statements), receipts=load(args.receipts),
        enrollment=load(args.enrollment), checkpoint_size=args.checkpoint_size,
        now=now, follow_rotation=not args.no_rotation,
        stale_checkpoints=args.stale_checkpoints, stale_seconds=args.stale_seconds)

    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
    else:
        _print_human(res)
    return 0 if res.status == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
