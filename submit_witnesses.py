#!/usr/bin/env python3
"""Submit ONE pinned checkpoint to every configured witness, collect cosignatures,
and publish the witnessed checkpoint.

WHY THIS IS THE LOAD-BEARING PIECE. Bitcoin gives the log a TIME nobody controls.
It does not stop us rebuilding the tree and signing a different history: we hold
the log key. Only an INDEPENDENT witness, which refuses a checkpoint inconsistent
with what it already cosigned, turns "append-only" from our promise into a fact a
stranger can check.

TWO THINGS THIS FIXES (2026-07-14):

1. PIN THE CHECKPOINT. The old version shelled out to `log_server.py --submit` once
   per witness, and each call re-derived `size` from the live tree. A leaf landing
   mid-run meant different witnesses cosigned DIFFERENT checkpoints, and no single
   witnessed note could ever be assembled. We now compute the checkpoint ONCE and
   submit those exact bytes to everybody.

2. PUBLISH IT. Cosignatures written to a directory nobody can fetch prove nothing.
   We write `witnessed.checkpoint` -- the pinned note plus every independent
   cosignature line -- and log_server serves it at GET /checkpoint. That is what
   makes the guarantee checkable by a stranger with stock tooling.

Our own witness cosigning our own log is theatre. It is submitted (to exercise the
path) but DELIBERATELY EXCLUDED from the published note: `independent: false`.

VERIFY BEFORE PUBLISH (2026-07-16): the old version published whatever bytes a
witness returned, trusting the response blind. Now every returned cosignature is
CHECKED against a pinned Ed25519 verifier key (witness_keys.json) before it goes
into the published note: the keyId must match the pinned key and the C2SP
cosignature/v1 signature must verify over the exact checkpoint body. A cosignature
whose key we have not pinned, or whose signature does not verify, is DROPPED and
loudly flagged -- never published. A witness's longer post-quantum cosignature
line rides along only if that same witness's Ed25519 line verified in the same
response (authenticated-by-association; we do not have a PQ verifier here).
"""
import json
import pathlib
import sys
import base64
import urllib.request
import urllib.error

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import log_server as L
from proofbundle import merkle

HERE       = pathlib.Path(__file__).resolve().parent
WITNESSES  = HERE / "witnesses.json"
KEYS_FILE  = HERE / "witness_keys.json"
COSIGS     = HERE / "cosignatures"
WITNESSED  = HERE / "witnessed.checkpoint"


def load_pinned():
    """cosig-line-name -> (keyid_hex, 32-byte Ed25519 pubkey), from the pinned vkeys."""
    pinned = {}
    if not KEYS_FILE.exists():
        return pinned
    for entry in json.loads(KEYS_FILE.read_text()).get("keys", []):
        v = entry["vkey"]
        name, rest = v.split("+", 1)          # names carry no '+'; base64 keys may
        keyid, kb64 = rest[:8], rest[9:]
        raw = base64.b64decode(kb64)
        if raw[0] != 0x04:                     # 0x04 = Ed25519 cosignature key
            continue
        pinned[name] = (keyid, raw[1:])
    return pinned


def _cosig_body(checkpoint):
    """The bytes a witness cosigns: origin/size/root, each newline-terminated."""
    lines = checkpoint.split("\n")
    return ("\n".join(lines[:3]) + "\n").encode()


def verify_cosig_lines(lines, body, pinned):
    """Return (accepted_lines, note). Publish ONLY cosignatures we can verify:
    a pinned Ed25519 key whose keyId matches and whose signature checks out. A PQ
    (non-76-byte) line rides along only if that same witness's Ed25519 verified.
    Everything else is dropped, with a reason in the note."""
    accepted, authed, notes = [], set(), []
    # pass 1 -- Ed25519 cosignature/v1 lines (4 keyid + 8 time + 64 sig = 76 bytes)
    for ln in lines:
        parts = ln.split(" ", 2)
        if len(parts) < 3:
            continue
        _, wname, b64 = parts
        try:
            raw = base64.b64decode(b64)
        except Exception:
            notes.append("undecodable line DROPPED"); continue
        if len(raw) != 76:
            continue                           # handled in pass 2
        kid = raw[:4].hex()
        pk = pinned.get(wname)
        if not pk:
            notes.append(f"{wname}: UNPINNED ed25519 key DROPPED (pin it in witness_keys.json)")
            continue
        if pk[0] != kid:
            notes.append(f"{wname}: keyId {kid} != pinned {pk[0]} DROPPED")
            continue
        ts = int.from_bytes(raw[4:12], "big")
        msg = b"cosignature/v1\ntime " + str(ts).encode() + b"\n" + body
        try:
            Ed25519PublicKey.from_public_bytes(pk[1]).verify(raw[12:], msg)
            accepted.append(ln); authed.add(wname); notes.append(f"{wname}: ed25519 OK")
        except Exception:
            notes.append(f"{wname}: ED25519 SIGNATURE FAILED -- DROPPED (forgery or key rotation)")
    # pass 2 -- non-Ed25519 (post-quantum) lines ride along only for authenticated witnesses
    for ln in lines:
        parts = ln.split(" ", 2)
        if len(parts) < 3:
            continue
        _, wname, b64 = parts
        try:
            raw = base64.b64decode(b64)
        except Exception:
            continue
        if len(raw) == 76:
            continue
        if wname in authed:
            accepted.append(ln); notes.append(f"{wname}: pq line ride-along (ed25519-authenticated)")
        else:
            notes.append(f"{wname}: pq line DROPPED (witness not ed25519-authenticated)")
    return accepted, "; ".join(notes)



# Cloudflare's managed bot rule answers 403 "error code: 1010" to urllib's
# default User-Agent, before the request reaches the witness. Identify the log.
UA_SUBMIT = "markovian-log/1.0 (+https://markovianprotocol.com/log; c2sp tlog-witness submit)"


def submit_pinned(url, leaves, size, checkpoint, timeout=20):
    """Submit the EXACT pinned checkpoint. Returns (status, body)."""
    def _post(old):
        proof = merkle.consistency_proof(leaves, old) if 0 < old < size else []
        header = f"old {old}\n" + "".join(base64.b64encode(p).decode() + "\n" for p in proof) + "\n"
        req = urllib.request.Request(url, data=(header + checkpoint).encode(),
                                     method="POST", headers={"Content-Type": "text/plain", "User-Agent": UA_SUBMIT})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()
        except Exception as e:                      # network/TLS/timeout
            return 0, str(e)

    status, resp = _post(0)                         # optimistic first-use
    if status == 409:                               # witness knows us; retry at its stored size
        try:
            old = int(resp.strip())
        except ValueError:
            return status, resp
        status, resp = _post(old)
    return status, resp


def main():
    COSIGS.mkdir(exist_ok=True)
    if not WITNESSES.exists():
        print("no witnesses.json")
        return 1

    conn   = L.init_db()
    signer = L.load_signer()
    pinned = load_pinned()
    print(f"pinned verifier keys: {len(pinned)}")

    # ---- PIN ONCE. Every witness sees these exact bytes. ----
    leaves     = L.all_leaves(conn)
    size       = len(leaves)
    checkpoint = L.signed_checkpoint(conn, signer, L.ORIGIN, size)
    body       = _cosig_body(checkpoint)
    print(f"pinned checkpoint: {L.ORIGIN} @ size {size}\n")

    cosig_lines, independent = [], 0
    for w in json.loads(WITNESSES.read_text()):
        if not w.get("enabled", True) or not w.get("add_checkpoint"):
            continue
        name, url = w["name"], w["add_checkpoint"]
        status, resp = submit_pinned(url, leaves, size, checkpoint)

        if status == 200:
            lines = [ln for ln in resp.splitlines() if ln.startswith("—")]
            (COSIGS / f"{name.replace('/', '_')}.cosig").write_text(resp)
            if w.get("independent"):
                good, note = verify_cosig_lines(lines, body, pinned)
                if good:
                    cosig_lines.extend(good)
                    independent += 1
                    print(f"  {name:<42} VERIFIED   [{len(good)} line(s) published] {note}")
                else:
                    print(f"  {name:<42} REJECTED   [nothing published] {note}")
            else:
                print(f"  {name:<42} cosigned   [SELF (no weight) -- not published]")
        else:
            print(f"  {name:<42} FAILED {status}: {resp.strip()[:70]}")

    print(f"\nINDEPENDENT verified witnesses: {independent}")

    if independent:
        # PQ dual-signing (roadmap step 2): append our own ML-DSA-44 timestamped
        # cosignature (c2sp tlog-cosignature type 0x06) over the pinned note, so the
        # published checkpoint is authenticated by Ed25519 AND ML-DSA-44. Guarded:
        # a missing lib/seed skips the line and publishes exactly as before.
        pq_line = None
        try:
            import pq_selfsign
            pq_line = pq_selfsign.sign_line(checkpoint)
            print("  ML-DSA-44 self-cosignature appended (PQ dual-signing)")
        except Exception as e:
            print(f"  ML-DSA-44 self-cosignature SKIPPED: {e!r}")
        # Publish atomically: the pinned note + every VERIFIED cosignature line.
        all_lines = cosig_lines + ([pq_line] if pq_line else [])
        tmp = WITNESSED.with_suffix(".tmp")
        tmp.write_text(checkpoint + "".join(ln + "\n" for ln in all_lines))
        tmp.replace(WITNESSED)
        print(f"published {WITNESSED.name}: size {size}, {len(cosig_lines)} verified witness line(s)"
              + (" + 1 self PQ line" if pq_line else ""))
        print("  -> now served at GET /checkpoint")
    else:
        print("  WARNING: no cosignature verified. Non-equivocation is NOT established, and")
        print("  witnessed.checkpoint was NOT updated (the last good one still serves).")
        print("  Check witness_keys.json is current if witnesses are cosigning but not verifying.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
