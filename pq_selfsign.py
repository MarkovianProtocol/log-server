#!/usr/bin/env python3
"""ML-DSA-44 self-cosignature for the Markovian log checkpoint (PQ roadmap step 2).

Emits a c2sp.org/tlog-cosignature line (signature type 0x06, timestamped
subtree cosignature per FIPS 204 pure ML-DSA, empty context) under the log
operator's own PQ key, so the published checkpoint is authenticated by both
Ed25519 (log signature) and ML-DSA-44 going forward.

Key ID  = SHA-256(name || "\n" || 0x06 || 1312-byte public key)[:4]
Line    = "— <name> base64(keyid(4) || timestamp(8 BE) || sig(2420))"
Message = "subtree/v1\n\0" || lp(name) || ts(8 BE) || lp(origin)
          || start=0 (8 BE) || end=tree_size (8 BE) || root(32)

The seed lives at ~/.secrets/log_mldsa44.seed (32 bytes, 0600); keys are
derived deterministically with ML_DSA_44.key_derive. The secret key is never
printed. Verifiers that do not pin this key ignore the line (per signed-note).
"""
import base64
import hashlib
import os
import struct
import sys
import time

from dilithium_py.ml_dsa import ML_DSA_44

SEED_PATH = os.path.expanduser(os.environ.get("LOG_MLDSA_SEED", "~/.secrets/log_mldsa44.seed"))
NAME = "markovianprotocol.com/log"


def load_keys():
    if not os.path.exists(SEED_PATH):
        raise SystemExit(f"no seed at {SEED_PATH} -- run with 'init' first")
    seed = open(SEED_PATH, "rb").read()
    assert len(seed) == 32, "seed must be 32 bytes"
    pk, sk = ML_DSA_44.key_derive(seed)
    assert len(pk) == 1312
    return pk, sk


def key_id(pk):
    return hashlib.sha256(NAME.encode() + b"\n" + b"\x06" + pk).digest()[:4]


def vkey(pk):
    keymat = base64.b64encode(b"\x06" + pk).decode()
    return f"{NAME}+{key_id(pk).hex()}+{keymat}"


def _lp(b):
    assert 1 <= len(b) <= 255
    return bytes([len(b)]) + b


def parse_note_body(note_text):
    """origin, size, root from the first three lines of a checkpoint note."""
    lines = note_text.split("\n")
    origin, size, root = lines[0], int(lines[1]), base64.b64decode(lines[2])
    assert len(root) == 32
    body = "\n".join(lines[:3]) + "\n"
    return origin, size, root, body


def cosigned_message(origin, size, root, ts):
    return (b"subtree/v1\n\x00"
            + _lp(NAME.encode())
            + struct.pack(">Q", ts)
            + _lp(origin.encode())
            + struct.pack(">Q", 0)
            + struct.pack(">Q", size)
            + root)


def sign_line(note_text, ts=None):
    pk, sk = load_keys()
    origin, size, root, _ = parse_note_body(note_text)
    ts = int(time.time()) if ts is None else ts
    sig = ML_DSA_44.sign(sk, cosigned_message(origin, size, root, ts), b"")
    assert len(sig) == 2420
    payload = key_id(pk) + struct.pack(">Q", ts) + sig
    line = f"— {NAME} {base64.b64encode(payload).decode()}"
    ok, why = verify_line(note_text, line, pk)
    if not ok:
        raise SystemExit(f"self-check failed after signing: {why}")
    return line


def verify_line(note_text, line, pk=None):
    if pk is None:
        pk, _ = load_keys()
    origin, size, root, _ = parse_note_body(note_text)
    parts = line.split(" ")
    if len(parts) != 3 or parts[0] != "—" or parts[1] != NAME:
        return False, "not our line"
    raw = base64.b64decode(parts[2])
    if len(raw) != 4 + 8 + 2420:
        return False, f"payload length {len(raw)}"
    if raw[:4] != key_id(pk):
        return False, "key id mismatch"
    ts = struct.unpack(">Q", raw[4:12])[0]
    sig = raw[12:]
    if not ML_DSA_44.verify(pk, cosigned_message(origin, size, root, ts), sig, b""):
        return False, "ML-DSA-44 signature invalid"
    return True, f"ok (time {ts})"


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "init":
        if os.path.exists(SEED_PATH):
            raise SystemExit(f"{SEED_PATH} already exists -- refusing to overwrite")
        seed = os.urandom(32)
        fd = os.open(SEED_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, seed)
        os.close(fd)
        pk, _ = load_keys()
        print("seed written to", SEED_PATH)
        print("vkey:", vkey(pk))
    elif cmd == "vkey":
        pk, _ = load_keys()
        print(vkey(pk))
    elif cmd == "sign":
        note = open(sys.argv[2]).read() if len(sys.argv) > 2 else sys.stdin.read()
        print(sign_line(note))
    elif cmd == "verify":
        note = open(sys.argv[2]).read()
        line = open(sys.argv[3]).read().strip()
        ok, why = verify_line(note, line)
        print("PASS" if ok else "FAIL", "--", why)
        sys.exit(0 if ok else 1)
    else:
        raise SystemExit("usage: pq_selfsign.py init|vkey|sign [note]|verify <note> <linefile>")


if __name__ == "__main__":
    main()
