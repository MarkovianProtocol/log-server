#!/usr/bin/env python3
"""Verify an ML-DSA-44 cosignature line on a checkpoint against a published vkey.

The key id is recomputed from the key material, so a key that doesn't belong to
the line fails there instead of silently passing. Every verified line is also
re-run with one flipped signature bit, which must fail.

usage: verify_pq_line.py <checkpoint-file> <vkey-string>
vkey format: <name>+<keyid-hex>+<base64(0x06 || 1312-byte pk)>

Needs dilithium_py (pip install dilithium-py). Ed25519 cosignatures and the
quorum are checked by verify_tlog_proof.py; this covers the post-quantum lines,
which are additive and are not required for quorum.
"""
import base64, hashlib, struct, sys
from dilithium_py.ml_dsa import ML_DSA_44


def lp(b):
    assert 1 <= len(b) <= 255
    return bytes([len(b)]) + b


def cosigned_message(cosigner_name, origin, size, root, ts):
    return (b"subtree/v1\n\x00"
            + lp(cosigner_name.encode())
            + struct.pack(">Q", ts)
            + lp(origin.encode())
            + struct.pack(">Q", 0)
            + struct.pack(">Q", size)
            + root)


def main():
    note = open(sys.argv[1]).read()
    vkey = sys.argv[2].strip()
    # split on the LAST two '+' would break base64; key name may contain no '+',
    # so split on the first two only.
    name, keyid_hex, keymat_b64 = vkey.split("+", 2)
    keymat = base64.b64decode(keymat_b64)
    assert keymat[0] == 0x06, f"not a ML-DSA-44 vkey (alg byte {keymat[0]:#x})"
    pk = keymat[1:]
    assert len(pk) == 1312, f"pk len {len(pk)}"
    computed_id = hashlib.sha256(name.encode() + b"\n" + b"\x06" + pk).digest()[:4]
    print(f"vkey name       : {name}")
    print(f"keyid declared  : {keyid_hex}")
    print(f"keyid recomputed: {computed_id.hex()}  {'MATCH' if computed_id.hex() == keyid_hex else 'MISMATCH'}")

    lines = note.split("\n")
    origin, size, root = lines[0], int(lines[1]), base64.b64decode(lines[2])
    print(f"checkpoint      : {origin} size={size}")

    found = 0
    for ln in lines:
        if not ln.startswith("— "):
            continue
        _, ln_name, payload_b64 = ln.split(" ", 2)
        raw = base64.b64decode(payload_b64)
        if raw[:4] != computed_id:
            continue
        found += 1
        print(f"line            : name={ln_name} payload={len(raw)} bytes")
        if ln_name != name:
            print("  !! line name differs from vkey name")
        ts = struct.unpack(">Q", raw[4:12])[0]
        sig = raw[12:]
        msg = cosigned_message(name, origin, size, root, ts)
        ok = ML_DSA_44.verify(pk, msg, sig, b"")
        print(f"  timestamp     : {ts}")
        print(f"  ML-DSA-44     : {'VERIFIED' if ok else 'FAILED'}")
        # negative control
        bad = bytearray(sig); bad[0] ^= 0x01
        print(f"  tamper control: {'FAILED (good)' if not ML_DSA_44.verify(pk, msg, bytes(bad), b'') else 'VERIFIED (BAD!)'}")
    if not found:
        print("no line on this checkpoint carries that key id")


main()
