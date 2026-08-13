#!/usr/bin/env python3
"""Offline verifier for c2sp.org/tlog-proof bundles against a c2sp.org/tlog-policy file.

    verify_tlog_proof.py <proof-file> <leaf-file> <policy-file>

No network. Verifies, in order:
  1. the checkpoint's log signature against the policy's log vkey (keyid checked);
  2. witness cosignatures (cosignature/v1) against the policy's pinned witness
     vkeys, counting only cryptographically valid ones toward the quorum;
  3. the RFC 6962 inclusion proof binding SHA-256(0x00 || leaf bytes) to the
     checkpoint's root at the checkpoint's size.

Policy support: flat `witness` lines, one `group <name> <k> <members...>` of
witnesses, `quorum <group>` (the shape markovianprotocol.com/log publishes).
Exit 0 = all checks pass; nonzero with a message otherwise.
"""
import base64, hashlib, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def die(msg):
    print("FAIL:", msg)
    sys.exit(1)


def parse_vkey(vkey):
    # split from the LEFT: names never contain '+', but base64 does
    name, keyid_hex, b64 = vkey.split("+", 2)
    blob = base64.b64decode(b64)
    keytype, pub = blob[0], blob[1:]
    want = hashlib.sha256(name.encode() + b"\n" + blob).digest()[:4]
    if want.hex() != keyid_hex:
        die(f"vkey keyid mismatch for {name}: computed {want.hex()}, vkey says {keyid_hex}")
    return name, bytes.fromhex(keyid_hex), keytype, pub


def parse_policy(path):
    log_vkeys, witnesses, group = [], {}, None
    quorum_name = None
    for raw in open(path):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts[0] == "log":
            log_vkeys.append(parse_vkey(parts[1]))
        elif parts[0] == "witness":
            witnesses[parts[1]] = parse_vkey(parts[2])
        elif parts[0] == "group":
            gname, k, members = parts[1], parts[2], parts[3:]
            k = len(members) if k == "all" else (1 if k == "any" else int(k))
            unknown = [m for m in members if m not in witnesses]
            if unknown:
                die(f"group {gname} references undefined members {unknown} (only witness members supported)")
            group = (gname, k, members)
        elif parts[0] == "quorum":
            quorum_name = parts[1]
    if not log_vkeys:
        die("policy has no log line")
    if quorum_name == "none":
        return log_vkeys, witnesses, (None, 0, [])
    if group is None or quorum_name != group[0]:
        die("quorum must name the single defined group in this verifier")
    return log_vkeys, witnesses, group


def parse_proof(path):
    text = open(path).read()
    lines = text.split("\n")
    if lines[0] != "c2sp.org/tlog-proof@v1":
        die("not a c2sp.org/tlog-proof@v1 file")
    i = 1
    extra = None
    if lines[i].startswith("extra "):
        extra = base64.b64decode(lines[i][len("extra "):])
        i += 1
    if not lines[i].startswith("index "):
        die("missing index line")
    index = int(lines[i][len("index "):])
    i += 1
    proof = []
    while i < len(lines) and lines[i] != "":
        proof.append(base64.b64decode(lines[i]))
        i += 1
    if i >= len(lines):
        die("missing blank line before checkpoint")
    note = "\n".join(lines[i + 1:])
    return extra, index, proof, note


def split_note(note):
    body, _, sigblock = note.partition("\n\n")
    body += "\n"
    sigs = []
    for line in sigblock.splitlines():
        if not line.startswith("— "):
            continue
        _, name, b64 = line.split(" ", 2)
        sigs.append((name, base64.b64decode(b64)))
    return body, sigs


def rfc6962_root(leaf_hash, index, size, path):
    if not (0 <= index < size):
        die("index outside tree")
    fn, sn, r = index, size - 1, leaf_hash
    H = lambda l, rt: hashlib.sha256(b"\x01" + l + rt).digest()
    for v in path:
        if sn == 0:
            die("inclusion path longer than tree height")
        if fn & 1 or fn == sn:
            r = H(v, r)
            if not (fn & 1):
                while True:
                    fn >>= 1
                    sn >>= 1
                    if fn & 1 or fn == 0:
                        break
        else:
            r = H(r, v)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        die("inclusion path shorter than tree height")
    return r


def main():
    if len(sys.argv) != 4:
        die("usage: verify_tlog_proof.py <proof> <leaf-file> <policy>")
    proof_path, leaf_path, policy_path = sys.argv[1:4]
    log_vkeys, witnesses, (gname, k, members) = parse_policy(policy_path)
    extra, index, path, note = parse_proof(proof_path)
    body, sigs = split_note(note)

    origin, size_s, root_b64 = body.splitlines()[:3]
    size = int(size_s)
    root = base64.b64decode(root_b64)

    # 1. log signature
    log_ok = False
    for name, keyid, keytype, pub in log_vkeys:
        if name != origin or keytype != 0x01:
            continue
        for sname, blob in sigs:
            if sname == name and blob[:4] == keyid:
                try:
                    Ed25519PublicKey.from_public_bytes(pub).verify(blob[4:], body.encode())
                    log_ok = True
                except InvalidSignature:
                    die("log signature INVALID")
    if not log_ok:
        die(f"no log signature from policy key for origin {origin}")
    print(f"ok: log signature verified ({origin})")

    # 2. witness cosignatures (cosignature/v1: blob = keyid4 + ts8(BE) + sig64)
    valid = set()
    by_keyid = {v[1]: (wname, v) for wname, v in witnesses.items()}
    for sname, blob in sigs:
        if len(blob) != 76 or blob[:4] not in by_keyid:
            continue
        wname, (name, keyid, keytype, pub) = by_keyid[blob[:4]]
        if sname != name or keytype != 0x04:
            continue
        ts = struct.unpack(">Q", blob[4:12])[0]
        msg = f"cosignature/v1\ntime {ts}\n".encode() + body.encode()
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(blob[12:], msg)
            valid.add(wname)
            print(f"ok: cosignature verified ({name})")
        except InvalidSignature:
            die(f"cosignature from pinned witness {name} INVALID (possible forgery)")
    in_quorum = [m for m in members if m in valid]
    if len(in_quorum) < k:
        die(f"quorum not met: {len(in_quorum)}/{k} required from group {gname}")
    print(f"ok: quorum met ({len(in_quorum)} of {len(members)} witnesses, threshold {k})")

    # 3. inclusion
    leaf = open(leaf_path, "rb").read()
    leaf_hash = hashlib.sha256(b"\x00" + leaf).digest()
    computed = rfc6962_root(leaf_hash, index, size, path)
    if computed != root:
        die("inclusion proof does NOT bind leaf to checkpoint root")
    print(f"ok: leaf {index} included under root {root_b64} at size {size}")
    print("PASS: proof verifies offline against the policy")


if __name__ == "__main__":
    main()
