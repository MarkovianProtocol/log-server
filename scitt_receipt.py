#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Emit a SCITT COSE Receipt (RFC 9942) for one leaf of our transparency log.

Given a leaf index, this fetches the leaf bytes, the RFC 6962 inclusion proof,
and the signed checkpoint from our public, read-only log endpoints, then projects
them into a COSE_Sign1 receipt in the exact shape defined by RFC 9942 ("COSE
Receipts") for verifiable-data-structure value 1 = RFC9162_SHA256, matching the
peer implementation github.com/action-state-group/scitt-cose.

Structure emitted (CBOR tag 18 = COSE_Sign1):
    protected  : { 395: 1, 1: -8 }        # 395=vds -> RFC9162_SHA256 ; 1=alg -> EdDSA
    unprotected: { 396: { -1: [ incl ] } }  # 396=vdp ; -1=inclusion-proofs
    payload    : nil                       # detached; the payload is the Merkle root
    signature  : Ed25519 over Sig_structure ["Signature1", protected_bstr, b"", root]
  where  incl = cbor([ tree_size, leaf_index, [ audit_path_node_bstr, ... ] ])
  and the map key order {395,1} is insertion order, byte-identical to the peer.

RFC citations are in INTEROP.md.

KEYS -----------------------------------------------------------------------
Default: a THROWAWAY Ed25519 key generated fresh each run (written next to the
receipt as receipt.pubkey.pem). Self-consistent and round-trippable, but not
attributable to the log -- use this to check the wire format, not to hand
someone a receipt they should trust.

--real-key: signs with the SAME Ed25519 key the log already uses to sign
checkpoints, loaded from the same seed path log_server.py reads (env LOG_SEED,
default ~/.secrets/log_ed25519.seed; base64, 32 bytes -- see log_server.py's
load_signer()). No new key, no new trust root: the receipt re-expresses the
checkpoint's existing signature domain in COSE. The private seed is never
printed or written anywhere by this tool, only loaded into memory to sign;
only the derived public key is ever written to disk.
------------------------------------------------------------------------------
"""
from __future__ import annotations

import argparse
import base64
import os
import pathlib
import sys
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import cbor_min
import rfc6962

DEFAULT_LOG = "https://log.markovianprotocol.com"
DEFAULT_SEED_PATH = os.path.expanduser(os.environ.get("LOG_SEED", "~/.secrets/log_ed25519.seed"))

# COSE / SCITT labels and code points (RFC 9052, RFC 9053, RFC 9942).
HDR_ALG = 1            # RFC 9052 3.1
HDR_VDS = 395          # RFC 9942: verifiable-data-structure
HDR_VDP = 396          # RFC 9942: verifiable-data-proofs
VDS_RFC9162_SHA256 = 1  # RFC 9942 registry: CT/RFC-6962-style SHA-256 Merkle tree
VDP_INCLUSION = -1     # RFC 9942: inclusion-proofs array within the vdp map
ALG_EDDSA = -8         # RFC 9053
COSE_SIGN1_TAG = 18    # RFC 9052 2


def load_real_log_key(seed_path: str = DEFAULT_SEED_PATH) -> Ed25519PrivateKey:
    """Load the log's real Ed25519 signing key -- same seed, same decoding as
    log_server.py's load_signer(). The seed never leaves this process."""
    seed = base64.b64decode(pathlib.Path(seed_path).read_text().strip())
    if len(seed) != 32:
        raise SystemExit(f"log seed must decode to 32 bytes, got {len(seed)}")
    return Ed25519PrivateKey.from_private_bytes(seed)


def _get(url: str, timeout: int = 20) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


def fetch_leaf(log: str, index: int) -> bytes:
    """Raw RFC 8785 JCS JSON bytes of leaf `index` (the RFC 6962 leaf entry)."""
    return _get(f"{log}/leaf/{index}")


def fetch_checkpoint(log: str) -> tuple[int, bytes, str]:
    """Return (tree_size, root_bytes, raw_checkpoint_text) from the signed checkpoint."""
    text = _get(f"{log}/checkpoint").decode()
    lines = text.split("\n")
    tree_size = int(lines[1])
    root = base64.b64decode(lines[2])
    return tree_size, root, text


def fetch_inclusion(log: str, index: int, size: int) -> list[bytes]:
    """Bottom-up RFC 6962 audit path: list of 32-byte node hashes."""
    text = _get(f"{log}/inclusion?leaf={index}&size={size}").decode()
    return [base64.b64decode(line) for line in text.split() if line.strip()]


def build_sig_structure(protected_bstr: bytes, payload: bytes) -> bytes:
    """RFC 9052 4.4 Sig_structure for COSE_Sign1, external_aad = b""."""
    return cbor_min.dumps(["Signature1", protected_bstr, b"", payload])


def build_receipt(leaf_entry: bytes, leaf_index: int, tree_size: int,
                  audit_path: list[bytes], signing_key: Ed25519PrivateKey,
                  detached: bool = True) -> tuple[bytes, bytes]:
    """Build a COSE_Sign1 SCITT receipt. Returns (receipt_bytes, root_bytes)."""
    # Reconstruct the root from the leaf + proof — this is what we sign, and it
    # proves the proof is internally valid before we ever emit it.
    root = rfc6962.root_from_inclusion(leaf_entry, leaf_index, tree_size, audit_path)

    # inclusion proof = cbor([tree_size, leaf_index, [path nodes]])
    inclusion = cbor_min.dumps([tree_size, leaf_index, list(audit_path)])

    # protected header: {395: vds, 1: alg}  -- insertion order matches the peer
    protected = {HDR_VDS: VDS_RFC9162_SHA256, HDR_ALG: ALG_EDDSA}
    protected_bstr = cbor_min.dumps(protected)

    unprotected = {HDR_VDP: {VDP_INCLUSION: [inclusion]}}

    signature = signing_key.sign(build_sig_structure(protected_bstr, root))

    payload_slot = None if detached else root
    receipt = cbor_min.dumps(
        cbor_min.Tag(COSE_SIGN1_TAG, [protected_bstr, unprotected, payload_slot, signature])
    )
    return receipt, root


def main() -> int:
    ap = argparse.ArgumentParser(description="Emit a SCITT COSE receipt for one log leaf.")
    ap.add_argument("index", type=int, help="0-based leaf index")
    ap.add_argument("--log", default=DEFAULT_LOG, help="log base URL")
    ap.add_argument("--size", type=int, default=None,
                    help="tree size to prove against (default: current checkpoint size)")
    ap.add_argument("--out", default="receipt.cose", help="output receipt path")
    ap.add_argument("--attached", action="store_true",
                    help="embed the root as the payload instead of detaching it")
    ap.add_argument("--real-key", action="store_true",
                    help="sign with the log's real Ed25519 key (env LOG_SEED or "
                         "~/.secrets/log_ed25519.seed) instead of a throwaway one")
    ap.add_argument("--seed-path", default=DEFAULT_SEED_PATH,
                    help="path to the real log seed, if --real-key is set")
    args = ap.parse_args()

    tree_size, cp_root, cp_text = fetch_checkpoint(args.log)
    size = args.size or tree_size
    leaf = fetch_leaf(args.log, args.index)
    path = fetch_inclusion(args.log, args.index, size)

    if args.real_key:
        key = load_real_log_key(args.seed_path)
        key_label = "REAL log key"
    else:
        key = Ed25519PrivateKey.generate()
        key_label = "THROWAWAY (NOT the log key)"
    receipt, root = build_receipt(leaf, args.index, size, path, key, detached=not args.attached)

    with open(args.out, "wb") as f:
        f.write(receipt)
    with open(args.out.replace(".cose", "") + ".leaf.bin", "wb") as f:
        f.write(leaf)
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(args.out.replace(".cose", "") + ".pubkey.pem", "wb") as f:
        f.write(pub_pem)

    print(f"log            : {args.log}")
    print(f"leaf_index     : {args.index}")
    print(f"tree_size      : {size}")
    print(f"leaf bytes     : {len(leaf)}  ({leaf[:60].decode('utf-8', 'replace')}...)")
    print(f"audit path len : {len(path)} nodes")
    print(f"merkle root    : {root.hex()}")
    if size == tree_size:
        print(f"checkpoint root: {cp_root.hex()}  MATCH={root == cp_root}")
    print(f"receipt bytes  : {len(receipt)} -> {args.out}")
    print(f"signing key    : {key_label}")
    print(f"pubkey written : {args.out.replace('.cose','')}.pubkey.pem")
    return 0


if __name__ == "__main__":
    sys.exit(main())
