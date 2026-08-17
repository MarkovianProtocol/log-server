# Interop

## SCITT COSE Receipts, cross-checked against action-state-group/scitt-cose

The log serves a COSE_Sign1 receipt for any leaf at `GET /receipt/scitt/<i>`
(`log_server.py`, using the same signer object it signs checkpoints with —
no separate key). Protected header `{395: 1, 1: -8}` (395 = verifiable-data-
structure, value 1 = RFC9162_SHA256; 1 = alg, -8 = EdDSA), unprotected header
`{396: {-1: [incl]}}` (396 = verifiable-data-proofs, -1 = inclusion-proof
array), payload detached (the Merkle root), signature over `["Signature1",
protected_bstr, b"", root]`. That shape is drawn from RFC 9942 and pinned to
match one specific peer implementation:
[`action-state-group/scitt-cose`](https://github.com/action-state-group/scitt-cose).

Until 2026-08-17 that match was asserted in a docstring and never run. It's
now checked against the live endpoint, using nothing but the publicly
published signing key — no server access, no cooperation from us needed:

```
$ curl -o receipt.cose https://log.markovianprotocol.com/receipt/scitt/7271
$ curl -o leaf.bin https://log.markovianprotocol.com/leaf/7271

$ python3 -c "
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from scitt_cose import verify_receipt

# the log's vkey, as published at https://log.markovianprotocol.com/policy
vkey = 'markovianprotocol.com/log+0302c6c8+ATkpOWo95UuEiW2EhNZAol4f0CS8hMluJfPcTSzrr03v'
raw = base64.b64decode(vkey.split('+', 2)[2])[1:]   # drop the leading alg byte
pub_pem = Ed25519PublicKey.from_public_bytes(raw).public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

receipt = open('receipt.cose', 'rb').read()
leaf = open('leaf.bin', 'rb').read()
res = verify_receipt(receipt, leaf_entry_hex=leaf.hex(), log_public_key_pem=pub_pem)
print(res.ok, res.root, res.tree_size, res.leaf_index)
"
True 9197250336b47f9138241010cfd9195b19ecf3dab39c0dcc89b3b13b05b07162 7395 7271
```

`res.root` matches the checkpoint root at size 7395 exactly. That's the log's
real, publicly pinned key — the same one that signs every checkpoint — not a
throwaway. A single flipped byte in the receipt makes `verify_receipt` return
`ok=False`; nothing here trusts our server, our tooling, or our word — the
key comes from `/policy`, the receipt and leaf come from public GET
endpoints, and `scitt-cose` is code neither of us wrote with the other in
mind.

`scitt_receipt.py` (this repo) is the offline generator behind the endpoint,
and also useful standalone: `python3 scitt_receipt.py <index>` builds the
same receipt against a throwaway key for checking the wire format without
touching any real key; `--real-key` signs with the actual log seed the way
`log_server.py` does internally.

## Why this is here

A receipt format checked only by the code that emits it has the same
single-signer blind spot the log itself has, one layer down — see
`get-witnessed.html`. An independent implementation reading the bytes and
agreeing is the check; the RFC citation alone is not.
