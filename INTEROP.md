# Interop

## SCITT COSE Receipts, cross-checked against action-state-group/scitt-cose

`scitt_receipt.py` projects one log leaf into a COSE_Sign1 receipt: protected
header `{395: 1, 1: -8}` (395 = verifiable-data-structure, value 1 =
RFC9162_SHA256; 1 = alg, -8 = EdDSA), unprotected header `{396: {-1: [incl]}}`
(396 = verifiable-data-proofs, -1 = inclusion-proof array), payload detached
(the Merkle root), signature over `["Signature1", protected_bstr, b"", root]`.
That shape is drawn from RFC 9942 and pinned to match one specific peer
implementation: [`action-state-group/scitt-cose`](https://github.com/action-state-group/scitt-cose).

Until 2026-08-17 that match was asserted in the docstring and never run. It's
now checked:

```
$ python3 scitt_receipt.py 7271 --out receipt7271.cose
log            : https://log.markovianprotocol.com
leaf_index     : 7271
tree_size      : 7395
merkle root    : 9197250336b47f9138241010cfd9195b19ecf3dab39c0dcc89b3b13b05b07162
checkpoint root: 9197250336b47f9138241010cfd9195b19ecf3dab39c0dcc89b3b13b05b07162  MATCH=True
receipt bytes  : 469 -> receipt7271.cose

$ python3 -c "
from scitt_cose import verify_receipt
receipt = open('receipt7271.cose','rb').read()
leaf = open('receipt7271.leaf.bin','rb').read()
pub = open('receipt7271.pubkey.pem','rb').read()
res = verify_receipt(receipt, leaf_entry_hex=leaf.hex(), log_public_key_pem=pub)
print(res.ok, res.root, res.tree_size, res.leaf_index)
"
True 9197250336b47f9138241010cfd9195b19ecf3dab39c0dcc89b3b13b05b07162 7395 7271
```

A receipt built by our code, on a real leaf, against the live checkpoint at
size 7395, verifies under an independent implementation neither of us wrote
with the other's code in mind after the fact — `scitt-cose` was built as
generic, payload-agnostic substrate; `scitt_receipt.py` targeted its wire
format because it's the one Python peer implementing this shape. Tamper
control: flipping one byte of the receipt makes `verify_receipt` return
`ok=False`.

The receipt above is signed by a throwaway key generated per run, not the
log's real Ed25519 key -- useful for checking the wire format, not for
handing someone a receipt they should trust. `--real-key` closes that: it
loads the same seed `log_server.py` signs checkpoints with (env `LOG_SEED`,
default `~/.secrets/log_ed25519.seed`) and signs the receipt with it instead.
Run the same way, on leaf 7271:

```
$ python3 scitt_receipt.py 7271 --real-key --out realkey.cose
...
signing key    : REAL log key
pubkey written : realkey.pubkey.pem
```

The derived public key, `3929396a...baf4def`, matches byte-for-byte the key
in the log's own published policy (`markovianprotocol.com/log+0302c6c8+...`)
-- decode the vkey's base64, drop the leading algorithm byte, and the
remaining 32 bytes are identical to what this tool wrote to
`realkey.pubkey.pem`. That receipt then verifies under `scitt-cose` the same
way: `ok=True`, same root, same tree_size, same leaf_index, tamper control
fails. Not a decoy key producing a self-consistent receipt -- the log's
actual, publicly pinned signing key, checked against an independent
implementation, with the private seed never leaving the process that loaded
it.

## Why this is here

A receipt format checked only by the code that emits it has the same
single-signer blind spot the log itself has, one layer down — see
`get-witnessed.html`. An independent implementation reading the bytes and
agreeing is the check; the RFC citation alone is not.
