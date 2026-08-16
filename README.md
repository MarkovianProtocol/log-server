# log-server

[![witnessed head](https://log.markovianprotocol.com/badge.svg)](https://log.markovianprotocol.com/checkpoint)

The complete tooling behind [log.markovianprotocol.com](https://log.markovianprotocol.com/),
published as it runs in production. A small transparency log doesn't need a platform;
it needs three files and a place to run them.

| File | What it is |
|---|---|
| `log_server.py` | The log: SQLite + RFC 6962 tree, serving `checkpoint` / `tile` (tlog-tiles) / `inclusion` / `consistency` / `proof` (tlog-proof) / `policy` (tlog-policy) / `receipt/scitt` (RFC 9942) / public `POST /submit` (hash-only, rate-limited) |
| `witness_server.py` | The witness: cosigns *other* operators' logs per c2sp.org/tlog-witness. Pins each log's key, refuses forks and rollbacks, never signs two histories |
| `verify_tlog_proof.py` | Offline verifier: proof bundle + leaf + policy in, PASS/FAIL out. No network |
| `make_tiles.py` | Renders the tree as static c2sp.org/tlog-tiles (stdlib only) |
| `scitt_receipt.py` | Projects a leaf into an RFC 9942 COSE receipt |
| `check_stream_v2.py` | Completeness checker: verify a stream's records are dense (nothing withheld), chained, and honestly repaired — the independent version of [/ask.html](https://markovianprotocol.com/ask.html) |
| `pq_selfsign.py` | ML-DSA-44 (FIPS 204) self-cosignature on the checkpoint, alongside Ed25519 |
| `verify_pq_line.py` | Checks any ML-DSA-44 cosignature line on a checkpoint against the operator's published verifier key |
| `submit_witnesses.py` | Sends one pinned checkpoint to every witness, verifies each returned cosignature against `witness_keys.json` before publishing it, drops anything that doesn't check out |
| `witness_keys.json` | The 7 witness verifier keys we pin, each collected from the operator's own page, never from a log |
| `tlog.policy.example` | Our live trust policy: a 4-of-7 quorum over named, unrelated operators |

## Quickstart

```
git clone https://github.com/MarkovianProtocol/proofbundle   # the crypto (checkpoints, cosignatures, merkle)
git clone https://github.com/MarkovianProtocol/log-server
pip install cryptography
python3 log_server.py --selftest && python3 log_server.py --serve
```

Keys are 32-byte Ed25519 seeds read from paths you set via env (`LOG_SEED`, `WITNESS_SEED`).
Generate one: `python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"`

## Verify something offline

```
curl -O https://log.markovianprotocol.com/proof/7271
curl -o leaf.bin https://log.markovianprotocol.com/leaf/7271
curl -o live.policy https://log.markovianprotocol.com/policy
python3 verify_tlog_proof.py leaf7271.tlog-proof leaf.bin live.policy
```

Checks the log signature, every witness cosignature against the policy's pinned
keys, the quorum, and the inclusion path to the signed root — with no network
and no trust in the operator.

Two of our witnesses also attach ML-DSA-44 cosignatures. Their verifier keys come
from the operators, not from us — TrustFabric publishes ring-any-bells' at
[transparency.dev/witnesses](https://transparency.dev/witnesses), Geomys publishes
navigli's on the [witness's own homepage](https://witness.navigli.sunlight.geomys.org):

```
curl -o cp.txt https://log.markovianprotocol.com/checkpoint
python3 verify_pq_line.py cp.txt "<vkey from the operator's page>"
```

The key id is recomputed from the key material before anything is verified, so a
key that doesn't belong to the line fails there rather than silently passing.

## Scope, honestly

A signature proves who signed; this stack exists for the harder problem: one
operator's log can keep two sets of books — one tree for you, a different one
for whoever checks later — and both print valid receipts. Witness cosignatures
make the books singular. Nothing here proves any entry's *content* is true; the
log proves what was said and when, never whether it was right.

Getting your own log witnessed: run your checkpoint through `submit_witnesses.py`
against `witness_keys.json` and you're sending to all 7. To get on that list
yourself, enroll at [witness-network.org/participate](https://witness-network.org/participate) —
our witness follows it and picks up new logs automatically — or open an issue
here with your origin, key, and checkpoint URL and we'll pin you directly.

Companion repos: [log-monitor](https://github.com/MarkovianProtocol/log-monitor)
(the standing auditor), [log-terminal-export](https://github.com/MarkovianProtocol/log-terminal-export)
(the whole log, offline). Apache-2.0.
