# log-server

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

## Scope, honestly

A signature proves who signed; this stack exists for the harder problem: one
operator's log can keep two sets of books — one tree for you, a different one
for whoever checks later — and both print valid receipts. Witness cosignatures
make the books singular. Nothing here proves any entry's *content* is true; the
log proves what was said and when, never whether it was right.

Getting your own log witnessed: [witness-network.org/participate](https://witness-network.org/participate).
Our witness will cosign you too.

Companion repos: [log-monitor](https://github.com/MarkovianProtocol/log-monitor)
(the standing auditor), [log-terminal-export](https://github.com/MarkovianProtocol/log-terminal-export)
(the whole log, offline). Apache-2.0.
