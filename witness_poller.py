#!/usr/bin/env python3
"""Poll-based witnessing for logs that do not push checkpoints to us.

For each log in poll_logs.json:
  1. fetch its current checkpoint (tlog-tiles: GET <monitor>/checkpoint;
     sigsum: GET <base>/get-tree-head, reconstructed into the C2SP note the
     sigsum log key actually signed),
  2. verify the log signature against the key PINNED in logs.json,
  3. build the RFC 6962 consistency proof from our last-cosigned size to the
     new size (tlog-tiles: computed from the log's public hash tiles;
     sigsum: GET <base>/get-consistency-proof/<old>/<new>),
  4. verify that proof locally against our stored root,
  5. submit old+proof+checkpoint to OUR witness (localhost, the same
     c2sp.org/tlog-witness endpoint anyone else uses), and
  6. verify the returned cosignature against our own published verifier key,
     with the same check submit_witnesses.py applies to external witnesses.

The witness server stays the single enforcement point: the poller never writes
witness state, it only submits. A log that shrank or forked gets submitted
as-is and the server's refusal (400/409/422) is logged loudly.
"""
import base64, hashlib, json, os, sqlite3, sys, urllib.request, urllib.error

sys.path.insert(0, os.path.expanduser("~/pb_test/src"))
from proofbundle.checkpoint import verify_checkpoint, verify_cosignature  # noqa: E402
from proofbundle import merkle  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

sys.path.insert(0, os.path.expanduser("~/markovian/witness"))
import witness_server as W  # noqa: E402  (shared config: paths, seed, vkey)

WITNESS_URL = f"http://127.0.0.1:{W.PORT}/add-checkpoint"
TIMEOUT = 20


def http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "markovianprotocol.com/witness poller"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read()


# ------------------------- tlog-tiles consistency prover -------------------------
class TileProver:
    """Computes RFC 6962 node hashes and consistency proofs for a c2sp.org/tlog-tiles
    log from its public hash tiles. Entry i of tile (l, n) is the Merkle tree hash of
    leaves [(n*256+i)*256**l, (n*256+i+1)*256**l)."""

    def __init__(self, monitor_url, tree_size):
        self.base = monitor_url.rstrip("/")
        self.size = tree_size
        self.cache = {}

    @staticmethod
    def _enc_index(n):
        s = str(n)
        s = "0" * ((3 - len(s) % 3) % 3) + s
        groups = [s[i:i + 3] for i in range(0, len(s), 3)]
        return "/".join("x" + g for g in groups[:-1]) + ("/" if len(groups) > 1 else "") + groups[-1]

    def _tile(self, l, n):
        if (l, n) in self.cache:
            return self.cache[(l, n)]
        total = self.size >> (8 * l)              # complete entries at this tile level
        if total <= n * 256:
            raise ValueError(f"tile {l}/{n} beyond tree size {self.size}")
        w = min(256, total - n * 256)
        url = f"{self.base}/tile/{l}/{self._enc_index(n)}" + ("" if w == 256 else f".p/{w}")
        data = http_get(url)
        if len(data) != 32 * w:
            raise ValueError(f"tile {url}: got {len(data)} bytes, want {32 * w}")
        hashes = [data[i:i + 32] for i in range(0, len(data), 32)]
        self.cache[(l, n)] = hashes
        return hashes

    def node(self, v, i):
        """Hash of the complete subtree covering leaves [i*2**v, (i+1)*2**v)."""
        l, rem = v // 8, v % 8
        first = i << rem                           # first tile-level-l entry under this node
        tile = self._tile(l, first >> 8)
        off = first & 255
        row = tile[off:off + (1 << rem)]
        if len(row) != 1 << rem:
            raise ValueError(f"node({v},{i}): incomplete tile row")
        while len(row) > 1:
            row = [hashlib.sha256(b"\x01" + row[j] + row[j + 1]).digest()
                   for j in range(0, len(row), 2)]
        return row[0]

    def hash_range(self, lo, hi):
        """MTH(D[lo:hi]) per RFC 6962."""
        n = hi - lo
        if n <= 0 or hi > self.size:
            raise ValueError("bad range")
        if n & (n - 1) == 0 and lo % n == 0:
            return self.node(n.bit_length() - 1, lo // n)
        k = 1 << (n - 1).bit_length() - 1          # largest power of two < n
        if k == n:
            k >>= 1
        return hashlib.sha256(b"\x01" + self.hash_range(lo, lo + k)
                              + self.hash_range(lo + k, hi)).digest()

    def consistency_proof(self, m, n):
        """PROOF(m, D[n]) per RFC 6962 section 2.1.2."""
        if m == 0 or m == n:
            return []

        def sub(m_abs, lo, hi, b):
            if m_abs == hi:
                return [] if b else [self.hash_range(lo, hi)]
            k = 1 << (hi - lo - 1).bit_length() - 1
            if k == hi - lo:
                k >>= 1
            mid = lo + k
            if m_abs <= mid:
                return sub(m_abs, lo, mid, b) + [self.hash_range(mid, hi)]
            return sub(m_abs, mid, hi, False) + [self.hash_range(lo, mid)]

        return sub(m, 0, n, True)


# ------------------------------- fetchers -------------------------------
def fetch_tiles_checkpoint(meta):
    note = http_get(meta["monitor"].rstrip("/") + "/checkpoint").decode("utf-8")
    return note, None


def fetch_checkpoint_entries(meta):
    """Flat, non-tiled c2sp.org/tlog-checkpoint logs (same shape as our own):
    all leaves served as raw newline-delimited bytes at one URL, no tiling.
    Each line, trailing newline stripped, is exactly the leaf the log's
    Merkle tree hashes -- verified for log.traceseal.io 2026-08-17 by
    recomputing its root from these bytes and matching the published
    checkpoint (proofbundle.merkle.merkle_tree_hash)."""
    data = http_get(meta["entries"])
    return [line for line in data.split(b"\n") if line]


def fetch_sigsum_checkpoint(meta, origin, pinned_vkey):
    """Sigsum logs speak their own ASCII API, but the log signature IS the Ed25519
    signature over the C2SP checkpoint note for origin sigsum.org/v1/tree/<keyhash>.
    Reconstruct that note so the standard pinned-key verification applies."""
    fields = {}
    for line in http_get(meta["base"].rstrip("/") + "/get-tree-head").decode().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            fields.setdefault(k, v)
    size = int(fields["size"])
    root = bytes.fromhex(fields["root_hash"])
    sig = bytes.fromhex(fields["signature"])
    keyid_hex = pinned_vkey.split("+", 2)[1]
    payload = base64.b64encode(bytes.fromhex(keyid_hex) + sig).decode()
    note = f"{origin}\n{size}\n{base64.b64encode(root).decode()}\n\n— {origin} {payload}\n"
    return note, fields


def sigsum_consistency_proof(meta, old, new):
    proof = []
    body = http_get(meta["base"].rstrip("/") + f"/get-consistency-proof/{old}/{new}").decode()
    for line in body.splitlines():
        if line.startswith("node_hash="):
            proof.append(bytes.fromhex(line.split("=", 1)[1]))
    return proof


# ------------------------- cosignature verification -------------------------
def verify_like_submit_witnesses(cosig_line, note_text, wname, keyid_hex, pub32):
    """The exact check submit_witnesses.py applies before publishing a cosignature:
    keyId must match the pinned key and Ed25519 must verify over
    'cosignature/v1\\ntime <T>\\n' + first-three-lines-of-note."""
    parts = cosig_line.strip().split(" ", 2)
    if len(parts) != 3 or parts[1] != wname:
        return False, "malformed cosignature line"
    raw = base64.b64decode(parts[2])
    if len(raw) != 76:
        return False, f"payload {len(raw)} bytes, want 76"
    if raw[:4].hex() != keyid_hex:
        return False, f"keyId {raw[:4].hex()} != pinned {keyid_hex}"
    ts = int.from_bytes(raw[4:12], "big")
    body = "\n".join(note_text.split("\n")[:3]) + "\n"
    msg = b"cosignature/v1\ntime " + str(ts).encode() + b"\n" + body.encode()
    try:
        Ed25519PublicKey.from_public_bytes(pub32).verify(raw[12:], msg)
    except Exception:
        return False, "Ed25519 signature failed"
    return True, f"ok (time {ts})"


# ------------------------------- main -------------------------------
def stored_state(origin):
    db = sqlite3.connect(f"file:{W.DB_PATH}?mode=ro", uri=True)
    row = db.execute("SELECT size, root FROM cosigned WHERE origin=?", (origin,)).fetchone()
    db.close()
    return (row[0], row[1]) if row else (0, None)


def submit(old, proof, note):
    body = (f"old {old}\n" + "".join(base64.b64encode(p).decode() + "\n" for p in proof)
            + "\n" + note).encode()
    req = urllib.request.Request(WITNESS_URL, data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.getcode(), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def process(origin, vkey, meta, wname, keyid_hex, pub32):
    kind = meta.get("type", "tiles")
    if kind == "sigsum":
        note, _ = fetch_sigsum_checkpoint(meta, origin, vkey)
    else:
        note, _ = fetch_tiles_checkpoint(meta)
    res = verify_checkpoint(note, vkey)
    if not res["ok"]:
        return False, "log signature did NOT verify against pinned key -- refusing to submit"
    if res["origin"] != origin:
        return False, f"origin mismatch: checkpoint says {res['origin']!r}"
    new_size, new_root = res["tree_size"], res["root"]
    old_size, old_root = stored_state(origin)

    if new_size < old_size:
        st, bd = submit(old_size, [], note)     # server must refuse; record that loudly
        return False, (f"ROLLBACK? log serves size {new_size} < cosigned {old_size}; "
                       f"witness said {st} {bd.decode(errors='replace').strip()}")
    if new_size == old_size and new_root == old_root:
        return True, f"unchanged at size {new_size}; nothing to cosign"

    if old_size == 0 or new_size == old_size:
        proof = []                              # TOFU, or same-size (root equality is the server's check)
    elif kind == "sigsum":
        proof = sigsum_consistency_proof(meta, old_size, new_size)
    elif kind == "checkpoint":
        proof = merkle.consistency_proof(fetch_checkpoint_entries(meta)[:new_size], old_size)
    else:
        proof = TileProver(meta["monitor"], new_size).consistency_proof(old_size, new_size)

    if old_size and new_size > old_size:
        if not merkle.verify_consistency(old_size, new_size, proof, old_root, new_root):
            return False, f"local consistency check {old_size}->{new_size} FAILED -- not submitting"

    st, bd = submit(old_size, proof, note)
    if st != 200:
        return False, f"witness refused: {st} {bd.decode(errors='replace').strip()}"
    cosig_line = bd.decode()
    okA = verify_cosignature(note + cosig_line, W.our_vkey(W.load_signer())).get("ok")
    okB, why = verify_like_submit_witnesses(cosig_line, note, wname, keyid_hex, pub32)
    if not (okA and okB):
        return False, f"cosigned {old_size}->{new_size} but VERIFICATION FAILED: pb={okA} sw={why}"
    return True, f"cosigned {old_size}->{new_size}, cosignature verified ({why})"


def main():
    import time
    logs = W.load_logs()
    poll = json.load(open(W.POLL_PATH))
    our = W.our_vkey(W.load_signer())
    wname, keyid_hex, kb64 = our.split("+")
    keymat = base64.b64decode(kb64)
    assert keymat[0] == 0x04 and len(keymat) == 33
    pub32 = keymat[1:]

    failures = 0
    for origin, meta in poll.items():
        vkey = logs.get(origin)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if not vkey:
            print(f"{stamp} {origin}: SKIP -- no pinned key in logs.json"); failures += 1; continue
        try:
            ok, msg = process(origin, vkey, meta, wname, keyid_hex, pub32)
        except Exception as e:
            ok, msg = False, f"error: {e!r}"
        print(f"{stamp} {origin}: {'OK' if ok else 'FAIL'} -- {msg}")
        failures += 0 if ok else 1
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
