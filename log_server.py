#!/usr/bin/env python3
"""A complete C2SP transparency log in one file. This is the live server behind
log.markovianprotocol.com, published as-is.

It stores leaves in SQLite, computes the RFC 6962 tree, serves signed checkpoints
(c2sp.org/tlog-checkpoint) with witness cosignatures, static tiles
(c2sp.org/tlog-tiles), inclusion/consistency proofs, offline proof bundles
(c2sp.org/tlog-proof), a machine-readable trust policy (c2sp.org/tlog-policy),
RFC 9942 SCITT COSE receipts, a live status badge (/badge.svg), and a
rate-limited public hash-only submission door whose receipts link a human
receipt page per leaf.

All crypto is proofbundle (github.com/MarkovianProtocol/proofbundle, spec-verified
against C2SP); this file is storage + endpoints. Appends beyond /submit require the
local admin token; everything else is public read.

Usage: log_server.py --selftest | --serve | --add "<data>" | --checkpoint | --submit <witness-url>
"""
import sqlite3, threading, time, base64, os, pathlib, json, re, sys, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, os.path.expanduser("~/pb_test/src"))
from proofbundle.checkpoint import sign_checkpoint, verify_checkpoint, vkey  # noqa: E402
from proofbundle import merkle  # noqa: E402
import scitt_receipt as _scitt  # noqa: E402  (RFC 9942 COSE receipt projection)
import make_tiles as _tiles  # noqa: E402  (c2sp.org/tlog-tiles static mirror)

TILES_DIR = os.path.expanduser("~/markovian/log/tiles")
# tile path element: "042", "x042", a ".p"-suffixed form, or a bare width 1-255
_TILE_ELEM = re.compile(r"^(x?\d{3}(\.p)?|[1-9]\d{0,2})$")

ORIGIN     = os.environ.get("LOG_ORIGIN", "markovianprotocol.com/log")
SEED_PATH  = os.path.expanduser(os.environ.get("LOG_SEED", "~/.secrets/log_ed25519.seed"))
DB_PATH    = os.path.expanduser(os.environ.get("LOG_DB", "~/markovian/log/log.db"))
TOKEN_PATH = os.path.expanduser(os.environ.get("LOG_TOKEN", "~/.secrets/log_admin_token"))
PORT       = int(os.environ.get("LOG_PORT", "8098"))
_lock = threading.Lock()


def _badge_svg(label, value, color):
    """Markovian badge: dark slate label segment with the gold atom mark, colored
    value segment, sheen, rounded corners. Width from 11px system-font metrics."""
    ICON_W = 21
    lw = ICON_W + int(6.1 * len(label)) + 10
    vw = int(6.1 * len(value)) + 18
    w = lw + vw
    tx_l = ICON_W + (lw - ICON_W) / 2.0
    tx_v = lw + vw / 2.0
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="22" role="img" aria-label="{label}: {value}">
<title>{label}: {value}</title>
<defs>
<linearGradient id="s" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity=".14"/><stop offset=".92" stop-opacity="0"/></linearGradient>
<clipPath id="r"><rect width="{w}" height="22" rx="5"/></clipPath>
</defs>
<g clip-path="url(#r)">
<rect width="{lw}" height="22" fill="#24292f"/>
<rect x="{lw}" width="{vw}" height="22" fill="{color}"/>
<rect width="{w}" height="22" fill="url(#s)"/>
</g>
<g transform="translate(5.5,4.6)" stroke="#e6b845" stroke-width="1.05" fill="none">
<circle cx="6.4" cy="6.4" r="1.25" fill="#e6b845" stroke="none"/>
<ellipse cx="6.4" cy="6.4" rx="5.7" ry="2.15"/>
<ellipse cx="6.4" cy="6.4" rx="5.7" ry="2.15" transform="rotate(60 6.4 6.4)"/>
<ellipse cx="6.4" cy="6.4" rx="5.7" ry="2.15" transform="rotate(120 6.4 6.4)"/>
</g>
<g font-family="-apple-system,'Segoe UI',Helvetica,Arial,sans-serif" font-size="11" font-weight="500" text-anchor="middle" letter-spacing=".2">
<text x="{tx_l}" y="15.6" fill="#010101" fill-opacity=".25">{label}</text>
<text x="{tx_l}" y="14.8" fill="#fff">{label}</text>
<text x="{tx_v}" y="15.6" fill="#010101" fill-opacity=".25">{value}</text>
<text x="{tx_v}" y="14.8" fill="#fff">{value}</text>
</g>
</svg>'''


# --- public submit (hash receipts) ---
# Hash-only by design: nothing a submitter sends is stored except 32 bytes of
# sha256, so there is no content to moderate and no way to make the log carry
# anything but hashes. The submitter keeps the preimage; inclusion in a
# witnessed checkpoint (and its Bitcoin anchor) is what bounds the time.
PUBLIC_LEAF_PREFIX = "public-note:v1"
PUBLIC_BASE = os.environ.get("LOG_PUBLIC_BASE", "https://log.markovianprotocol.com")
_submit_lock = threading.Lock()
_submit_hist = {}            # ip -> [epoch, ...]; in-memory, resets on restart
_SUBMIT_PER_IP_HOUR = 10
_SUBMIT_GLOBAL_DAY = 500


def load_signer(seed_path=SEED_PATH):
    seed = base64.b64decode(pathlib.Path(seed_path).read_text().strip())
    if len(seed) != 32:
        raise SystemExit(f"log seed must decode to 32 bytes, got {len(seed)}")
    return Ed25519PrivateKey.from_private_bytes(seed)


def log_vkey(signer, origin=ORIGIN):
    pub = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return vkey(origin, pub)


def init_db(path=DB_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("CREATE TABLE IF NOT EXISTS leaves(idx INTEGER PRIMARY KEY, data BLOB NOT NULL)")
    conn.commit()
    return conn


# ----------------------------- log core -----------------------------
def all_leaves(conn):
    return [row[0] for row in conn.execute("SELECT data FROM leaves ORDER BY idx ASC")]


def tree_size(conn):
    row = conn.execute("SELECT COUNT(*) FROM leaves").fetchone()
    return row[0]


def add_leaf(conn, data: bytes):
    """Append one leaf; returns the new tree size. Append-only: idx = current size."""
    with _lock:
        n = tree_size(conn)
        conn.execute("INSERT INTO leaves(idx, data) VALUES(?, ?)", (n, data))
        conn.commit()
        # tiles must be current before a checkpoint at the new size is served
        # (tlog-tiles MUST); build is incremental+atomic, <1s at current scale.
        # A failure never blocks the append — the daily sweep converges it.
        try:
            _tiles.make_tiles(all_leaves(conn), TILES_DIR)
        except (Exception, SystemExit) as e:  # make_tiles sys.exits on fatals
            print("tile build failed:", e, file=sys.stderr)
        return n + 1


ANCHOR_DIR = pathlib.Path(os.path.expanduser("~/markovian/log/anchors"))


def _anchor_state():
    """Newest anchored checkpoint, and the Bitcoin block confirming it (if any).

    A proof with only calendar attestations is PENDING, not anchored. Say so.
    """
    import re as _re
    import subprocess as _sp
    if not ANCHOR_DIR.exists():
        return {"anchored": False, "reason": "no anchors yet"}
    proofs = sorted(ANCHOR_DIR.glob("*.checkpoint.ots"),
                    key=lambda f: int(f.name.split(".")[0]))
    if not proofs:
        return {"anchored": False, "reason": "no anchors yet"}

    newest = proofs[-1]
    size = int(newest.name.split(".")[0])
    ots = "/home/mkv/venv/bin/ots"
    try:
        info = _sp.run([ots, "info", str(newest)], capture_output=True,
                       text=True, timeout=20).stdout
    except Exception:
        info = ""
    m = _re.search(r"BitcoinBlockHeaderAttestation\((\d+)\)", info)

    # Also report the newest proof that IS confirmed, which may be older than the
    # newest proof overall -- the most recent checkpoint is usually still pending.
    confirmed_size, confirmed_block = None, None
    for f in reversed(proofs):
        try:
            i2 = _sp.run([ots, "info", str(f)], capture_output=True,
                         text=True, timeout=20).stdout
        except Exception:
            continue
        m2 = _re.search(r"BitcoinBlockHeaderAttestation\((\d+)\)", i2)
        if m2:
            confirmed_size = int(f.name.split(".")[0])
            confirmed_block = int(m2.group(1))
            break

    state = {
        "latest_stamped_size": size,
        "latest_stamped_block": int(m.group(1)) if m else None,
        "confirmed_size": confirmed_size,
        "confirmed_block": confirmed_block,
        "anchored": confirmed_block is not None,
        "block": confirmed_block,
        "proof": ("/anchor/%d.ots" % confirmed_size) if confirmed_size else None,
        "note": ("checkpoint at size %d is committed to Bitcoin block %d"
                 % (confirmed_size, confirmed_block)) if confirmed_block else
                "stamped, pending confirmation in a Bitcoin block",
    }

    # Header verification (verify_anchor_headers's periodic run): the confirmed
    # anchors' merkle roots checked against self-validated Bitcoin headers, not
    # the calendar's word. Surfaced so a reader sees what we verified, not what
    # OpenTimestamps asserted.
    try:
        import json as _json
        st = _json.loads((ANCHOR_DIR / "header_verify_status.json").read_text())
        age = int(time.time()) - int(st.get("checked_at", 0))
        state["header_verified"] = bool(st.get("ok")) and age < 86400
        state["header_verified_count"] = st.get("verified")
        state["header_mismatches"] = st.get("mismatch")
        state["header_verify_note"] = (
            "%d confirmed anchors' merkle roots matched self-validated Bitcoin headers "
            "(%d mismatches), checked %dh ago"
            % (st.get("verified", 0), st.get("mismatch", 0), age // 3600))
    except Exception:
        state["header_verified"] = None
    return state


def signed_checkpoint(conn, signer, origin=ORIGIN, size=None):
    leaves = all_leaves(conn)
    if size is None:
        size = len(leaves)
    if size > len(leaves):
        raise ValueError("size beyond tree")
    root = merkle.merkle_tree_hash(leaves[:size])
    return sign_checkpoint(origin, size, root, signer, origin)


WITNESSED_PATH = pathlib.Path(os.path.expanduser("~/markovian/log/witnessed.checkpoint"))


def witnessed_checkpoint(conn):
    """The newest checkpoint independent witnesses have actually cosigned, or None.

    Written by submit_witnesses.py: the pinned note plus every independent cosignature
    line. This is what GET /checkpoint serves, because a checkpoint nobody witnessed is
    a checkpoint you have to take our word for -- and we hold the log key.

    Re-derived and checked against our own tree on every read. A witnessed note whose
    size or root does not match this tree is a bug or a tamper, and we serve nothing
    rather than serve a lie: a cosignature is bound to ONE (size, root), so publishing a
    stale one against a grown tree is worse than publishing none.
    """
    if not WITNESSED_PATH.exists():
        return None
    try:
        note = WITNESSED_PATH.read_text()
        lines = note.split("\n")
        size = int(lines[1])
        root = lines[2]
        leaves = all_leaves(conn)
        if size > len(leaves):
            return None                                     # claims more than we have
        if base64.b64encode(merkle.merkle_tree_hash(leaves[:size])).decode() != root:
            return None                                     # root disagrees with our tree
        if not any(ln.startswith("—") and ORIGIN not in ln for ln in lines):
            return None                                     # no independent cosignature in it
        return note
    except Exception:
        return None


# ----------------------------- tlog-witness submit client -----------------------------
def submit_to_witness(witness_url, conn, signer, origin=ORIGIN, timeout=15):
    """Submit our current checkpoint to a C2SP tlog-witness, resolving `old` via the 409 dance.

    Returns (status, cosignature_or_body). On 200 the body is the witness cosignature line(s)."""
    leaves = all_leaves(conn)
    size = len(leaves)
    checkpoint = signed_checkpoint(conn, signer, origin, size)

    def _post(old):
        proof = merkle.consistency_proof(leaves, old) if 0 < old < size else []
        header = f"old {old}\n" + "".join(base64.b64encode(p).decode() + "\n" for p in proof) + "\n"
        body = (header + checkpoint).encode()
        req = urllib.request.Request(witness_url, data=body, method="POST",
                                     headers={"Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    status, resp = _post(0)                       # optimistic first-use
    if status == 409:                             # witness already knows us; retry with its stored size
        try:
            old = int(resp.strip())
        except ValueError:
            return status, resp
        status, resp = _post(old)
    return status, resp


# ----------------------------- HTTP server -----------------------------
def _proof_body(proof):
    return ("".join(base64.b64encode(p).decode() + "\n" for p in proof)).encode()


def make_handler(conn, signer, admin_token, origin=ORIGIN):
    class H(BaseHTTPRequestHandler):
        def do_OPTIONS(self):
            # Preflight for browser-based verifiers.
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _send(self, status, body=b"", ctype="text/plain; charset=utf-8", cache=False):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            # A log nobody can read is a log nobody can check.
            self.send_header("Access-Control-Allow-Origin", "*")
            if cache == "short":
                # bytes are stable but the file gets superseded (partial tiles)
                self.send_header("Cache-Control", "public, max-age=30")
            elif cache:
                # only for responses whose bytes can never change (completed leaf ranges)
                self.send_header("Cache-Control", "public, max-age=86400, immutable")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            path = u.path.rstrip("/") or "/"
            try:
                if path == "/":
                    idx = (
                        f"{origin}\n"
                        f"C2SP tlog-checkpoint-format transparency log\n\n"
                        f"tree size : {tree_size(conn)}\n"
                        f"vkey      : {log_vkey(signer, origin)}\n\n"
                        f"GET /checkpoint\n"
                        f"GET /consistency?old=<n>&new=<m>\n"
                        f"GET /inclusion?leaf=<i>&size=<m>\n"
                        f"GET /leaf/<i>\n"
                        f"GET /leaves?start=<s>&end=<e>\n"
                        f"GET /receipt/scitt/<i>          (RFC 9942 COSE receipt)\n"
                        f"GET /tile/<L>/<N>[.p/<W>]           (c2sp.org/tlog-tiles)\n"
                        f"GET /tile/entries/<N>[.p/<W>]\n"
                        f"GET /proof/<i>                      (c2sp.org/tlog-proof offline bundle)\n"
                        f"GET /policy                         (c2sp.org/tlog-policy trust policy)\n"
                        f"GET /health\n"
                        f"POST /submit                        (public: notarize a sha256 hash,\n"
                        f"                                     body \"sha256:<64 hex>\", rate-limited)\n"
                    )
                    return self._send(200, idx.encode())
                if path.startswith("/tile/"):
                    parts = path.split("/")[2:]
                    if (not parts or len(parts) < 2 or
                            (parts[0] != "entries" and not (parts[0].isdigit() and int(parts[0]) <= 63)) or
                            any(not _TILE_ELEM.match(p) for p in parts[1:])):
                        return self._send(404, b"not found\n")
                    f = pathlib.Path(TILES_DIR).joinpath("tile", *parts)
                    if not f.is_file():
                        return self._send(404, b"not found\n")
                    return self._send(200, f.read_bytes(), "application/octet-stream",
                                      cache=("short" if ".p" in path else True))
                if path == "/health":
                    return self._send(200, b"ok\n")

                if path == "/anchor":
                    return self._send(200, json.dumps(_anchor_state(), indent=2).encode(),
                                      "application/json")

                if path.startswith("/anchor/") and path.endswith(".ots"):
                    name = path[len("/anchor/"):]
                    f = ANCHOR_DIR / (name.replace(".ots", ".checkpoint.ots"))
                    if not f.exists() or ".." in name:
                        return self._send(404, b"no such anchor\n")
                    return self._send(200, f.read_bytes(), "application/octet-stream")

                if path.startswith("/anchor/") and path.endswith(".checkpoint"):
                    name = path[len("/anchor/"):]
                    f = ANCHOR_DIR / name
                    if not f.exists() or ".." in name:
                        return self._send(404, b"no such checkpoint\n")
                    return self._send(200, f.read_bytes())
                if path.startswith("/proof/"):
                    # c2sp.org/tlog-proof ("spicy signature"): a self-contained,
                    # offline-verifiable bundle -- index, RFC 6962 inclusion path,
                    # and the witnessed checkpoint verbatim (cosignatures included).
                    # Built only against the WITNESSED checkpoint: a proof against
                    # an unwitnessed tip would carry no non-equivocation weight.
                    i = int(path.split("/proof/", 1)[1])
                    wnote = witnessed_checkpoint(conn)
                    if wnote is None:
                        return self._send(503, b"no witnessed checkpoint available yet\n")
                    size = int(wnote.split("\n")[1])
                    if not (0 <= i < size):
                        return self._send(404, b"leaf not yet in a witnessed checkpoint; retry after the next witness round\n")
                    proof = merkle.inclusion_proof(all_leaves(conn)[:size], i)
                    body = ("c2sp.org/tlog-proof@v1\n"
                            + "index %d\n" % i
                            + "".join(base64.b64encode(p).decode() + "\n" for p in proof)
                            + "\n" + wnote)
                    return self._send(200, body.encode(), cache="short")
                if path == "/badge.svg":
                    # Live badge: witnessed head size + distinct witness count.
                    # Self-served but checkable — it's a claim about /checkpoint.
                    wnote = witnessed_checkpoint(conn)
                    if wnote is None:
                        label, value, color = "witnessed head", "none yet", "#86868b"
                    else:
                        size = int(wnote.split("\n")[1])
                        wits = len({l.split(" ")[1] for l in wnote.splitlines()
                                    if l.startswith("— ") and origin not in l})
                        label = "witnessed head"
                        value = "size %s · %d witnesses" % (format(size, ","), wits)
                        color = "#1d8a4e" if wits >= 4 else "#b26a00"
                    return self._send(200, _badge_svg(label, value, color).encode(),
                                      "image/svg+xml", cache="short")
                if path == "/policy":
                    # c2sp.org/tlog-policy: the log's witness trust policy, so an
                    # offline verifier knows which cosignature sets are sufficient.
                    f = pathlib.Path(os.path.expanduser("~/markovian/log/tlog.policy"))
                    if not f.is_file():
                        return self._send(404, b"no policy published\n")
                    return self._send(200, f.read_bytes(), cache="short")
                if path == "/checkpoint":
                    w = witnessed_checkpoint(conn)
                    if w is not None:
                        return self._send(200, w.encode())
                    return self._send(200, signed_checkpoint(conn, signer, origin).encode())
                if path == "/checkpoint/unwitnessed":
                    # The live tree tip, signed by us alone. No witness has seen it yet,
                    # so it carries no non-equivocation guarantee. Debugging only.
                    return self._send(200, signed_checkpoint(conn, signer, origin).encode())
                if path == "/consistency":
                    size = tree_size(conn)
                    old = int(q.get("old", ["0"])[0]); new = int(q.get("new", [str(size)])[0])
                    if not (0 <= old <= new <= size):
                        return self._send(400, b"require 0<=old<=new<=size\n")
                    leaves = all_leaves(conn)[:new]
                    proof = merkle.consistency_proof(leaves, old) if 0 < old < new else []
                    return self._send(200, _proof_body(proof))
                if path == "/inclusion":
                    size = tree_size(conn)
                    m = int(q.get("size", [str(size)])[0]); i = int(q.get("leaf", ["-1"])[0])
                    if not (0 <= i < m <= size):
                        return self._send(400, b"require 0<=leaf<size<=tree\n")
                    proof = merkle.inclusion_proof(all_leaves(conn)[:m], i)
                    return self._send(200, _proof_body(proof))
                if path == "/evidence":
                    i = int(q.get("leaf", ["-1"])[0])
                    if not (0 <= i < tree_size(conn)):
                        return self._send(400, b"require 0<=leaf<tree\n")
                    import subprocess as _sp
                    r = _sp.run(["/usr/bin/python3",
                                 os.path.expanduser("~/markovian/log/evidence.py"),
                                 str(i)], capture_output=True, text=True, timeout=120)
                    if r.returncode != 0:
                        return self._send(500, b"evidence unavailable\n")
                    return self._send(200, r.stdout.encode(), "application/json")
                if path.startswith("/leaf/"):
                    i = int(path.split("/leaf/", 1)[1])
                    row = conn.execute("SELECT data FROM leaves WHERE idx=?", (i,)).fetchone()
                    return self._send(200, row[0], "application/octet-stream") if row else self._send(404, b"no such leaf\n")
                if path == "/leaves":
                    # Bulk read for verifiers and the endorsements panel: at most 256
                    # leaves per request, base64 in a JSON envelope (leaves are bytes).
                    # Bounds are strict -- no clamping to the tip -- so a valid range's
                    # body is immutable and marked cacheable for browsers and CDNs.
                    size = tree_size(conn)
                    start = int(q.get("start", ["0"])[0])
                    end = int(q.get("end", [str(min(size, start + 256))])[0])
                    if not (0 <= start < end <= size):
                        return self._send(400, b"require 0<=start<end<=size\n")
                    if end - start > 256:
                        return self._send(400, b"at most 256 leaves per request\n")
                    rows = conn.execute(
                        "SELECT data FROM leaves WHERE idx>=? AND idx<? ORDER BY idx",
                        (start, end)).fetchall()
                    body = json.dumps({"start": start, "end": end,
                                       "leaves": [base64.b64encode(r[0]).decode() for r in rows]}).encode()
                    return self._send(200, body, "application/json", cache=True)
                if path.startswith("/receipt/scitt/"):
                    # RFC 9942 COSE receipt (verifiable-data-structure RFC9162_SHA256)
                    # for leaf i: a COSE_Sign1 carrying the RFC 6962 inclusion proof,
                    # signed by the log's own Ed25519 key. A lossy projection of our
                    # native witnessed checkpoint -- inclusion under the log key, no
                    # witness quorum -- for SCITT-ecosystem interop.
                    # Built against the WITNESSED checkpoint (the cosigned state /checkpoint
                    # serves), so a consumer can cross-check the receipt's root against
                    # /checkpoint and fetch the witness cosignatures for the quorum this
                    # single-signer COSE receipt cannot itself carry.
                    i = int(path.split("/receipt/scitt/", 1)[1])
                    wnote = witnessed_checkpoint(conn)
                    if wnote is None:
                        return self._send(503, b"no witnessed checkpoint available yet\n")
                    size = int(wnote.split("\n")[1])
                    if not (0 <= i < size):
                        return self._send(404, b"leaf not yet in a witnessed checkpoint; retry after the next witness round\n")
                    row = conn.execute("SELECT data FROM leaves WHERE idx=?", (i,)).fetchone()
                    if not row:
                        return self._send(404, b"no such leaf\n")
                    proof = merkle.inclusion_proof(all_leaves(conn)[:size], i)
                    receipt, _root = _scitt.build_receipt(row[0], i, size, proof, signer, detached=True)
                    return self._send(200, receipt, "application/cose")
                return self._send(404, b"not found\n")
            except (ValueError, KeyError):
                return self._send(400, b"bad request\n")

        def _submit_public(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            if n > 128:
                return self._send(413, b'body too large; send "sha256:<64 hex>"\n')
            body = self.rfile.read(n).decode("utf-8", "replace").strip().lower()
            h = body[len("sha256:"):] if body.startswith("sha256:") else body
            if not re.fullmatch(r"[0-9a-f]{64}", h):
                return self._send(400, b'send a sha256 hash: "sha256:<64 hex>"\n')
            # Rate limit by connecting IP (proxy header first -- the server sits
            # behind a local-only listener, so client_address is the tunnel).
            ip = (self.headers.get("CF-Connecting-IP")
                  or self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                  or self.client_address[0])
            now = time.time()
            with _submit_lock:
                hist = _submit_hist.setdefault(ip, [])
                hist[:] = [t for t in hist if now - t < 86400]
                if sum(1 for t in hist if now - t < 3600) >= _SUBMIT_PER_IP_HOUR:
                    return self._send(429, b"rate limit: %d submissions/hour/IP\n"
                                      % _SUBMIT_PER_IP_HOUR)
                if sum(len(v) for v in _submit_hist.values()) >= _SUBMIT_GLOBAL_DAY:
                    return self._send(429, b"log-wide daily submission cap reached\n")
                hist.append(now)
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            leaf = f"{PUBLIC_LEAF_PREFIX} sha256:{h} {ts}".encode()
            size = add_leaf(conn, leaf)
            i = size - 1
            out = {
                "leaf_index": i,
                "tree_size": size,
                "leaf": leaf.decode(),
                "inclusion_proof": f"{PUBLIC_BASE}/inclusion?leaf={i}&size={size}",
                "leaf_bytes": f"{PUBLIC_BASE}/leaf/{i}",
                "witnessed_checkpoint": f"{PUBLIC_BASE}/checkpoint",
                "receipt_page": f"https://markovianprotocol.com/r/{i}",
                "scitt_receipt": f"{PUBLIC_BASE}/receipt/scitt/{i}",
                "note": ("your leaf is in the tree now; it is covered by witness "
                         "cosignatures and the Bitcoin anchor once /checkpoint "
                         "reports a size greater than %d (next witness round, "
                         "within the hour). The log stores only this hash -- "
                         "keep your file to prove what it was.") % i,
            }
            return self._send(200, json.dumps(out, indent=2).encode() + b"\n",
                              "application/json")

        def do_POST(self):
            if self.path.rstrip("/") == "/submit":
                return self._submit_public()
            if self.path.rstrip("/") != "/add-leaf":
                return self._send(404, b"not found\n")
            auth = self.headers.get("Authorization", "")
            if not admin_token or auth != f"Bearer {admin_token}":
                return self._send(403, b"admin token required\n")
            n = int(self.headers.get("Content-Length", 0) or 0)
            data = self.rfile.read(n)
            if not data:
                return self._send(400, b"empty leaf\n")
            return self._send(200, (f"{add_leaf(conn, data)}\n").encode())

        def log_message(self, fmt, *args):
            line = "%s - %s\n" % (self.log_date_time_string(), fmt % args)
            with open(os.path.expanduser("~/markovian/log/log.log"), "a") as f:
                f.write(line)
    return H


def _admin_token():
    return pathlib.Path(TOKEN_PATH).read_text().strip() if os.path.exists(TOKEN_PATH) else ""


def serve():
    signer = load_signer()
    conn = init_db()
    print(f"log origin   : {ORIGIN}")
    print(f"log vkey     : {log_vkey(signer)}")
    print(f"tree size    : {tree_size(conn)}")
    print(f"listening    : localhost:{PORT}  (GET /checkpoint /consistency /inclusion /leaf/<i>)")
    ThreadingHTTPServer(("127.0.0.1", PORT), make_handler(conn, signer, _admin_token())).serve_forever()


# ----------------------------- self-test -----------------------------
def selftest():
    """End-to-end: our log's checkpoints + proofs are accepted and cosigned by our ACTUAL tlog-witness,
    and the witness refuses us if we ever equivocate."""
    sys.path.insert(0, os.path.expanduser("~/markovian/witness"))
    from witness_server import add_checkpoint as witness_add   # our real Half-1 witness handler
    from proofbundle.checkpoint import verify_cosignature, cosign_vkey
    ok = lambda c, m: print(("PASS" if c else "FAIL"), m) or (c or sys.exit(1))

    # our log
    lsigner = Ed25519PrivateKey.generate()
    origin = "markovianprotocol.com/log"
    lpub = lsigner.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    lvkey = vkey(origin, lpub)
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE leaves(idx INTEGER PRIMARY KEY, data BLOB NOT NULL)")
    print("our log vkey:", lvkey)

    # a witness (reuse the real handler + a fresh witness key), trusting our log
    wsigner = Ed25519PrivateKey.generate()
    wname = "markovianprotocol.com/witness"
    wpub = wsigner.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    wvkey = cosign_vkey(wname, wpub)
    logs = {origin: lvkey}
    wconn = sqlite3.connect(":memory:")
    wconn.execute("CREATE TABLE cosigned(origin TEXT PRIMARY KEY, size INTEGER, root BLOB, checkpoint TEXT)")

    def submit(old):
        leaves = all_leaves(conn); size = len(leaves)
        cp = signed_checkpoint(conn, lsigner, origin, size)
        proof = merkle.consistency_proof(leaves, old) if 0 < old < size else []
        header = f"old {old}\n" + "".join(base64.b64encode(p).decode() + "\n" for p in proof) + "\n"
        return witness_add((header + cp).encode(), wconn, wsigner, logs, wname), cp

    # 1) append 10 leaves, checkpoint is well-formed and self-verifies
    for i in range(10):
        add_leaf(conn, f"mkv-entry-{i}".encode())
    ok(tree_size(conn) == 10, "10 leaves appended")
    cp10 = signed_checkpoint(conn, lsigner, origin)
    ok(verify_checkpoint(cp10, lvkey)["ok"], "our checkpoint verifies against our log vkey")

    # 2) witness cosigns us at size 10 (first use), and the cosignature verifies
    (st, hd, bd), cp = submit(0)
    ok(st == 200, f"witness cosigns first checkpoint (got {st})")
    ok(verify_cosignature(cp + bd.decode(), wvkey)["ok"], "witness cosignature verifies")

    # 3) grow to 25, submit with a real consistency proof -> cosigned
    for i in range(10, 25):
        add_leaf(conn, f"mkv-entry-{i}".encode())
    (st, hd, bd), _ = submit(10)
    ok(st == 200, f"witness cosigns consistent growth 10->25 (got {st})")

    # 4) the /consistency endpoint returns a proof that actually verifies old->new roots
    leaves = all_leaves(conn)
    proof = merkle.consistency_proof(leaves[:25], 10)
    r10 = merkle.merkle_tree_hash(leaves[:10]); r25 = merkle.merkle_tree_hash(leaves[:25])
    ok(merkle.verify_consistency(10, 25, proof, r10, r25), "served consistency proof verifies 10->25")

    # 5) inclusion proof for a leaf verifies against the checkpoint root
    ip = merkle.inclusion_proof(leaves[:25], 7)
    ok(merkle.verify_inclusion(leaves[7], 7, 25, ip, r25), "inclusion proof verifies for leaf 7")

    # 6) if WE equivocate (same size 25, different root) the witness refuses -> 422
    evil_root = merkle.merkle_tree_hash(leaves[:24] + [b"FORGED"])
    evil_cp = sign_checkpoint(origin, 25, evil_root, lsigner, origin)
    header = "old 25\n\n"
    st, hd, bd = witness_add((header + evil_cp).encode(), wconn, wsigner, logs, wname)
    ok(st == 422, f"witness refuses our split-view checkpoint (got {st})")

    # 7) honest growth still works afterward -> state intact
    for i in range(25, 40):
        add_leaf(conn, f"mkv-entry-{i}".encode())
    (st, hd, bd), _ = submit(25)
    ok(st == 200, f"witness resumes cosigning 25->40 after the reject (got {st})")

    print("\nALL SELFTESTS PASSED")


if __name__ == "__main__":
    if "--serve" in sys.argv:
        serve()
    elif "--add" in sys.argv:
        conn = init_db()
        data = sys.argv[sys.argv.index("--add") + 1].encode()
        print(add_leaf(conn, data))
    elif "--checkpoint" in sys.argv:
        print(signed_checkpoint(init_db(), load_signer()), end="")
    elif "--submit" in sys.argv:
        url = sys.argv[sys.argv.index("--submit") + 1]
        st, resp = submit_to_witness(url, init_db(), load_signer())
        print(f"[{st}]")
        print(resp, end="")
        sys.exit(0 if st == 200 else 1)
    else:
        selftest()
