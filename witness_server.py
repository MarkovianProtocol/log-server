#!/usr/bin/env python3
"""C2SP tlog-witness for Markovian Protocol: we COSIGN other operators' transparency logs.

Verify the log's signature against its PINNED key, verify the checkpoint is an append-only
(consistent) extension of the last one we cosigned, and if so append our cosignature/v1 line.
Reject equivocation/inconsistency: we NEVER cosign two different roots for the same size and
NEVER accept a smaller tree than one we already cosigned. All crypto is proofbundle
(spec-verified against C2SP); this file is the tlog-witness HTTP protocol + per-log state.

Wire protocol (c2sp.org/tlog-witness):
  POST .../add-checkpoint
  body: "old <N>\n" + zero-or-more base64 consistency-hash lines + "\n" + <signed checkpoint>
  200 -> our cosignature line(s) (start with U+2014, end with \n)
  400 -> old>size / malformed        403 -> signature not from a trusted key
  404 -> unknown origin              409 -> old!=stored size; body = stored size, Content-Type text/x.tlog.size
  422 -> bad consistency proof / root mismatch / non-empty proof on empty tree

Public GET surface (also proxied at https://markovianprotocol.com/witness/...):
  /about                             witness name, verifier key, policy, watched logs
  /checkpoints                       latest cosigned checkpoint per log
  /<sha256(origin) hex>/checkpoint   monitor endpoint per c2sp.org/tlog-witness
  /health                            liveness

Log-key pinning: logs.json maps origin -> C2SP vkey. The pin source for each log is recorded
in poll_logs.json and shown on the about page. Our own log (markovianprotocol.com/log) is in
the set as a DEMO only: self-witnessing has no independence value and is excluded from the
independent-witness count our log publishes.

Usage: witness_server.py --selftest   |   witness_server.py --serve
"""
import sqlite3, threading, time, base64, os, pathlib, json, sys, hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, os.path.expanduser("~/pb_test/src"))
from proofbundle.checkpoint import verify_checkpoint, cosign_checkpoint, cosign_vkey  # noqa: E402
from proofbundle import merkle  # noqa: E402

WITNESS_NAME = os.environ.get("WITNESS_NAME", "markovianprotocol.com/witness")
SEED_PATH = os.path.expanduser(os.environ.get("WITNESS_SEED", "~/.secrets/witness_ed25519.seed"))
DB_PATH   = os.path.expanduser(os.environ.get("WITNESS_DB", "~/markovian/witness/witness.db"))
LOGS_PATH = os.path.expanduser(os.environ.get("WITNESS_LOGS", "~/markovian/witness/logs.json"))
NET_LOGS_PATH = os.path.expanduser(os.environ.get("WITNESS_NET_LOGS", "~/markovian/witness/logs_network.json"))
POLL_PATH = os.path.expanduser(os.environ.get("WITNESS_POLL", "~/markovian/witness/poll_logs.json"))
PORT      = int(os.environ.get("WITNESS_PORT", "8097"))
_lock = threading.Lock()


def load_signer(seed_path=SEED_PATH):
    seed = base64.b64decode(pathlib.Path(seed_path).read_text().strip())
    if len(seed) != 32:
        raise SystemExit(f"witness seed must decode to 32 bytes, got {len(seed)}")
    return Ed25519PrivateKey.from_private_bytes(seed)


def our_vkey(signer, name=WITNESS_NAME):
    pub = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return cosign_vkey(name, pub)


def load_logs():
    """Trusted origin->vkey map: logs_network.json (witness-network list-followed) merged UNDER
    logs.json (manual pins win on any conflict). Both files optional. Shared by the server and
    the poller so both see the same trusted set."""
    merged = {}
    for p in (NET_LOGS_PATH, LOGS_PATH):
        try:
            merged.update(json.load(open(p)))
        except Exception:
            pass
    return merged


def init_db(path=DB_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("CREATE TABLE IF NOT EXISTS cosigned("
                 "origin TEXT PRIMARY KEY, size INTEGER, root BLOB, checkpoint TEXT)")
    for col in ("cosigned_note TEXT", "cosigned_at INTEGER"):
        try:
            conn.execute(f"ALTER TABLE cosigned ADD COLUMN {col}")
        except sqlite3.OperationalError:
            pass                                        # column already exists
    conn.commit()
    return conn


def add_checkpoint(body: bytes, conn, signer, logs, name=WITNESS_NAME):
    """Pure request handler. Returns (status:int, headers:dict, body:bytes)."""
    try:
        text = body.decode("utf-8")
    except Exception:
        return 400, {}, b"bad encoding\n"
    if "\n\n" not in text:
        return 400, {}, b"missing proof/checkpoint separator\n"
    header, checkpoint = text.split("\n\n", 1)          # first blank line splits header from checkpoint
    hlines = header.split("\n")
    if not hlines[0].startswith("old "):
        return 400, {}, b"missing 'old' line\n"
    try:
        old_size = int(hlines[0][4:])
        assert old_size >= 0
    except (ValueError, AssertionError):
        return 400, {}, b"bad old size\n"
    proof_lines = [l for l in hlines[1:] if l != ""]
    if len(proof_lines) > 63:
        return 400, {}, b"too many consistency-proof lines\n"
    try:
        proof = [base64.b64decode(l, validate=True) for l in proof_lines]
    except Exception:
        return 400, {}, b"bad consistency-proof base64\n"

    origin = checkpoint.split("\n", 1)[0]
    vkey = logs.get(origin)
    if vkey is None:
        return 404, {}, b"unknown origin\n"
    try:
        res = verify_checkpoint(checkpoint, vkey)
    except Exception:
        return 400, {}, b"malformed checkpoint\n"
    if not res["ok"]:
        return 403, {}, b"no trusted signature for origin\n"
    new_size, new_root = res["tree_size"], res["root"]
    if old_size > new_size:
        return 400, {}, b"old size exceeds checkpoint size\n"

    with _lock:
        row = conn.execute("SELECT size, root FROM cosigned WHERE origin=?", (origin,)).fetchone()
        stored_size = row[0] if row else 0
        stored_root = row[1] if row else None
        if old_size != stored_size:
            return 409, {"Content-Type": "text/x.tlog.size"}, (f"{stored_size}\n").encode()
        if stored_size == 0:                              # trust-on-first-use: nothing prior to prove
            if proof:
                return 422, {}, b"non-empty proof for empty/unknown tree\n"
        elif old_size == new_size:                        # same size => same root, else equivocation
            if stored_root is None or stored_root != new_root:
                return 422, {}, b"root mismatch at equal size (equivocation)\n"
        else:                                             # 0 < old < new => must be a consistent extension
            if not merkle.verify_consistency(old_size, new_size, proof, stored_root, new_root):
                return 422, {}, b"invalid consistency proof\n"
        try:
            cosigned = cosign_checkpoint(checkpoint, signer, name, int(time.time()))
        except Exception as e:
            return 400, {}, (f"cannot cosign: {e}\n").encode()
        cosig_line = cosigned[len(checkpoint):]           # cosign_checkpoint only appends
        conn.execute("INSERT OR REPLACE INTO cosigned(origin,size,root,checkpoint,cosigned_note,cosigned_at)"
                     " VALUES(?,?,?,?,?,?)",
                     (origin, new_size, new_root, checkpoint, cosigned, int(time.time())))
        conn.commit()
    return 200, {"Content-Type": "text/plain; charset=utf-8"}, cosig_line.encode()


# ----------------------------- public GET pages -----------------------------
def _poll_meta():
    try:
        return json.load(open(POLL_PATH))
    except Exception:
        return {}


def about_text(signer, logs):
    poll = _poll_meta()
    lines = [
        WITNESS_NAME,
        "",
        "This is a C2SP transparency-log witness (https://c2sp.org/tlog-witness).",
        "It cosigns checkpoints of the logs listed below after verifying the log's",
        "signature against a pinned key and verifying that the new tree is a",
        "consistent, append-only extension of every checkpoint it has already",
        "cosigned for that log.",
        "",
        "Verifier key:",
        "",
        "  " + our_vkey(signer),
        "",
        "What a cosignature from this witness attests: at the signed timestamp,",
        "this witness saw this checkpoint, the log's signature verified against",
        "the pinned key, and the tree was consistent with everything this witness",
        "previously cosigned for that log. It attests log consistency only. It",
        "says nothing about whether the log's contents are true.",
        "",
        "Refusal rules: unknown origin -> 404. Signature that does not verify",
        "against the pinned key -> 403. Stale 'old' size -> 409 (body carries our",
        "stored size). Inconsistent tree, a different root at a size we already",
        "cosigned, or a tree smaller than one we already cosigned -> 422. State",
        "updates are atomic; this witness never cosigns two conflicting views of",
        "the same log.",
        "",
        "Endpoints:",
        "  POST https://witness.markovianprotocol.com/add-checkpoint",
        "  GET  https://witness.markovianprotocol.com/checkpoints",
        "  GET  https://witness.markovianprotocol.com/<sha256(origin) lowercase hex>/checkpoint",
        "The same endpoints are reachable under https://markovianprotocol.com/witness/...",
        "",
        "Witness Network: this witness follows the witness-network.org testing log list",
        "(transparency-dev/witness-network lists/testing/log-list.1), refreshed hourly. New logs on",
        "that list are configured automatically; a log already configured is never removed or",
        "re-keyed from a list change.",
        "",
        "Logs this witness accepts, with pinned keys:",
        "",
    ]
    for origin, vk in sorted(logs.items()):
        lines.append("  " + vk)
        meta = poll.get(origin, {})
        if origin == "markovianprotocol.com/log":
            lines.append("    our own log. DEMO: self-witnessing has no independence value;")
            lines.append("    this cosignature is excluded from the independent-witness count")
            lines.append("    the log publishes.")
        elif meta:
            lines.append(f"    polled every 15 minutes from {meta.get('monitor') or meta.get('base')}")
            lines.append(f"    key pinned from {meta.get('key_src')}")
        else:
            lines.append("    submits to us over the tlog-witness protocol")
        lines.append("")
    lines += ["Contact: hello@markovianprotocol.com", ""]
    return "\n".join(lines)


def checkpoints_text(conn, logs):
    out = ["Latest checkpoint cosigned by " + WITNESS_NAME + " for each log.",
           "Policy and verifier key: /about", ""]
    with _lock:
        rows = conn.execute("SELECT origin,size,cosigned_note,cosigned_at FROM cosigned").fetchall()
    shown = False
    for origin, size, note, ts in sorted(rows):
        if origin not in logs or not note:
            continue
        shown = True
        when = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts)) if ts else "unknown time"
        out.append(f"== {origin}  (size {size}, cosigned {when})")
        out.append(note.rstrip("\n"))
        out.append("")
    if not shown:
        out.append("(no cosigned checkpoints yet)")
    return "\n".join(out) + "\n"


# ----------------------------- HTTP server -----------------------------
def make_handler(conn, signer, logs):
    hash_to_origin = {hashlib.sha256(o.encode()).hexdigest(): o for o in logs}

    class H(BaseHTTPRequestHandler):
        def _send(self, status, body: bytes, ctype="text/plain; charset=utf-8"):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            path = self.path.split("?")[0]
            if path.startswith("/witness/"):
                path = path[len("/witness"):]
            if path.rstrip("/") != "/add-checkpoint":
                self.send_response(404); self.end_headers(); return
            n = int(self.headers.get("Content-Length", 0) or 0)
            status, headers, resp = add_checkpoint(self.rfile.read(n), conn, signer, logs)
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path.startswith("/witness/"):
                path = path[len("/witness"):]
            if path == "/health":
                return self._send(200, b"ok\n")
            if path in ("/", "", "/about"):
                return self._send(200, about_text(signer, logs).encode())
            if path == "/checkpoints":
                return self._send(200, checkpoints_text(conn, logs).encode())
            parts = path.strip("/").split("/")
            if len(parts) == 2 and parts[1] == "checkpoint" and len(parts[0]) == 64:
                origin = hash_to_origin.get(parts[0].lower())
                if origin:
                    with _lock:
                        row = conn.execute("SELECT cosigned_note FROM cosigned WHERE origin=?",
                                           (origin,)).fetchone()
                    if row and row[0]:
                        return self._send(200, row[0].encode())
                return self._send(404, b"no cosigned checkpoint for that origin\n")
            self.send_response(404); self.end_headers()

        def log_message(self, fmt, *args):
            line = "%s - %s\n" % (self.log_date_time_string(), fmt % args)
            with open(os.path.expanduser("~/markovian/witness/witness.log"), "a") as f:
                f.write(line)
    return H


def serve():
    signer = load_signer()
    logs = load_logs()
    conn = init_db()
    print(f"witness name : {WITNESS_NAME}")
    print(f"witness vkey : {our_vkey(signer)}")
    print(f"trusted logs : {list(logs)}")
    print(f"listening    : localhost:{PORT}/add-checkpoint")
    ThreadingHTTPServer(("127.0.0.1", PORT), make_handler(conn, signer, logs)).serve_forever()


# ----------------------------- self-test -----------------------------
def selftest():
    from proofbundle.checkpoint import sign_checkpoint, vkey as ckvkey, verify_cosignature
    ok = lambda c, m: print(("PASS" if c else "FAIL"), m) or (c or sys.exit(1))

    wsigner = load_signer()
    wname = "markovianprotocol.com/witness"
    wvkey = our_vkey(wsigner, wname)
    print("our witness vkey:", wvkey)

    # a fake log we will witness
    lsk = Ed25519PrivateKey.generate()
    lpub = lsk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    origin = "test.example/log"
    lvkey = ckvkey(origin, lpub)
    logs = {origin: lvkey}
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE cosigned(origin TEXT PRIMARY KEY, size INTEGER, root BLOB,"
                 " checkpoint TEXT, cosigned_note TEXT, cosigned_at INTEGER)")

    leaves = [f"leaf-{i}".encode() for i in range(50)]

    def cp(n):
        root = merkle.merkle_tree_hash(leaves[:n])
        return sign_checkpoint(origin, n, root, lsk, origin)

    def req(old, proof, checkpoint):
        h = f"old {old}\n" + "".join(base64.b64encode(p).decode() + "\n" for p in proof) + "\n"
        return (h + checkpoint).encode()

    # 1) first use: old 0, empty proof -> 200 + valid cosignature
    c10 = cp(10)
    st, hd, bd = add_checkpoint(req(0, [], c10), conn, wsigner, logs, wname)
    ok(st == 200, f"first-use 200 (got {st})")
    v = verify_cosignature(c10 + bd.decode(), wvkey)
    ok(v.get("ok"), "our cosignature verifies against our vkey")

    # 2) growth 10 -> 25 with real consistency proof -> 200
    proof = merkle.consistency_proof(leaves[:25], 10)
    c25 = cp(25)
    st, hd, bd = add_checkpoint(req(10, proof, c25), conn, wsigner, logs, wname)
    ok(st == 200, f"consistent growth 10->25 200 (got {st})")

    # 3) wrong old size -> 409 with stored size in body
    st, hd, bd = add_checkpoint(req(10, proof, c25), conn, wsigner, logs, wname)
    ok(st == 409 and bd == b"25\n" and hd.get("Content-Type") == "text/x.tlog.size",
       f"stale old -> 409 body={bd!r} ct={hd.get('Content-Type')}")

    # 4) INCONSISTENT proof 25 -> 40 (garbage proof) -> 422
    bad = [b"\x00" * 32 for _ in range(4)]
    c40 = cp(40)
    st, hd, bd = add_checkpoint(req(25, bad, c40), conn, wsigner, logs, wname)
    ok(st == 422, f"inconsistent proof -> 422 (got {st})")

    # 5) equivocation: same size 25, different root -> 422
    forked = leaves[:24] + [b"EVIL"]
    froot = merkle.merkle_tree_hash(forked)
    c25b = sign_checkpoint(origin, 25, froot, lsk, origin)
    st, hd, bd = add_checkpoint(req(25, [], c25b), conn, wsigner, logs, wname)
    ok(st == 422, f"split-view same-size different-root -> 422 (got {st})")

    # 6) unknown origin -> 404
    st, hd, bd = add_checkpoint(req(0, [], cp(5).replace(origin, "other.example/log", 1)),
                                conn, wsigner, logs, wname)
    ok(st == 404, f"unknown origin -> 404 (got {st})")

    # 7) bad signature (tamper the sig) -> 403
    tampered = c25[:-6] + "AAAAA\n"
    st, hd, bd = add_checkpoint(req(10, proof, tampered), conn, wsigner, logs, wname)
    ok(st in (400, 403), f"tampered signature -> 403/400 (got {st})")

    # 8) legitimate continued growth 25 -> 50 after the rejects -> 200 (state intact)
    proof2 = merkle.consistency_proof(leaves[:50], 25)
    c50 = cp(50)
    st, hd, bd = add_checkpoint(req(25, proof2, c50), conn, wsigner, logs, wname)
    ok(st == 200, f"resume growth 25->50 200 (got {st})")

    # 9) rollback: cosigned 50, now a signed checkpoint for size 40 with old=50 -> 400
    st, hd, bd = add_checkpoint(req(50, [], c40), conn, wsigner, logs, wname)
    ok(st == 400, f"rollback to smaller tree -> 400 (got {st})")

    # 10) the cosigned note is stored (what the monitor endpoint serves) and verifies
    row = conn.execute("SELECT cosigned_note FROM cosigned WHERE origin=?", (origin,)).fetchone()
    ok(bool(row and row[0]) and verify_cosignature(row[0], wvkey).get("ok"),
       "stored cosigned note verifies against our vkey")
    print("\nALL SELFTESTS PASSED")


if __name__ == "__main__":
    if "--serve" in sys.argv:
        serve()
    else:
        selftest()
