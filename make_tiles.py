#!/usr/bin/env python3
"""make_tiles.py — render a Markovian log.db as static tiles per c2sp.org/tlog-tiles v0.1.0.

DRAFT. Pure stdlib. Usage:

    make_tiles.py <log.db> <outdir> [--size N]

Reads the `leaves` table (idx INTEGER PRIMARY KEY, data BLOB NOT NULL), builds:

    <outdir>/tile/<L>/<N>[.p/<W>]        Merkle tree tiles (raw concatenated 32-byte hashes)
    <outdir>/tile/entries/<N>[.p/<W>]    entry bundles (big-endian uint16 length-prefixed raw leaf bytes)

Every file is written atomically: write to a temp file in the same directory,
fsync, os.replace. Existing files whose content already matches are left
untouched (so re-runs are cheap and full tiles are never rewritten).

Spec anchors (quotes in NOTES.md):
  - "Full tiles MUST be exactly 256 hashes wide, or 8,192 bytes."
  - tile (l, n) hash i = MTH(D[(n*256+i)*256**l : (n*256+i+1)*256**l])
  - partial tile at level l for size s has floor(s/256**l) mod 256 entries;
    "Empty tiles MUST NOT be served."
  - "A partial tile ... MUST NOT be hashed into a tile at the level above."
  - N encoding: zero-padded 3-digit path elements, all but the last x-prefixed.
  - entry bundles: "sequences of big-endian uint16 length-prefixed log entries."
"""

import hashlib
import os
import sqlite3
import sys
import tempfile

TILE_H = 8            # tile height: 2**8 = 256 hashes per full tile
W = 1 << TILE_H       # 256
HASH_LEN = 32


def leaf_hash(data: bytes) -> bytes:
    """RFC 6962 sec 2.1: MTH({d}) = SHA-256(0x00 || d)."""
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 sec 2.1: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def subtree_root(hashes: list) -> bytes:
    """Root of a perfectly balanced subtree whose leaves are `hashes`.

    len(hashes) must be a power of two (we only ever roll up FULL tiles:
    "each hash in a tile is the Merkle Tree Hash of a full tile at the level
    below"). For a complete subtree the RFC 6962 MTH recursion degenerates to
    pairwise hashing, level by level.
    """
    assert len(hashes) and (len(hashes) & (len(hashes) - 1)) == 0
    level = hashes
    while len(level) > 1:
        level = [node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def tile_path(base: str, level, n: int, width: int) -> str:
    """Filesystem path for tile (level, n); level may be int or 'entries'.

    Spec: "<N> ... MUST be a non-negative integer encoded into zero-padded
    3-digit path elements. All but the last path element MUST begin with an x."
    "The .p/<W> suffix is only present for partial tiles."
    """
    elems = []
    s = str(n)
    s = "0" * ((3 - len(s) % 3) % 3) + s          # left-pad to multiple of 3
    groups = [s[i:i + 3] for i in range(0, len(s), 3)]
    elems = ["x" + g for g in groups[:-1]] + [groups[-1]]
    if width < W:
        assert 1 <= width <= 255
        elems[-1] += ".p"
        elems.append(str(width))
    return os.path.join(base, "tile", str(level), *elems)


def write_atomic(path: str, content: bytes) -> str:
    """Write content to path atomically; return 'written'/'unchanged'."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            if f.read() == content:
                return "unchanged"
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp.")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return "written"


def read_leaves(db_path: str, size=None) -> list:
    conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    rows = conn.execute("SELECT idx, data FROM leaves ORDER BY idx").fetchall()
    conn.close()
    for want, (idx, _) in enumerate(rows):
        if idx != want:
            sys.exit("FATAL: leaves not contiguous at idx %d (got %d)" % (want, idx))
    if size is not None:
        if size > len(rows):
            sys.exit("FATAL: --size %d > %d leaves in db" % (size, len(rows)))
        rows = rows[:size]
    return [bytes(d) for _, d in rows]


def make_tiles(leaves: list, outdir: str) -> dict:
    s = len(leaves)
    if s == 0:
        sys.exit("FATAL: empty log; 'Empty tiles MUST NOT be served.'")
    stats = {"written": 0, "unchanged": 0, "files": []}

    def emit(level, n, width, content):
        p = tile_path(outdir, level, n, width)
        stats[write_atomic(p, content)] += 1
        stats["files"].append(os.path.relpath(p, outdir))

    # --- entry bundles ---------------------------------------------------
    for n in range(0, (s + W - 1) // W):
        chunk = leaves[n * W:(n + 1) * W]
        parts = []
        for e in chunk:
            if len(e) > 0xFFFF:
                sys.exit("FATAL: leaf in bundle %d is %d bytes; uint16 length "
                         "prefix caps entries at 65535 bytes" % (n, len(e)))
            parts.append(len(e).to_bytes(2, "big") + e)
        emit("entries", n, len(chunk), b"".join(parts))

    # --- hash tiles, level by level -------------------------------------
    # hashes[i] at level l = MTH of the complete subtree over leaves
    # [i*256**l, (i+1)*256**l). Level 0: the leaf hashes themselves.
    level = 0
    hashes = [leaf_hash(d) for d in leaves]
    while hashes:  # floor(s / 256**level) > 0
        assert len(hashes) == s // (W ** level)
        for n in range(0, (len(hashes) + W - 1) // W):
            chunk = hashes[n * W:(n + 1) * W]
            emit(level, n, len(chunk), b"".join(chunk))
        # Roll up FULL tiles only ("A partial tile ... MUST NOT be hashed
        # into a tile at the level above").
        full = len(hashes) // W
        hashes = [subtree_root(hashes[k * W:(k + 1) * W]) for k in range(full)]
        level += 1
        if level > 63:
            sys.exit("FATAL: level > 63")
    return stats


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    size = None
    for a in sys.argv[1:]:
        if a.startswith("--size="):
            size = int(a.split("=", 1)[1])
    if len(args) != 2:
        sys.exit("usage: make_tiles.py <log.db> <outdir> [--size=N]")
    db_path, outdir = args
    leaves = read_leaves(db_path, size)
    stats = make_tiles(leaves, outdir)
    print("tree size %d -> %d files (%d written, %d unchanged)"
          % (len(leaves), len(stats["files"]), stats["written"], stats["unchanged"]))
    for f in stats["files"]:
        print("  " + f)


if __name__ == "__main__":
    main()
