# SPDX-License-Identifier: Apache-2.0
"""RFC 6962 / RFC 9162 SHA-256 Merkle inclusion, minimal and self-contained.

Identical hashing to our live log and to the peer's clean-room merkle.py:
  * leaf hash : SHA-256(0x00 || entry_bytes)          (RFC 6962 2.1)
  * node hash : SHA-256(0x01 || left || right)
Our log's leaf entry is the RFC 8785 JCS JSON bytes served at /leaf/<i>; the audit
path is the base64 node list served at /inclusion?leaf=<i>&size=<m>, bottom-up.
"""
from __future__ import annotations

import hashlib


def leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def _node(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + l + r).digest()


def _largest_pow2_below(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root_from_inclusion(entry: bytes, index: int, tree_size: int, path: list[bytes]) -> bytes:
    """Fold a leaf up its RFC 6962 2.1.1 audit path (bottom-up) to the root."""
    if not 0 <= index < tree_size:
        raise ValueError("index out of range for tree_size")
    target = leaf_hash(entry)
    siblings = list(path)

    def fold(size: int, m: int) -> bytes:
        if size == 1:
            return target
        k = _largest_pow2_below(size)
        sib = siblings.pop()  # outermost sibling at this level
        if m < k:
            return _node(fold(k, m), sib)
        return _node(sib, fold(size - k, m - k))

    root = fold(tree_size, index)
    if siblings:
        raise ValueError("audit path longer than tree geometry requires")
    return root
