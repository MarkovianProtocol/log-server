# SPDX-License-Identifier: Apache-2.0
"""Minimal, dependency-free CBOR (RFC 8949) encoder + decoder.

Just enough of CBOR to build and read a COSE_Sign1 SCITT receipt: unsigned and
negative integers, byte strings, text strings, arrays, maps, `nil`, and a single
tag. ~90 lines instead of a dependency, which is itself part of the "thin
adapter" claim: the whole SCITT projection is a few dozen lines of encoding over
data our log already serves.

Encoding notes (to byte-match the reference emitter, action-state-group/scitt-cose,
which uses cbor2's *default* non-canonical dumps):
  * integer / length headers are minimal (shortest form) — same as cbor2.
  * map keys are emitted in *insertion order*, NOT sorted. cbor2's default
    `dumps` preserves dict order, and the peer builds the receipt protected
    header as {395: vds} then sets {1: alg}, i.e. {395, 1} — deliberately not the
    canonical {1, 395}. We reproduce that order so our bytes match theirs.
Both choices are verified against the peer's committed test vectors.
"""
from __future__ import annotations


class Tag:
    """A CBOR tagged item (major type 6)."""

    __slots__ = ("tag", "value")

    def __init__(self, tag: int, value):
        self.tag = tag
        self.value = value

    def __repr__(self):
        return f"Tag({self.tag}, {self.value!r})"


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def dumps(x) -> bytes:
    if x is None:
        return b"\xf6"  # nil
    if x is True:
        return b"\xf5"
    if x is False:
        return b"\xf4"
    if isinstance(x, Tag):
        return _head(6, x.tag) + dumps(x.value)
    if isinstance(x, int):
        if x >= 0:
            return _head(0, x)
        return _head(1, -1 - x)
    if isinstance(x, (bytes, bytearray)):
        return _head(2, len(x)) + bytes(x)
    if isinstance(x, str):
        b = x.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(x, (list, tuple)):
        out = _head(4, len(x))
        for item in x:
            out += dumps(item)
        return out
    if isinstance(x, dict):
        out = _head(5, len(x))
        for k, v in x.items():  # insertion order, matches cbor2 default
            out += dumps(k) + dumps(v)
        return out
    raise TypeError(f"cbor_min cannot encode {type(x).__name__}")


def _dec(buf: bytes, i: int):
    """Decode one item starting at offset i; return (value, next_offset)."""
    ib = buf[i]
    major = ib >> 5
    ai = ib & 0x1F
    i += 1
    if ai < 24:
        n = ai
    elif ai == 24:
        n = buf[i]; i += 1
    elif ai == 25:
        n = int.from_bytes(buf[i:i + 2], "big"); i += 2
    elif ai == 26:
        n = int.from_bytes(buf[i:i + 4], "big"); i += 4
    elif ai == 27:
        n = int.from_bytes(buf[i:i + 8], "big"); i += 8
    else:
        # simple values / floats: only the ones we need
        if ib == 0xF6:  # nil
            return None, i
        if ib == 0xF5:
            return True, i
        if ib == 0xF4:
            return False, i
        raise ValueError(f"unsupported CBOR initial byte 0x{ib:02x}")

    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major == 2:
        return buf[i:i + n], i + n
    if major == 3:
        return buf[i:i + n].decode("utf-8"), i + n
    if major == 4:
        arr = []
        for _ in range(n):
            v, i = _dec(buf, i)
            arr.append(v)
        return arr, i
    if major == 5:
        d = {}
        for _ in range(n):
            k, i = _dec(buf, i)
            v, i = _dec(buf, i)
            d[k] = v
        return d, i
    if major == 6:
        v, i = _dec(buf, i)
        return Tag(n, v), i
    if major == 7:
        if ib == 0xF6:
            return None, i
        if ib == 0xF5:
            return True, i
        if ib == 0xF4:
            return False, i
    raise ValueError(f"unsupported CBOR major type {major}")


def loads(buf: bytes):
    """Decode a single CBOR item; raise if trailing bytes remain."""
    buf = bytes(buf)
    value, end = _dec(buf, 0)
    if end != len(buf):
        raise ValueError(f"trailing bytes after CBOR item ({len(buf) - end} extra)")
    return value
