#!/usr/bin/env python3
"""
Experimental: use raw bytes from UserDataMsgStorage Matrix.dat (TD 54 44 01 01) as
key material for standard XXTEA (https://github.com/xxtea/xxtea-c) and try to
decrypt buddy content.dat ciphertext.

The real QQ 2010 path is TXEncryptMgr (MD5 Init, optional Seal, sub_30002340
envelope) — this script is a *sanity check* that the on-disk Matrix alone is
not enough with a single XXTEA block. See printed report.
"""

from __future__ import annotations

import hashlib
import math
import struct
import sys
from pathlib import Path
from typing import Iterable, List, Tuple

DELTA = 0x9E3779B9


def _mx(z: int, y: int, sum_: int, p: int, e: int, k: List[int]) -> int:
    return (
        ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4))
        ^ ((sum_ ^ y) + (k[(p & 3) ^ e] ^ z))
    ) & 0xFFFFFFFF


def xxtea_decrypt_block(ct8: bytes, key16: bytes) -> bytes:
    """Decrypt one 8-byte block (n=2 words)."""
    if len(ct8) != 8 or len(key16) != 16:
        raise ValueError("need 8-byte block and 16-byte key")
    v = list(struct.unpack("<2I", ct8))
    k = list(struct.unpack("<4I", key16))
    n = 1  # len(v) - 1
    q = 6 + 52 // (n + 1)
    sum_ = (q * DELTA) & 0xFFFFFFFF
    while sum_:
        e = (sum_ >> 2) & 3
        for p in range(n, 0, -1):
            z = v[p - 1]
            y = v[p]
            v[p] = (y - _mx(z, y, sum_, p, e, k)) & 0xFFFFFFFF
        z = v[n]
        y = v[0]
        v[0] = (y - _mx(z, y, sum_, 0, e, k)) & 0xFFFFFFFF
        sum_ = (sum_ - DELTA) & 0xFFFFFFFF
    return struct.pack("<2I", *v)


def xxtea_decrypt_block_be_words(ct8: bytes, key16: bytes) -> bytes:
    """Same but ciphertext interpreted as big-endian 32-bit pairs (NOTES: byteswap ulong)."""
    v0 = struct.unpack_from(">I", ct8, 0)[0]
    v1 = struct.unpack_from(">I", ct8, 4)[0]
    ct_le = struct.pack("<2I", v0, v1)
    pt_le = xxtea_decrypt_block(ct_le, key16)
    o0, o1 = struct.unpack("<2I", pt_le)
    return struct.pack(">II", o0, o1)


def md5_digest(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


def candidate_keys(matrix: bytes) -> Iterable[Tuple[str, bytes]]:
    """Yield (label, 16-byte key) guesses from Matrix.dat blob."""
    yield ("zeros", b"\x00" * 16)
    for off in range(0, max(1, len(matrix) - 15)):
        yield (f"raw_off_{off:03d}", matrix[off : off + 16])
    # TXEncryptMgr::Init style: MD5(4-byte flag || 16-byte material) -> 16 bytes as key material
    for fl in (0, 1, 2, 3):
        flag = struct.pack("<I", fl)
        for off in range(0, max(1, len(matrix) - 15)):
            material = matrix[off : off + 16]
            d = md5_digest(flag + material)
            yield (f"md5_flag{fl}_off_{off:03d}", d)


def first_cipher_after_marker(chunk: bytes) -> bytes | None:
    """Find first '-:' marker (2d3a0000) and return following 8 bytes if present."""
    needle = struct.pack("<I", 0x00003A2D)
    idx = chunk.find(needle)
    if idx < 0:
        return None
    start = idx + 4
    if start + 8 > len(chunk):
        return None
    return chunk[start : start + 8]


def ascii_printable_ratio(blob: bytes) -> float:
    if not blob:
        return 0.0
    return sum(1 for b in blob if 32 <= b < 127) / len(blob)


def byte_entropy(b: bytes) -> float:
    if not b:
        return 0.0
    freq = [0] * 256
    for x in b:
        freq[x] += 1
    ent = 0.0
    n = len(b)
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    matrix_path = root / "msg2.0" / "Matrix.dat"
    content_path = root / "msg2.0" / "buddy" / "1002598880" / "content.dat"
    if "--matrix" in sys.argv:
        i = sys.argv.index("--matrix")
        matrix_path = Path(sys.argv[i + 1])
    if "--content" in sys.argv:
        i = sys.argv.index("--content")
        content_path = Path(sys.argv[i + 1])

    matrix = matrix_path.read_bytes()
    ct_full = content_path.read_bytes()
    first_u32 = struct.unpack_from("<I", ct_full, 0)[0]
    chunk1 = ct_full[4 : 4 + first_u32] if len(ct_full) >= 4 + first_u32 else ct_full[4:]

    block = first_cipher_after_marker(chunk1)
    print("Matrix:", matrix_path, "bytes", len(matrix), "magic", matrix[:4].hex())
    print("Content:", content_path, "outer_u32", first_u32, "chunk1_len", len(chunk1))
    print("First 8-byte cipher block after '-:'", block.hex() if block else None)

    if not block:
        print("No marker — abort.")
        return 1

    print("\n--- XXTEA single-block tries (standard xxtea-c, LE ciphertext) ---")
    best: List[Tuple[float, str, bytes]] = []
    for label, key in candidate_keys(matrix):
        try:
            pt = xxtea_decrypt_block(block, key)
            pt_be = xxtea_decrypt_block_be_words(block, key)
        except Exception:
            continue
        for variant, out in (("LE", pt), ("BE_blk", pt_be)):
            # Prefer readable ASCII (buddy plaintext is mostly GBK — needs multi-byte block chain).
            score = ascii_printable_ratio(out)
            best.append((score, f"{label}/{variant}", out))
    best.sort(key=lambda x: -x[0])
    for score, label, out in best[:12]:
        print(
            f"ascii_ratio={score:.3f} entropy={byte_entropy(out):.2f} bits/byte "
            f"{label} pt_hex={out.hex()}"
        )

    print("\n--- Same top entries as UTF-8 / GB18030 preview (usually garbage) ---")
    for score, label, out in best[:5]:
        print(label, "utf-8", out.decode("utf-8", errors="replace"))

    print(
        "\nConclusion: Matrix.dat holds TD records + key blobs but session ciphertext"
        " is not one XXTEA ECB block under raw slices or MD5(flag||slice)."
        " Expect TXEncryptMgr::Init / Seal / sub_30002340 envelope + ITXEncrypt."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
