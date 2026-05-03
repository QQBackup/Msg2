#!/usr/bin/env python3
"""
QQ2009 Common.dll primitives for Msg2.0 ciphertext:

  * xxtea_60401cf0_block — same arithmetic as native/envelope_qq2009.c (sub_60401CF0).
  * decrypt_envelope_wine — delegates envelope decode (sub_60402340) to MinGW EXE + Wine.

Offline decryption requires the 16-byte ITXEncrypt session key (same as Common.dll object +0x1F).
That material is produced only after TXEncryptMgr/Matrix/login bind; it is **not** derivable from
Msg2.0.db + Matrix.dat alone in the general case — supply `--key-hex` from a trusted capture
(调试器 / 迁移工具 / 运行时导出).
"""

from __future__ import annotations

import binascii
import os
import shutil
import struct
import subprocess
import tempfile
from typing import Optional, Tuple

SUM0 = 0xE3779B90
DELTA = 0x61C88647


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _bswap32(x: int) -> int:
    return int.from_bytes(struct.pack("<I", x)[::-1], "little")


def xxtea_60401cf0_block(block8: bytes, key16: bytes) -> bytes:
    """Bit-compatible with sub_60401CF0 in native/envelope_qq2009.c."""
    if len(block8) != 8 or len(key16) != 16:
        raise ValueError("bad block/key size")
    v8 = [_bswap32(struct.unpack_from("<I", key16, i)[0]) for i in range(0, 16, 4)]
    v4 = _bswap32(struct.unpack_from("<I", block8, 0)[0])
    v5 = _bswap32(struct.unpack_from("<I", block8, 4)[0])
    v6 = SUM0
    rounds = 16
    while rounds:
        t0 = _u32(v6 + v4)
        t1 = _u32(v8[2] + _u32(v4 << 4))
        t2 = _u32(v8[3] + (v4 >> 5))
        t3 = _u32(t0 ^ _u32(t1 ^ t2))
        v5 = _u32(v5 - t3)

        u0 = _u32(v6 + v5)
        u1 = _u32(v8[0] + _u32(v5 << 4))
        u2 = _u32(v8[1] + (v5 >> 5))
        u3 = _u32(u0 ^ _u32(u1 ^ u2))
        v4 = _u32(v4 - u3)

        v6 = _u32(v6 + DELTA)
        rounds -= 1
    return struct.pack("<II", _bswap32(v4), _bswap32(v5))


def _default_envelope_exe() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "native", "envelope_qq2009.exe")


def decrypt_envelope_wine(
    cipher_body: bytes,
    key16: bytes,
    wine_exe: str = "wine",
    envelope_exe: Optional[str] = None,
) -> Tuple[bool, bytes]:
    """
    Run native envelope decoder (sub_60402340). cipher_body must NOT include the 0x01 version byte.
    """
    if len(key16) != 16:
        raise ValueError("key must be 16 bytes")
    exe = envelope_exe or _default_envelope_exe()
    if not os.path.isfile(exe):
        raise FileNotFoundError(f"envelope tool missing: {exe} — build native/envelope_qq2009.c")
    if shutil.which(wine_exe) is None:
        raise EnvironmentError(f"'{wine_exe}' not found — install Wine to run the PE helper")

    kh = binascii.hexlify(key16).decode("ascii")
    ch = binascii.hexlify(cipher_body).decode("ascii")
    try:
        proc = subprocess.run(
            [wine_exe, exe, kh, ch],
            capture_output=True,
            timeout=120,
            check=False,
        )
    except FileNotFoundError as e:
        raise EnvironmentError(str(e)) from e

    if proc.returncode != 0:
        return False, (proc.stderr or b"") + (proc.stdout or b"")

    return True, proc.stdout or b""
