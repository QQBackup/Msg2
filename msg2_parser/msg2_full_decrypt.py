#!/usr/bin/env python3
"""
End-to-end Msg2.0.db buddy/content.dat decryption helper (QQ2009-era).

Requires:
  * 16-byte session key as 32 hex chars (ITXEncrypt key material from Common.dll chain).
  * Wine + native/envelope_qq2009.exe (MinGW build) for envelope sub_60402340.

Steps performed per chunk:
  * Split outer length framing (msg2_session_parse.split_content_dat).
  * Strip inner 8-byte shell (00000000 + packed marker) when present.
  * If payload starts with 0x01, strip version byte and call envelope decoder.
  * Feed buddy inner layout through parse_buddy_plain_inner (GB18030).
"""

from __future__ import annotations

import argparse
import binascii
import json
import os
import struct
import sys

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

from common_qq2009_crypto import decrypt_envelope_wine
from msg2_session_parse import parse_buddy_plain_inner, scan_packed_markers, split_content_dat


MARK_PACKED = {
    0x00003A2D,
    0x00003A2E,
    0x00003A2F,
}


def _maybe_strip_inner_shell(chunk: bytes) -> bytes:
    """Remove leading 8-byte shell 00000000 + packed marker when detected."""
    if len(chunk) < 8:
        return chunk
    z, m = struct.unpack_from("<II", chunk, 0)
    if z == 0 and m in MARK_PACKED:
        return chunk[8:]
    return chunk


def decrypt_chunk_payload(
    payload: bytes,
    key16: bytes,
    wine: str,
    envelope_exe: str | None,
    prepend_version: bool,
) -> dict:
    out: dict = {"ok": False}
    if not payload:
        out["error"] = "empty"
        return out

    trial = payload
    if prepend_version and (not trial or trial[0] != 1):
        trial = bytes([1]) + trial

    if trial[0] != 1:
        out["note"] = "first_byte_not_1_try_plain_parse"
        pr = parse_buddy_plain_inner(trial, encoding="gb18030")
        out["buddy_parse"] = pr
        out["ok"] = pr.get("text") is not None
        return out
    body = trial[1:]
    if len(body) % 8 or len(body) < 16:
        out["error"] = "bad_envelope_length"
        return out
    ok, plain = decrypt_envelope_wine(body, key16, wine_exe=wine, envelope_exe=envelope_exe)
    if not ok:
        out["error"] = "envelope_failed"
        out["stderr"] = plain.decode("utf-8", "replace")[:500]
        return out
    out["plaintext_len"] = len(plain)
    out["buddy_parse"] = parse_buddy_plain_inner(plain, encoding="gb18030")
    out["ok"] = out["buddy_parse"].get("text") is not None
    out["plaintext_preview"] = out["buddy_parse"].get("text")
    return out


def process_content_dat(
    path: str,
    key_hex: str,
    wine: str,
    envelope_exe: str | None,
    prepend_version: bool,
) -> dict:
    raw = open(path, "rb").read()
    sections, meta = split_content_dat(raw)
    try:
        key16 = binascii.unhexlify(key_hex.strip())
    except binascii.Error as e:
        raise SystemExit(f"bad --key-hex: {e}") from e
    if len(key16) != 16:
        raise SystemExit("--key-hex must decode to 16 bytes")

    report = {"content_meta": meta, "sections": []}
    for label, sec in sections:
        markers = scan_packed_markers(sec)
        payload = _maybe_strip_inner_shell(sec)
        sec_report = {
            "label": label,
            "len": len(sec),
            "markers": [{"off": o, "tag": t} for o, t in markers],
            "decrypt": decrypt_chunk_payload(
                payload, key16, wine, envelope_exe, prepend_version
            ),
        }
        report["sections"].append(sec_report)
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Decrypt Msg2.0 buddy content.dat (needs key + Wine helper).")
    p.add_argument("content_dat", help="path to buddy/.../content.dat")
    p.add_argument(
        "--key-hex",
        required=True,
        help="32 hex chars (16 bytes) session key from ITXEncrypt / runtime capture",
    )
    p.add_argument("--wine", default="wine", help="Wine executable (default: wine)")
    p.add_argument(
        "--envelope-exe",
        default=None,
        help="override path to envelope_qq2009.exe",
    )
    p.add_argument(
        "--prepend-version",
        action="store_true",
        help="prepend 0x01 version byte if missing (some on-disk layouts omit it)",
    )
    p.add_argument("--json", action="store_true", help="print JSON report")
    args = p.parse_args(argv)

    if not os.path.isfile(args.content_dat):
        print("file not found:", args.content_dat, file=sys.stderr)
        return 2

    rep = process_content_dat(
        args.content_dat,
        args.key_hex,
        args.wine,
        args.envelope_exe,
        args.prepend_version,
    )
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
