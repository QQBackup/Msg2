#!/usr/bin/env python3
"""
QQ2013 (PreloginLogic.dll / Common.dll) — reproducible pieces of the CS “IM login” stack.

Static findings (IDA, QQ2013SP6 PreloginLogic.dll):
  * Incoming CS packets are dispatched by command number wCsCmdNo; protobuf message type name is built as:
        "tencent.im.cs.cmd0x%04x.RspBody" % cmd
    see sub_6871E5C2 (CTXCSProcessor), Format(..., L"tencent.im.cs.cmd0x%x.RspBody", *v6).
  * The DynamicMessage factory parses the raw body bytes with google.protobuf (embedded runtime).
  * Prelogin path sub_6875041A reads ITXData key "bufPwdHashOne" (vtable +0x48 area) then drives
    TXEncryptMgr / seal proxy; sub_6874EE2C opens UserDataInfoStorage:\\Matrix.dat via CreateDataStorage.

You cannot derive the message-DB / ITXEncrypt session key from zero knowledge:
  * Server sends session material inside protobuf bodies (e.g. strings like buf16byteSessionKey in .rdata).
  * TXEncryptMgr::Init (Common) hashes MD5( uint32 flags || 16-byte blob ) — the 16B blob comes from
    those fields / Matrix.dat, not from algebra on UIN alone.

This module provides:
  * Exact CS RspBody type naming for offline protobuf tooling once you have .proto or captures.
  * MD5 digest matching Common’s Init input layout (see project NOTES.md §16.1).
  * A tiny protobuf wire scanner to carve unknown captures without full schema.
  * TD container parsing compatible with Common sub_300329B8 (same as MSG0 in sqlite extheader).
  * Debug endpoint host: use the same port as production, but prefix the hostname with ``debug.``
    (e.g. ``im.example.com`` → ``debug.im.example.com``). Not applied to bare IPv4/IPv6 literals.
"""

from __future__ import annotations

import hashlib
import ipaddress
import struct
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple

# Staging / debug DNS convention: same port, host becomes "debug." + original FQDN
DEBUG_HOST_PREFIX = "debug."


def debug_patched_host(production_host: str) -> str:
    """
    Return the debug-environment hostname: ``debug.`` + production hostname.

    Port is unchanged by convention — pass the same integer port as for production.

    If ``production_host`` is already prefixed or is a numeric IP address, it is returned unchanged
    (prefixing ``debug.`` before an IPv4 literal is not a valid host string).
    """
    h = production_host.strip().strip(".")
    if not h:
        raise ValueError("empty host")
    lower = h.lower()
    if lower.startswith(DEBUG_HOST_PREFIX):
        return h
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    return DEBUG_HOST_PREFIX + h


# --- CS protobuf message naming (PreloginLogic sub_6871E5C2) ---


def cs_rsp_body_typename(cmd: int) -> str:
    """Full protobuf message name used by the embedded DynamicMessage parser for *response* bodies."""
    if cmd < 0 or cmd > 0xFFFF:
        raise ValueError("cmd must be 16-bit")
    return f"tencent.im.cs.cmd0x{cmd:04x}.RspBody"


def cs_req_body_typename(cmd: int) -> str:
    """Symmetric guess for request side (ReqBody suffix appears in ecosystem; verify per build)."""
    return f"tencent.im.cs.cmd0x{cmd:04x}.ReqBody"


# Known command constants seen in strings (extend as you xref more):
CMD_PRELOGIN_0x12C = 0x12C


# --- TXEncryptMgr::Init-style digest (Common.dll, NOTES.md §16.1) ---


def md5_tx_encrypt_mgr_material(flags_le_u32: int, sixteen_byte_payload: bytes) -> bytes:
    """
    MD5( LE32(flags) || payload16 ) — output 16 bytes used as digest state for later QueryEncrypt chain.

    ``flags_le_u32`` matches the uint32 written first to MD5; ``sixteen_byte_payload`` is the
    16-byte binary block read from ITXBuffer / Matrix fields (e.g. session-related blob).
    """
    if len(sixteen_byte_payload) != 16:
        raise ValueError("payload must be exactly 16 bytes")
    h = hashlib.md5()
    h.update(struct.pack("<I", flags_le_u32 & 0xFFFFFFFF))
    h.update(sixteen_byte_payload)
    return h.digest()


# --- TD blob (MSG0 / Matrix.dat outer records), aligned with sub_300329B8 ---


def _xor_decode_name(name_len_word: int, raw: bytes) -> bytes:
    v15 = (name_len_word & 0xFF) ^ ((name_len_word >> 8) & 0xFF)
    return bytes((v15 ^ (~c & 0xFF)) & 0xFF for c in raw)


def _xor_decode_payload_type_8_9_16(payload_len_dword: int, raw: bytes) -> bytes:
    key = (payload_len_dword & 0xFF) ^ ((payload_len_dword >> 8) & 0xFF)
    return bytes((key ^ (~c & 0xFF)) & 0xFF for c in raw)


@dataclass
class TDRecord:
    typ: int
    name: str
    payload: bytes


def parse_td_document(blob: bytes) -> Tuple[int, int, List[TDRecord]]:
    """
    Parse TD container starting with b'TD', version bytes [2:4], record count uint16 LE [4:6].
    """
    if len(blob) < 6 or blob[:2] != b"TD":
        raise ValueError("not a TD blob")
    _maj, _min = blob[2], blob[3]
    nrec = struct.unpack_from("<H", blob, 4)[0]
    o = 6
    out: List[TDRecord] = []
    for _ in range(nrec):
        if o >= len(blob):
            raise ValueError("truncated TD")
        typ = blob[o]
        o += 1
        nw = struct.unpack_from("<H", blob, o)[0]
        o += 2
        nb = blob[o : o + nw]
        o += nw
        name_plain = _xor_decode_name(nw, nb).decode("utf-16-le")
        plen = struct.unpack_from("<I", blob, o)[0]
        o += 4
        pay = blob[o : o + plen]
        o += plen
        if typ in (8, 9, 0x10):
            pay = _xor_decode_payload_type_8_9_16(plen, pay)
        out.append(TDRecord(typ=typ, name=name_plain, payload=pay))
    return _maj, _min, out


# --- Minimal protobuf wire scanner (for anonymous PCAP / memory dumps) ---


WIRE_VARINT = 0
WIRE_64BIT = 1
WIRE_LEN = 2
WIRE_START_GROUP = 3
WIRE_END_GROUP = 4
WIRE_32BIT = 5


def _read_varint(buf: bytes, i: int) -> Tuple[int, int]:
    x = 0
    s = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        x |= (b & 0x7F) << s
        if not (b & 0x80):
            return x, i
        s += 7
        if s > 63:
            raise ValueError("varint too long")
    raise ValueError("truncated varint")


def iter_protobuf_fields(buf: bytes, start: int = 0, end: Optional[int] = None) -> Iterator[Tuple[int, int, object]]:
    """
    Yield (field_no, wire_type, value) where value is int for varint, bytes for len-delimited,
    float bits for 32/64-bit fixed (raw int).
    """
    i = start
    end = end if end is not None else len(buf)
    while i < end:
        key, i = _read_varint(buf, i)
        fn = key >> 3
        wt = key & 7
        if wt == WIRE_VARINT:
            v, i = _read_varint(buf, i)
            yield fn, wt, v
        elif wt == WIRE_64BIT:
            if i + 8 > end:
                raise ValueError("truncated")
            v = struct.unpack_from("<Q", buf, i)[0]
            i += 8
            yield fn, wt, v
        elif wt == WIRE_LEN:
            ln, i = _read_varint(buf, i)
            if i + ln > end:
                raise ValueError("truncated")
            chunk = buf[i : i + ln]
            i += ln
            yield fn, wt, chunk
        elif wt == WIRE_32BIT:
            if i + 4 > end:
                raise ValueError("truncated")
            v = struct.unpack_from("<I", buf, i)[0]
            i += 4
            yield fn, wt, v
        else:
            raise ValueError(f"unsupported wire type {wt} at offset {i - 1}")


def scan_protobuf_hex(blob: bytes, max_fields: int = 500) -> List[Tuple[int, str, str]]:
    """Human-readable scan lines: field_no, wire kind, value preview."""
    lines: List[Tuple[int, str, str]] = []
    for idx, (fn, wt, val) in enumerate(iter_protobuf_fields(blob)):
        if idx >= max_fields:
            break
        if wt == WIRE_LEN:
            assert isinstance(val, bytes)
            prev = val[:32].hex() + ("..." if len(val) > 32 else "")
            lines.append((fn, "LEN", prev))
        elif wt == WIRE_VARINT:
            lines.append((fn, "VARINT", str(val)))
        elif wt in (WIRE_32BIT, WIRE_64BIT):
            lines.append((fn, f"FIX{32 if wt==WIRE_32BIT else 64}", hex(val)))
        else:
            lines.append((fn, str(wt), repr(val)))
    return lines


# --- CLI ---


def _main() -> None:
    import argparse
    import json

    p = argparse.ArgumentParser(description="QQ2013 CS / TD / MD5 helpers")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_name = sub.add_parser("cs-name", help="Print protobuf type name for CS command")
    p_name.add_argument("hex_cmd", help="Command number e.g. 12c or 0x12c")

    p_md5 = sub.add_parser("md5-init", help="MD5(flags_u32 LE || 16 bytes) as in TXEncryptMgr Init")
    p_md5.add_argument("--flags", type=lambda x: int(x, 0), default=0, help="uint32 flags, default 0")
    p_md5.add_argument("--hex16", required=True, help="32 hex chars (16 bytes)")

    p_td = sub.add_parser("parse-td", help="Parse TD blob (e.g. MSG0 payload)")
    p_td.add_argument("--hex", required=True, help="hex-encoded TD bytes")

    p_pb = sub.add_parser("scan-protobuf", help="Scan raw protobuf payload (hex)")
    p_pb.add_argument("--hex", required=True)

    p_dbg = sub.add_parser(
        "debug-host",
        help='Print debug hostname (prefix "debug."), port unchanged — pass production host',
    )
    p_dbg.add_argument("production_host", help="e.g. im.qq.com (not the port)")

    args = p.parse_args()
    if args.cmd == "cs-name":
        c = int(args.hex_cmd, 16) if args.hex_cmd.lower().startswith("0x") else int(args.hex_cmd, 16)
        print(cs_rsp_body_typename(c))
        print(cs_req_body_typename(c))
    elif args.cmd == "md5-init":
        b = bytes.fromhex(args.hex16.replace(" ", ""))
        d = md5_tx_encrypt_mgr_material(args.flags, b)
        print(d.hex())
    elif args.cmd == "parse-td":
        blob = bytes.fromhex(args.hex.replace(" ", ""))
        maj, mn, recs = parse_td_document(blob)
        print(json.dumps({"version": [maj, mn], "records": [{"type": r.typ, "name": r.name, "payload_hex": r.payload.hex()} for r in recs]}, ensure_ascii=False, indent=2))
    elif args.cmd == "debug-host":
        print(debug_patched_host(args.production_host))
    else:
        blob = bytes.fromhex(args.hex.replace(" ", ""))
        for fn, kind, prev in scan_protobuf_hex(blob):
            print(fn, kind, prev)


if __name__ == "__main__":
    _main()
