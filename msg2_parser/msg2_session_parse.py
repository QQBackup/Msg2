#!/usr/bin/env python3
"""
Parse QQ 2010-era Msg2.0.db per-session streams exported as files:
  buddy/<UIN>/index.dat
  buddy/<UIN>/content.dat

Findings from IM.dll reverse-engineering + on-disk samples:

  index.dat — fixed records, each 8 bytes:
    UTF-16 LE 2-char tag (4 bytes) + uint32 LE value.
    Observed tags (wchar): "-:", ".:", "/:" (ASCII punctuation + colon).

  content.dat — length-prefixed sections; ciphertext after framing unless a
    Matrix.dat / TXEncryptMgr session key is applied (out of scope here).

Buddy plaintext layout once decrypted/unwrapped to the blob passed to the
buddy parser (see sub_3102E8F0): at inner pointer v6:

  [0:4]   opaque / reserved
  [4]     uint8 flag (used with ITXData "bSelfMsg"; encoding selector is *not*
          stored here — caller passes GBK vs BIG5 via another arg)
  [5:9]   int32 LE text byte length L (unaligned load in original binary)
  [9:9+L] message text bytes (historically GBK or BIG5)
  then optional chained segments: int32 len + len bytes (fed into ITXBuffer)

References: IM.dll ImageBase 0x31000000 — sub_3102E8F0, sub_3102FDB0.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import dataclass
from typing import Iterator, List, Optional, Sequence, Tuple


# Packed 32-bit markers (little-endian): low bytes are ASCII "<punct><colon>".
# Example: '-:' -> bytes 2d 3a 00 00 -> uint32 LE 0x00003a2d (NOT UTF-16 wchar pair).
MARK_U32 = {
    0x00003A2D: "-:",
    0x00003A2E: ".:",
    0x00003A2F: "/:",
}


@dataclass(frozen=True)
class IndexEntry:
    tag: str
    value: int


def u32_to_marker_tag(word: int) -> str:
    return MARK_U32.get(word & 0xFFFFFFFF, f"u32_0x{word & 0xFFFFFFFF:08x}")


def parse_index_dat(raw: bytes) -> List[IndexEntry]:
    """
    Parse index.dat as records of (uint32 marker, uint32 value), 8 bytes each.

    Known markers use packed ASCII in the low 16 bits (see MARK_U32).
    """
    if len(raw) % 8 != 0:
        raise ValueError(f"index.dat length {len(raw)} not multiple of 8")
    out: List[IndexEntry] = []
    off = 0
    while off + 8 <= len(raw):
        mark, value = struct.unpack_from("<II", raw, off)
        out.append(IndexEntry(u32_to_marker_tag(mark), value))
        off += 8
    return out


def parse_index_dat_relaxed(raw: bytes) -> dict:
    """Like parse_index_dat but falls back to raw u32 words if size not ×8."""
    if len(raw) % 8 == 0:
        try:
            entries = parse_index_dat(raw)
            return {"kind": "marker_u32_pairs", "entries": [(e.tag, e.value) for e in entries]}
        except Exception as e:
            return {"kind": "error", "error": str(e), "hex": raw.hex()}
    if len(raw) % 4 == 0:
        return {
            "kind": "raw_u32",
            "values": list(struct.unpack(f"<{len(raw)//4}I", raw)),
        }
    return {"kind": "opaque", "hex": raw.hex()}


def parse_marker_u32(data: bytes, off: int) -> Tuple[str, int]:
    """Read uint32 marker word + uint32 value at offset off."""
    (w, val) = struct.unpack_from("<II", data, off)
    return u32_to_marker_tag(w), val


def split_content_dat(raw: bytes) -> Tuple[List[Tuple[str, bytes]], dict]:
    """
    Split content.dat into logical sections.

    Two regimes observed:
      A) Single-chunk file: first u32 == len(raw). Payload is raw[4:].
      B) Multi-chunk: first u32 == L1 < len(raw). First body raw[4:4+L1],
         remainder raw[4+L1:] is another section whose layout still begins with
         zeros + UTF-16 marker ".:" in samples.

    Returns (sections, meta) where each section is (label, payload_bytes).
    """
    if len(raw) < 4:
        raise ValueError("content.dat too small")
    first_len = struct.unpack_from("<I", raw, 0)[0]
    meta: dict = {"first_u32": first_len, "file_len": len(raw)}

    # Regime A — entire file is one outer length field
    if first_len == len(raw):
        payload = raw[4:]
        meta["mode"] = "single_outer"
        sections: List[Tuple[str, bytes]] = [("outer", payload)]
        return sections, meta

    meta["mode"] = "multi_outer"
    if len(raw) < 4 + first_len:
        raise ValueError("truncated first section")
    sec1 = raw[4 : 4 + first_len]
    tail = raw[4 + first_len :]
    sections = [("chunk1", sec1)]
    if tail:
        sections.append(("chunk2+", tail))
    return sections, meta


def iter_inner_tlv_segments(blob: bytes, start: int = 0) -> Iterator[Tuple[int, bytes]]:
    """
    Iterator over int32-length–prefixed segments (buddy tail chain in
    sub_3102E8F0 after the primary GBK run).
    """
    pos = start
    while pos + 4 <= len(blob):
        ln = struct.unpack_from("<i", blob, pos)[0]
        if ln <= 0:
            break
        pos += 4
        if pos + ln > len(blob):
            raise ValueError(f"segment overrun pos={pos} len={ln} total={len(blob)}")
        yield ln, blob[pos : pos + ln]
        pos += ln


def parse_buddy_plain_inner(blob: bytes, encoding: str = "gb18030") -> dict:
    """
    Parse decrypted buddy inner blob per sub_3102E8F0.

    `encoding` should be "gb18030" or "big5hkscs" depending on client locale.
    """
    if len(blob) < 9:
        return {"error": "too_short", "raw_len": len(blob)}

    flag = blob[4]
    text_len = struct.unpack_from("<i", blob, 5)[0]
    if text_len < 0 or 9 + text_len > len(blob):
        return {
            "error": "bad_text_len",
            "flag": flag,
            "text_len": text_len,
            "raw_len": len(blob),
        }

    raw_text = blob[9 : 9 + text_len]
    try:
        text = raw_text.decode(encoding)
    except UnicodeDecodeError as e:
        text = None
        decode_err = str(e)
    else:
        decode_err = None

    tail_start = 9 + text_len
    extras: List[bytes] = []
    try:
        for _ln, seg in iter_inner_tlv_segments(blob, tail_start):
            extras.append(seg)
    except ValueError:
        extras = []

    return {
        "flag_byte": flag,
        "text_len": text_len,
        "text": text,
        "decode_error": decode_err,
        "extras_count": len(extras),
        "extras_preview_hex": [x[:32].hex() for x in extras[:5]],
    }


def scan_packed_markers(blob: bytes) -> List[Tuple[int, str]]:
    """Find packed uint32 markers (aligned to 4 bytes)."""
    hits: List[Tuple[int, str]] = []
    for i in range(0, len(blob) - 3, 4):
        (w,) = struct.unpack_from("<I", blob, i)
        if w in MARK_U32:
            hits.append((i, MARK_U32[w]))
    return hits


def analyze_session(index_path: str, content_path: str) -> dict:
    idx_raw = open(index_path, "rb").read()
    ct_raw = open(content_path, "rb").read()

    index_parsed = parse_index_dat_relaxed(idx_raw)
    sections, meta = split_content_dat(ct_raw)

    analysis = {
        "index": index_parsed,
        "content_meta": meta,
        "sections": [],
    }

    for label, sec in sections:
        markers = scan_packed_markers(sec)
        analysis["sections"].append(
            {
                "label": label,
                "len": len(sec),
                "markers": [{"off": o, "tag": t} for o, t in markers],
                "head_hex": sec[:48].hex(),
            }
        )

    # Cross-check multi-file: ".:" / "/:" values vs lengths
    if meta.get("mode") == "multi_outer" and index_parsed.get("kind") == "marker_u32_pairs":
        d = {t: v for t, v in index_parsed["entries"]}
        fl = meta["first_u32"]
        if ".:" in d and d[".:"] == fl:
            analysis["cross_check"] = "first_chunk_len_matches_index_.:"
        if "/:" in d:
            tail_len = len(ct_raw) - 4 - fl
            if d["/:"] == tail_len + 4:
                analysis["cross_check_tail"] = "/:_value_matches_tail_plus_4"
            elif d["/:"] == tail_len:
                analysis["cross_check_tail"] = "/:_value_matches_tail"

    return analysis


def self_test() -> None:
    inner = bytearray()
    inner += struct.pack("<I", 0)
    inner.append(0)
    txt = "你好".encode("gb18030")
    inner += struct.pack("<i", len(txt))
    inner += txt
    res = parse_buddy_plain_inner(bytes(inner))
    assert res.get("text") == "你好", res
    print("self_test OK:", res["text"])


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Parse Msg2.0 buddy index/content framing.")
    p.add_argument("index_dat", nargs="?", default=None)
    p.add_argument("content_dat", nargs="?", default=None)
    p.add_argument(
        "--demo-inner",
        metavar="HEX",
        help="optional synthetic inner buddy blob (hex) to run parse_buddy_plain_inner",
    )
    p.add_argument(
        "--self-test",
        action="store_true",
        help="run synthetic buddy-inner decode (GB18030 你好)",
    )
    args = p.parse_args(list(argv) if argv is not None else None)

    if args.self_test:
        self_test()
        return 0

    if args.demo_inner:
        blob = bytes.fromhex(args.demo_inner.replace(" ", ""))
        print(json.dumps(parse_buddy_plain_inner(blob), ensure_ascii=False, indent=2))
        return 0

    if not args.index_dat or not args.content_dat:
        p.error("index_dat and content_dat are required unless --self-test or --demo-inner")

    print(json.dumps(analyze_session(args.index_dat, args.content_dat), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
