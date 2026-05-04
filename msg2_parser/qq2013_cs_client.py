#!/usr/bin/env python3
"""
UDP/TCP client for probing QQ CS-style endpoints.

**Debug sandbox defaults (user-supplied):** ``UDP 183.60.48.174:8000``

Override with environment:

  QQ_CS_HOST          default ``183.60.48.174``
  QQ_CS_PORT          default ``8000``
  QQ_CS_UDP           ``1``/``0`` — default ``1`` (UDP). Set ``0`` for TCP.
  QQ_CS_USE_DEBUG     if ``1``, host becomes ``debug.`` + name (ignored for raw IPv4/IPv6)

There is no single plaintext ``host:port`` for the IM CS wire in PreloginLogic — this tool only
ships bytes you provide. For historical TCP literature defaults, set e.g.
``QQ_CS_HOST=tcpconn.tencent.com QQ_CS_PORT=80 QQ_CS_UDP=0``.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import time

from qq2013_cs_protocol import debug_patched_host, scan_protobuf_hex


def _env_bool(key: str, default: bool) -> bool:
    v = os.environ.get(key, "")
    if v == "":
        return default
    return v.lower() in ("1", "true", "yes", "y")


# Debug endpoint (UDP) — change via QQ_CS_*
DEFAULT_HOST = os.environ.get("QQ_CS_HOST", "183.60.48.174")
DEFAULT_PORT = int(os.environ.get("QQ_CS_PORT", "8000"))
DEFAULT_UDP = _env_bool("QQ_CS_UDP", True)


def resolve_host(raw: str, use_debug: bool) -> str:
    if use_debug:
        return debug_patched_host(raw)
    return raw


def tcp_roundtrip(host: str, port: int, payload: bytes, recv_max: int = 65536, timeout: float = 10.0) -> tuple[bytes, float]:
    addr = (host, port)
    with socket.create_connection(addr, timeout=timeout) as s:
        s.settimeout(timeout)
        t0 = time.perf_counter()
        s.sendall(payload)
        chunks: list[bytes] = []
        try:
            while True:
                b = s.recv(min(8192, recv_max - sum(len(x) for x in chunks)))
                if not b:
                    break
                chunks.append(b)
                if sum(len(x) for x in chunks) >= recv_max:
                    break
        except socket.timeout:
            pass
        elapsed = time.perf_counter() - t0
        return b"".join(chunks), elapsed


def udp_roundtrip(host: str, port: int, payload: bytes, recv_max: int = 65536, timeout: float = 10.0) -> tuple[bytes, float]:
    addr = (host, port)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        t0 = time.perf_counter()
        s.sendto(payload, addr)
        chunks: list[bytes] = []
        try:
            while sum(len(x) for x in chunks) < recv_max:
                b, _from = s.recvfrom(min(8192, recv_max - sum(len(x) for x in chunks)))
                chunks.append(b)
        except socket.timeout:
            pass
        elapsed = time.perf_counter() - t0
        return b"".join(chunks), elapsed


def main() -> None:
    p = argparse.ArgumentParser(description="UDP/TCP probe for QQ CS-related endpoints")
    p.add_argument("--host", default=None, help=f"override host (default QQ_CS_HOST / {DEFAULT_HOST})")
    p.add_argument("--port", type=int, default=None, help=f"override port (default QQ_CS_PORT / {DEFAULT_PORT})")
    p.add_argument(
        "--debug-host",
        action="store_true",
        help='use debug.<host> (QQ_CS_USE_DEBUG=1 / debug_patched_host); no-op for plain IPs',
    )
    mx = p.add_mutually_exclusive_group()
    mx.add_argument("--udp", action="store_true", help="force UDP")
    mx.add_argument("--tcp", action="store_true", help="force TCP")
    p.add_argument("--hex", default="", help="payload hex (optional; empty = zero-byte datagram/packet)")
    p.add_argument("--recv-max", type=int, default=4096)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--scan-protobuf", action="store_true", help="if response non-empty, run wire scan")
    args = p.parse_args()

    host = args.host or DEFAULT_HOST
    port = args.port if args.port is not None else DEFAULT_PORT
    use_dbg = args.debug_host or os.environ.get("QQ_CS_USE_DEBUG", "").lower() in ("1", "true", "yes")
    host = resolve_host(host, use_dbg)

    if args.udp:
        use_udp = True
    elif args.tcp:
        use_udp = False
    else:
        use_udp = DEFAULT_UDP

    payload = bytes.fromhex(args.hex.replace(" ", "")) if args.hex else b""

    proto = "udp" if use_udp else "tcp"
    print(f"{proto} {host!s}:{port} send {len(payload)} bytes", file=sys.stderr)
    try:
        if use_udp:
            data, elapsed = udp_roundtrip(host, port, payload, recv_max=args.recv_max, timeout=args.timeout)
        else:
            data, elapsed = tcp_roundtrip(host, port, payload, recv_max=args.recv_max, timeout=args.timeout)
    except OSError as e:
        print(f"ERROR {e}", file=sys.stderr)
        sys.exit(1)

    print(f"recv {len(data)} bytes in {elapsed:.3f}s", file=sys.stderr)
    if data:
        print(data.hex())
        if args.scan_protobuf:
            for fn, kind, prev in scan_protobuf_hex(data):
                print(fn, kind, prev, file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
