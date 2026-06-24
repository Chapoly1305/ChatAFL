#!/usr/bin/env python3
"""Replay an AFLNet replayable-queue directory against a coverage DUT.

Each file in replayable-queue/ was written by save_kl_messages_to_file() with
replay_enabled=1: a sequence of (uint32_le size, bytes) packets. This script
sends each packet via UDP to the coverage DUT and waits for a response, then
moves on.  The DUT is NOT managed here — the caller must start it (with
LLVM_PROFILE_FILE set) before invoking this script and kill it afterwards.

Usage:
  replay_queue_for_coverage.py --queue-dir DIR --port N
                               [--host 127.0.0.1] [--timeout-ms 200]
                               [--max-files N] [--verbose]
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--queue-dir", required=True, help="replayable-queue snapshot dir")
    p.add_argument("--port", required=True, type=int, help="DUT UDP port")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--timeout-ms", type=int, default=200,
                   help="per-packet recv timeout in ms (default 200)")
    p.add_argument("--max-files", type=int, default=0,
                   help="replay at most N files (0 = all)")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def parse_packets(data: bytes) -> list[bytes]:
    """Parse AFL replayable-queue file: [(uint32_le size)(bytes)...]"""
    packets: list[bytes] = []
    offset = 0
    while offset + 4 <= len(data):
        (size,) = struct.unpack_from("<I", data, offset)
        offset += 4
        if offset + size > len(data):
            break  # truncated packet — skip silently
        packets.append(data[offset: offset + size])
        offset += size
    return packets


def main() -> int:
    args = parse_args()
    queue_dir = Path(args.queue_dir)
    if not queue_dir.is_dir():
        print(f"[replay] queue dir not found: {queue_dir}", file=sys.stderr)
        return 1

    files = sorted(queue_dir.iterdir())
    if args.max_files > 0:
        files = files[: args.max_files]

    if not files:
        print("[replay] queue dir is empty — no packets to replay")
        return 0

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout_ms / 1000.0)
    addr = (args.host, args.port)

    sent_files = 0
    sent_pkts = 0
    errors = 0

    for f in files:
        if not f.is_file():
            continue
        try:
            data = f.read_bytes()
        except OSError:
            continue  # file disappeared mid-copy

        packets = parse_packets(data)
        if not packets:
            continue

        for pkt in packets:
            try:
                sock.sendto(pkt, addr)
                try:
                    sock.recvfrom(65535)
                except socket.timeout:
                    pass  # DUT may not respond to every packet
                sent_pkts += 1
            except OSError as e:
                errors += 1
                if args.verbose:
                    print(f"[replay] send error on {f.name}: {e}", file=sys.stderr)

        sent_files += 1
        if args.verbose:
            print(f"[replay] {f.name}: {len(packets)} packets")

    sock.close()
    print(f"[replay] done: {sent_files} files, {sent_pkts} packets, {errors} errors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
