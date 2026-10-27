import argparse
import socket
import struct
import sys
import time
import zlib

START, END, DATA, ACK = 0, 1, 2, 3
HDR_FMT = "!IIII"
HDR_LEN = struct.calcsize(HDR_FMT)
MAX_PKT = 1472
MAX_DATA = MAX_PKT - HDR_LEN
TIMEOUT = 0.5

def make_packet(ptype, seq, data=b""):
    hdr = struct.pack(HDR_FMT, ptype, seq, len(data), 0)
    csum = zlib.crc32(hdr + data) & 0xFFFFFFFF
    return struct.pack(HDR_FMT, ptype, seq, len(data), csum) + data

def parse_packet(raw):
    if len(raw) < HDR_LEN:
        return None
    ptype, seq, length, csum = struct.unpack(HDR_FMT, raw[:HDR_LEN])
    data = raw[HDR_LEN:]
    if length != len(data) or ptype > ACK:
        return None
    hdr = struct.pack(HDR_FMT, ptype, seq, length, 0)
    if (zlib.crc32(hdr + data) & 0xFFFFFFFF) != csum:
        return None
    return ptype, seq, data

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("receiver_ip", help="IP address of the receiver")
    ap.add_argument("receiver_port", type=int, help="Port the receiver listens on")
    ap.add_argument("window_size", type=int, help="Maximum number of outstanding packets")
    args = ap.parse_args()

    dest = (args.receiver_ip, args.receiver_port)
    window = args.window_size

    message = sys.stdin.buffer.read()
    chunks = [message[i:i + MAX_DATA] for i in range(0, len(message), MAX_DATA)]
    total = len(chunks)
    packets = [make_packet(DATA, i + 1, c) for i, c in enumerate(chunks)]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    start_pkt = make_packet(START, 0)
    while True:
        sock.sendto(start_pkt, dest)
        sock.settimeout(TIMEOUT)
        try:
            raw, _ = sock.recvfrom(2048)
        except socket.timeout:
            continue
        pkt = parse_packet(raw)
        if pkt and pkt[0] == ACK and pkt[1] == 0:
            break

    acked = [False] * (total + 2)
    base = 1
    next_seq = 1
    deadline = time.monotonic() + TIMEOUT

    while base <= total:
        while next_seq <= total and next_seq < base + window:
            sock.sendto(packets[next_seq - 1], dest)
            next_seq += 1

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            for s in range(base, next_seq):
                if not acked[s]:
                    sock.sendto(packets[s - 1], dest)
            deadline = time.monotonic() + TIMEOUT
            continue

        sock.settimeout(remaining)
        try:
            raw, _ = sock.recvfrom(2048)
        except socket.timeout:
            continue
        pkt = parse_packet(raw)
        if pkt is None or pkt[0] != ACK:
            continue
        s = pkt[1]
        if base <= s < next_seq:
            acked[s] = True
            moved = False
            while base <= total and acked[base]:
                base += 1
                moved = True
            if moved:
                deadline = time.monotonic() + TIMEOUT

    end_seq = total + 1
    end_pkt = make_packet(END, end_seq)
    t_end = time.monotonic() + TIMEOUT
    next_send = 0.0
    while True:
        now = time.monotonic()
        if now >= t_end:
            break
        if now >= next_send:
            sock.sendto(end_pkt, dest)
            next_send = now + 0.1
        wait = min(next_send, t_end) - time.monotonic()
        if wait <= 0:
            continue
        sock.settimeout(wait)
        try:
            raw, _ = sock.recvfrom(2048)
        except socket.timeout:
            continue
        pkt = parse_packet(raw)
        if pkt and pkt[0] == ACK and pkt[1] == end_seq:
            break

    sock.close()

if __name__ == "__main__":
    main()
