import argparse
import socket
import struct
import sys
import zlib

START, END, DATA, ACK = 0, 1, 2, 3
HDR_FMT = "!IIII"
HDR_LEN = struct.calcsize(HDR_FMT)

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
    ap.add_argument("receiver_ip", help="IP address to bind to")
    ap.add_argument("receiver_port", type=int, help="Port to listen on")
    ap.add_argument("window_size", type=int, help="Maximum number of outstanding packets")
    args = ap.parse_args()
    window = args.window_size

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.receiver_ip, args.receiver_port))
    out = sys.stdout.buffer

    connected = False
    expected = 1
    buf = {}

    while True:
        raw, addr = sock.recvfrom(2048)
        pkt = parse_packet(raw)
        if pkt is None:
            continue
        ptype, seq, data = pkt

        if not connected:
            if ptype == START and seq == 0:
                connected = True
                sock.sendto(make_packet(ACK, 1), addr)
            continue

        if ptype == START:
            continue

        if ptype == DATA:
            if seq >= expected + window:
                continue
            if seq >= expected and seq not in buf:
                buf[seq] = data
            while expected in buf:
                out.write(buf.pop(expected))
                expected += 1
            sock.sendto(make_packet(ACK, expected), addr)

        elif ptype == END:
            if seq == expected:
                sock.sendto(make_packet(ACK, seq + 1), addr)
                break
            sock.sendto(make_packet(ACK, expected), addr)

    out.flush()
    sock.close()

if __name__ == "__main__":
    main()
