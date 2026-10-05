#!/usr/bin/env python3
"""Custom packet sniffer: captures packets on an interface and prints protocol, src/dst IPs, and summary."""

import argparse
import socket
import struct
from datetime import datetime

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}


def parse_ethernet(data):
    dest, src, proto = struct.unpack("!6s6sH", data[:14])
    return dest.hex(":"), src.hex(":"), proto, data[14:]


def parse_ipv4(data):
    ihl = (data[0] & 0x0F) * 4
    src, dst = socket.inet_ntoa(data[12:16]), socket.inet_ntoa(data[16:20])
    return src, dst, data[9], data[ihl:]


def parse_tcp(data):
    src_port, dst_port = struct.unpack("!HH", data[:4])
    return src_port, dst_port, PROTOCOLS.get(6, "TCP")


def parse_udp(data):
    src_port, dst_port = struct.unpack("!HH", data[:4])
    return src_port, dst_port, "UDP"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iface", default=None, help="Interface to sniff on (default: all)")
    p.add_argument("--count", type=int, default=0, help="Number of packets (0 = unlimited)")
    args = p.parse_args()

    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) if hasattr(socket, "AF_PACKET") else socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    if args.iface:
        sniffer.bind((args.iface, 0))

    seen = 0
    try:
        while True:
            raw, _ = sniffer.recvfrom(65535)
            if hasattr(socket, "AF_PACKET"):
                _, _, proto, payload = parse_ethernet(raw)
                if proto != 0x0800:
                    continue
                ip_data = payload
            else:
                ip_data = raw
            src, dst, proto_num, transport = parse_ipv4(ip_data)
            proto = PROTOCOLS.get(proto_num, str(proto_num))
            ts = datetime.now().strftime("%H:%M:%S")
            line = f"{ts} {proto:4} {src} -> {dst}"
            if proto_num == 6:
                sp, dp, _ = parse_tcp(transport)
                line += f" ports {sp}->{dp}"
            elif proto_num == 17:
                sp, dp, _ = parse_udp(transport)
                line += f" ports {sp}->{dp}"
            print(line)
            seen += 1
            if args.count and seen >= args.count:
                break
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.close()


if __name__ == "__main__":
    main()
