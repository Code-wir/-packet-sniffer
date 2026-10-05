# Packet Sniffer

A custom packet sniffer written in Python using raw sockets. Captures packets on
an interface and displays protocol, source/destination IPs, and ports in real time.

## Features

- Live packet capture with timestamps
- Decodes IPv4, identifies TCP / UDP / ICMP
- Shows source and destination ports for TCP and UDP
- Optional interface binding and packet count limit

## Requirements

- Python 3.6+
- Root/administrator privileges (raw sockets)
- Linux (`AF_PACKET`) for full L2 capture; on macOS it falls back to ICMP-only

## Usage

```bash
sudo python3 packet_sniffer.py                    # sniff all traffic
sudo python3 packet_sniffer.py --iface eth0       # specific interface
sudo python3 packet_sniffer.py --count 20         # stop after 20 packets
```

Example output:

```
14:22:01 TCP  192.168.1.5 -> 142.250.72.14 ports 52344->443
14:22:02 UDP  192.168.1.5 -> 8.8.8.8 ports 5353->53
```
