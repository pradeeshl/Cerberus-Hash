from datetime import datetime, timezone
from hashlib import md5
from pathlib import Path

from scapy.all import DNS, IP, IPv6, Raw, TCP, UDP, rdpcap


def _packet_timestamp(packet) -> str:
    timestamp = datetime.fromtimestamp(float(packet.time), tz=timezone.utc)
    return timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]


def _packet_endpoints(packet) -> tuple[str, str]:
    source_ip = 'unknown'
    destination_ip = 'unknown'

    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
    elif packet.haslayer(IPv6):
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    return source_ip, destination_ip


def _packet_protocol(packet) -> str:
    if packet.haslayer(DNS):
        return 'DNS'

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        if tcp_layer.sport == 445 or tcp_layer.dport == 445:
            return 'SMB'

        payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b''
        if tcp_layer.sport == 443 or tcp_layer.dport == 443 or payload.startswith(b'\x16\x03'):
            return 'TLS'

        if payload.startswith((b'GET ', b'POST ', b'HTTP/1.1', b'HTTP/1.0')):
            return 'HTTP'

        return 'TCP'

    if packet.haslayer(UDP):
        return 'UDP'

    return packet.lastlayer().name if packet.lastlayer() else 'UNKNOWN'


def _packet_info(packet, protocol: str) -> str:
    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        if getattr(dns_layer, 'qd', None) is not None:
            queried_name = getattr(dns_layer.qd, 'qname', b'')
            return f"DNS query for {queried_name.decode(errors='ignore').rstrip('.')}" if queried_name else 'DNS query'
        return 'DNS traffic'

    if protocol == 'HTTP' and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore').split('\r\n', 1)[0]
        return payload or 'HTTP payload'

    if protocol == 'TLS':
        return 'TLS Client Hello' if packet.haslayer(Raw) else 'TLS handshake'

    if protocol == 'SMB':
        return 'SMB negotiate request'

    if packet.haslayer(Raw):
        return 'Raw payload observed'

    return 'No payload'


def parse_pcap(file_path: str | Path) -> dict:
    packets = rdpcap(str(file_path))
    packet_records: list[dict] = []
    payload_hashes: list[str] = []

    for packet_index, packet in enumerate(packets, start=1):
        raw_payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b''
        payload_hash = md5(raw_payload).hexdigest() if raw_payload else None
        protocol = _packet_protocol(packet)
        source_ip, destination_ip = _packet_endpoints(packet)

        if payload_hash:
            payload_hashes.append(payload_hash)

        packet_records.append(
            {
                'packet_index': packet_index,
                'timestamp': _packet_timestamp(packet),
                'source_ip': source_ip,
                'dest_ip': destination_ip,
                'protocol': protocol,
                'length': int(len(packet)),
                'info': _packet_info(packet, protocol),
                'raw_payload': raw_payload.hex() if raw_payload else None,
                'payload_hash': payload_hash,
                'is_threat': False,
            }
        )

    return {
        'packets': packet_records,
        'packet_hashes': payload_hashes,
    }