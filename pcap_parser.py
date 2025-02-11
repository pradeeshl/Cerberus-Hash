from scapy.all import rdpcap
import hashlib

def parse_pcap(file_path):
    
    packets = rdpcap(file_path)
    packet_hashes = ["a77d393d861eb34e71b888e7d9a97115","258aaed0820a97f193d6d158508f53ec","44b1b326fa901873281772d00ac72928"]

    for packet in packets:
        if packet.haslayer('Raw'):  # Only extract packets with Raw payload
            payload = packet['Raw'].load
            md5_hash = hashlib.md5(payload).hexdigest()
            packet_hashes.append(md5_hash)
    
    return packet_hashes
