import time
import json
from scapy.all import sniff, rdpcap

with open("config/config.json") as f:
    CONFIG = json.load(f)

class PacketSniffer:

    def __init__(self, queue):
        self.interface = CONFIG["interface"]
        self.bpf_filter = CONFIG["bpf_filter"]
        self.queue = queue

    def start_live_capture(self):
        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=self.enqueue_packet,
            store=False
        )

    def start_pcap_replay(self, pcap_file):
        packets = rdpcap(pcap_file)
        for pkt in packets:
            self.enqueue_packet(pkt)

    def enqueue_packet(self, pkt):
        # Push raw bytes and timestamp to bypass Scapy's slow serialization 
        # across the multiprocessing boundary
        try:
            raw_bytes = bytes(pkt)
            self.queue.put((time.time(), raw_bytes))
        except Exception:
            pass