from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import json
from datetime import datetime

class PacketSniffer:
    def __init__(self):
        self.running = False
        self.packets = []
        self.callback = None
        self.capture_thread = None
        self.interface = None
        self.filter = None

    def packet_callback(self, packet):
        if not self.running:
            return

        packet_info = self._parse_packet(packet)
        if packet_info:
            self.packets.append(packet_info)
            if self.callback:
                self.callback(packet_info)

    def _parse_packet(self, packet):
        try:
            packet_data = {
                'timestamp': datetime.now().isoformat(),
                'length': len(packet),
                'protocol': None,
                'src': None,
                'dst': None,
                'summary': packet.summary()
            }

            if IP in packet:
                packet_data.update({
                    'src': packet[IP].src,
                    'dst': packet[IP].dst,
                })

                if TCP in packet:
                    packet_data['protocol'] = 'TCP'
                    packet_data.update({
                        'sport': packet[TCP].sport,
                        'dport': packet[TCP].dport,
                        'flags': packet[TCP].flags
                    })
                elif UDP in packet:
                    packet_data['protocol'] = 'UDP'
                    packet_data.update({
                        'sport': packet[UDP].sport,
                        'dport': packet[UDP].dport
                    })
                elif ICMP in packet:
                    packet_data['protocol'] = 'ICMP'

            return packet_data
        except Exception:
            return None

    def start_capture(self, interface=None, filter=None, callback=None):
        if self.running:
            return False

        self.interface = interface
        self.filter = filter
        self.callback = callback
        self.running = True
        self.packets = []

        def capture_thread():
            sniff(
                iface=self.interface,
                filter=self.filter,
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda _: not self.running
            )

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()
        return True

    def stop_capture(self):
        self.running = False
        if self.capture_thread:
            self.capture_thread.join()
        return {
            'packets_captured': len(self.packets),
            'packets': self.packets[-100:]  # Return last 100 packets
        }

    def get_stats(self):
        protocols = {}
        for packet in self.packets:
            proto = packet.get('protocol', 'OTHER')
            protocols[proto] = protocols.get(proto, 0) + 1

        return {
            'total_packets': len(self.packets),
            'protocols': protocols,
            'active': self.running
        }
