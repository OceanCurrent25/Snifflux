from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import argparse
import time
from collections import defaultdict
import ipinfo

class NetworkSniffer:
    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.start_time = time.time()
        self.filter = None
        self.output_file = None
        # Initialize ipinfo handler (no token for free tier)
        self.ipinfo_handler = ipinfo.getHandler()

    def _get_ip_location(self, ip):
        try:
            details = self.ipinfo_handler.getDetails(ip)
            city = details.city or ""
            region = details.region or ""
            country = details.country_name or details.country or ""
            location = ", ".join([x for x in [city, region, country] if x])
            return location if location else "Unknown"
        except Exception:
            return "Unknown"

    def packet_callback(self, packet):
        """Process each captured packet with detailed analysis"""
        self.packet_count += 1
        protocol_label = None
        ip_src = ip_dst = None
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            src_loc = self._get_ip_location(ip_src)
            dst_loc = self._get_ip_location(ip_dst)
            proto = packet[IP].proto
            proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
            proto_name = proto_map.get(proto, str(proto))
            protocol_label = proto_name
            # ICMP
            if proto == 1 and packet.haslayer(ICMP):
                protocol_label = "ICMP"
                self.protocol_stats[protocol_label] += 1
                print(f"\nPacket #{self.packet_count}")
                print(f"IP Packet: {ip_src} ({src_loc}) -> {ip_dst} ({dst_loc}) | Protocol: {protocol_label}")
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                print(f"ICMP Packet: Type={icmp_type}, Code={icmp_code}")
                print(f"Packet size: {len(packet)} bytes")
                print("-" * 50)
                return
            # TCP
            if proto == 6 and packet.haslayer(TCP):
                tcp_sport = packet[TCP].sport
                tcp_dport = packet[TCP].dport
                # HTTP
                if packet.haslayer(HTTPRequest):
                    protocol_label = "HTTP"
                    self.protocol_stats[protocol_label] += 1
                # HTTPS (port 443)
                elif tcp_sport == 443 or tcp_dport == 443:
                    protocol_label = "HTTPS"
                    self.protocol_stats[protocol_label] += 1
                else:
                    protocol_label = "TCP"
                    self.protocol_stats[protocol_label] += 1
                print(f"\nPacket #{self.packet_count}")
                print(f"IP Packet: {ip_src} ({src_loc}) -> {ip_dst} ({dst_loc}) | Protocol: {protocol_label}")
                print(f"TCP Segment: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
                print(f"Flags: {packet[TCP].flags} | Seq: {packet[TCP].seq} | Ack: {packet[TCP].ack}")
                if protocol_label == "HTTP":
                    self._analyze_http_request(packet)
                print(f"Packet size: {len(packet)} bytes")
                print("-" * 50)
                return
            # UDP
            if proto == 17 and packet.haslayer(UDP):
                udp_sport = packet[UDP].sport
                udp_dport = packet[UDP].dport
                protocol_label = "UDP"
                self.protocol_stats[protocol_label] += 1
                print(f"\nPacket #{self.packet_count}")
                print(f"IP Packet: {ip_src} ({src_loc}) -> {ip_dst} ({dst_loc}) | Protocol: {protocol_label}")
                print(f"UDP Datagram: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")
                print(f"Length: {packet[UDP].len} | Checksum: {packet[UDP].chksum}")
                print(f"Packet size: {len(packet)} bytes")
                print("-" * 50)
                return
            # Fallback for other IP packets
            self.protocol_stats[protocol_label] += 1
            print(f"\nPacket #{self.packet_count}")
            print(f"IP Packet: {ip_src} ({src_loc}) -> {ip_dst} ({dst_loc}) | Protocol: {protocol_label}")
            print(f"Packet size: {len(packet)} bytes")
            print("-" * 50)
            return

    def _analyze_http_request(self, packet):
        """Extract and display HTTP request information"""
        http = packet[HTTPRequest]
        print("\n[HTTP Request]")
        print(f"Host: {http.Host.decode()}")
        print(f"Path: {http.Path.decode()}")
        print(f"Method: {http.Method.decode()}")
        
        # Show headers if present
        if hasattr(http, 'headers'):
            print("\nHeaders:")
            for header in http.headers.fields:
                print(f"{header.decode()}: {http.headers[header].decode()}")

    def _analyze_http_response(self, packet):
        """Extract and display HTTP response information"""
        http = packet[HTTPResponse]
        print("\n[HTTP Response]")
        print(f"Status Code: {http.Status_Code.decode()}")
        print(f"Reason Phrase: {http.Reason_Phrase.decode()}")
        
        # Show headers if present
        if hasattr(http, 'headers'):
            print("\nHeaders:")
            for header in http.headers.fields:
                print(f"{header.decode()}: {http.headers[header].decode()}")

    def display_stats(self):
        """Display capture statistics"""
        duration = time.time() - self.start_time
        print("\nCapture Statistics:")
        print(f"Total packets captured: {self.packet_count}")
        print(f"Capture duration: {duration:.2f} seconds")
        print(f"Packets per second: {self.packet_count/duration:.2f}")
        
        print("\nProtocol Distribution:")
        for proto, count in self.protocol_stats.items():
            print(f"{proto}: {count} packets ({count/self.packet_count*100:.1f}%)")

    def start_sniffing(self, interface, filter_exp=None, output_file=None):
        """Start the packet capture"""
        self.filter = filter_exp
        self.output_file = output_file
        
        print(f"\n[*] Starting sniffer on interface {interface}")
        if filter_exp:
            print(f"[*] Filter expression: {filter_exp}")
        if output_file:
            print(f"[*] Saving output to: {output_file}")
        
        sniff_params = {
            'iface': interface,
            'prn': self.packet_callback,
            'store': 0
        }
        
        if filter_exp:
            sniff_params['filter'] = filter_exp
        if output_file:
            sniff_params['offline'] = output_file
        
        try:
            sniff(**sniff_params)
        except KeyboardInterrupt:
            print("\n[*] Stopping sniffer...")
            self.display_stats()
        except Exception as e:
            print(f"[!] Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Advanced Network Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on", required=True)
    parser.add_argument("-f", "--filter", help="BPF filter expression (e.g., 'tcp port 80')", default=None)
    parser.add_argument("-o", "--output", help="Output file to save capture (.pcap format)", default=None)
    args = parser.parse_args()
    
    sniffer = NetworkSniffer()
    sniffer.start_sniffing(interface=args.interface, filter_exp=args.filter, output_file=args.output)

if __name__ == "__main__":
    main()