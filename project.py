#! /usr/bin/env python3

#from scapy.all import *

def create_ethernet_packet(dst_mac, src_mac, eth_type):
    """Create an Ethernet packet."""
    ether = Ether(dst=dst_mac, src=src_mac, type=eth_type)
    return ether

def create_ip_packet(src_ip, dst_ip, ttl=64):
    """Create an IP packet."""
    ip = IP(src=src_ip, dst=dst_ip, ttl=ttl)
    return ip

def create_tcp_packet(src_port, dst_port, seq=0, ack=0, flags='S'):
    """Create a TCP packet."""
    tcp = TCP(sport=src_port, dport=dst_port, seq=seq, ack=ack, flags=flags)
    return tcp

def create_udp_packet(src_port, dst_port):
    """Create a UDP packet."""
    udp = UDP(sport=src_port, dport=dst_port)
    return udp

def create_icmp_packet(type=8, code=0):
    """Create an ICMP packet."""
    icmp = ICMP(type=type, code=code)
    return icmp

def send_packet(packet, count=1, iface=None):
    """Send a packet."""
    sendp(packet, count=count, iface=iface)

def sniff_packets(filter=None, iface=None, count=10):
    """Sniff packets."""
    packets = sniff(filter=filter, iface=iface, count=count)
    return packets

def main():
    # Create an Ethernet packet
    eth_packet = create_ethernet_packet(dst_mac="ff:ff:ff:ff:ff:ff", src_mac="00:11:22:33:44:55", eth_type=0x0800)
    print("Ethernet Packet:")
    eth_packet.show()

    # Create an IP packet
    ip_packet = create_ip_packet(src_ip="192.168.1.1", dst_ip="192.168.1.2")
    print("IP Packet:")
    ip_packet.show()

    # Create a TCP packet
    tcp_packet = create_tcp_packet(src_port=12345, dst_port=80)
    print("TCP Packet:")
    tcp_packet.show()

    # Combine Ethernet, IP, and TCP packets
    combined_packet = eth_packet / ip_packet

