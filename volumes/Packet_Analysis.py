#!/usr/bin/env python3

from scapy.all import *

def analyze_packet(packet):
    if IP in packet:  
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")

        if protocol == 6 and TCP in packet:  
            print(f"Protocol: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif protocol == 17 and UDP in packet:  
            print(f"Protocol: UDP")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
        elif protocol == 1 and ICMP in packet: 
            print(f"Protocol: ICMP")
            print(f"Type: {packet[ICMP].type}")
            print(f"Code: {packet[ICMP].code}")
        else:
            print(f"Protocol: Other (Protocol Number: {protocol})")

        print("-" * 60)

def sniffer(target_ip, interface):
    print(f"Capturing packets for IP: {target_ip}")
    sniff(filter=f"host {target_ip}", prn=analyze_packet, store=0, iface=interface)

if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ").strip()
    interface = input("Enter the network interface : ").strip()

    try:
        print("Starting packet capture...")
        sniffer(target_ip, interface)  
    except KeyboardInterrupt:
        print("\nPacket capture stopped.")
