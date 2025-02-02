#! /usr/bin/env python3

from scapy.all import *

def send_custom_packet():
    packet_type = input("Choose the type of packet to send (ping/syn): ").strip().lower()

    target_ip = input("Enter the target IP address: ").strip()

    if packet_type == "ping":
        ip_layer = IP(dst=target_ip)
        icmp_layer = ICMP()
        packet = ip_layer / icmp_layer
        response = sr1(packet, timeout=1, verbose=0)  

        if response:
            print(f"Received response from {target_ip}: {response.summary()}")
        else:
            print(f"No response received from {target_ip}.")
    
    elif packet_type == "syn":
        target_port = int(input("Enter the target port number: ").strip())
        ip_layer = IP(dst=target_ip)
        tcp_layer = TCP(dport=target_port, flags='S') 
        packet = ip_layer / tcp_layer
        response = sr1(packet, timeout=1, verbose=0)  

        if response:
            if response.haslayer(TCP):
                print(f"Received SYN-ACK from {target_ip} on port {target_port}")
            else:
                print(f"Received unexpected response: {response.summary()}")
        else:
            print(f"No response received from {target_ip} on port {target_port}")
    
    else:
        print("Invalid packet type. Please choose 'ping' or 'syn'.")

send_custom_packet()
