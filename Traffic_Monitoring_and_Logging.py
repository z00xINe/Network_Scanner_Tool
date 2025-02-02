#! /usr/bin/env python3




from scapy.all import *
import csv
from datetime import datetime

# Define the CSV file and write the header
csv_file = "network_traffic.csv"
with open(csv_file, "w", newline="") as f:
    writer = csv.writer(f)
    # Write the header for the CSV file
    writer.writerow(["Timestamp", "Source IP", "Destination IP", 
                     "Protocol", "Source Port", "Destination Port","Packet Length", "Summary"])

def packet_callback(packet):
    """
    Callback function to process and log packet details to a CSV file.
    Args:
        packet: Captured packet.
    """
    # Extract timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = dst_ip = protocol = src_port = dst_port =packet_length = None

    # Extract IP layer details
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

    # Extract TCP layer details
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport

    # Extract UDP layer details
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        src_port = udp_layer.sport
        dst_port = udp_layer.dport



    packet_length = len(packet)
    # Write details to the CSV file
    with open(csv_file, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            timestamp, src_ip, dst_ip, protocol, 
            src_port, dst_port, packet_length,packet.summary()

        ])

def main():
    # Start sniffing the network
    print("Starting packet capture. Press Ctrl+C to stop.")
    try:
        # Start sniffing without specifying the interface; Scapy will automatically choose the best one
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("Packet capture stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

