#! /usr/bin/env python3

from scapy.all import *
from tkinter import *
import tkinter as tk
from datetime import datetime
from threading import Thread
from tkinter import scrolledtext, messagebox, filedialog
from tkinter import messagebox, filedialog
import time
import statistics

window = Tk()


def networkDiscovery(subnet, output_text):
  if not subnet:
    messagebox.showerror("Error", "Please enter a subnet!")
    return
  
  try:
    answered_list = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=2, verbose=False)[0]
    output_text.delete(1.0, END)
    output_text.insert(END, "Active devices on the network:\n\n")
    
    for sent, received in answered_list:
      output_text.insert(END, f"'IP': {received.psrc} \t 'MAC': {received.hwsrc}\n")
  except Exception as e:
    messagebox.showerror("Error", f"An error occurred: {e}")

def guiNetworkDiscovery():
  clear_gui()
  Button(window, text="Back", command=main, width=10).pack(pady=10)
  window.title("Network Discovery Tool")

  Label(window, text="Enter subnet of network:").pack(pady=10)
  subnet_entry = Entry(window, width=40)
  subnet_entry.pack()

  Button(
    window,
    text="Discover Devices",
    command=lambda: networkDiscovery(subnet_entry.get().strip(), output_text),
  ).pack()

  Label(window, text="Output:").pack(pady=10)
  output_text = scrolledtext.ScrolledText(window, width=60, height=15)
  output_text.pack()

  window.mainloop()



def analyze_packet(packet, text_widget):
  if IP in packet:
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto

    output = []
    output.append(f"Source IP: {src_ip}")
    output.append(f"Destination IP: {dst_ip}")

  if protocol == 6 and TCP in packet:
    output.append(f"Protocol: TCP")
    output.append(f"Source Port: {packet[TCP].sport}")
    output.append(f"Destination Port: {packet[TCP].dport}")
  elif protocol == 17 and UDP in packet:
    output.append(f"Protocol: UDP")
    output.append(f"Source Port: {packet[UDP].sport}")
    output.append(f"Destination Port: {packet[UDP].dport}")
  elif protocol == 1 and ICMP in packet:
    output.append(f"Protocol: ICMP")
    output.append(f"Type: {packet[ICMP].type}")
    output.append(f"Code: {packet[ICMP].code}")
  else:
    output.append(f"Protocol: Other (Protocol Number: {protocol})")

  output.append("-" * 60)
  text_widget.insert(tk.END, "\n".join(output) + "\n")
  text_widget.see(tk.END)


def sniffer(target_ip, interface, text_widget):
  text_widget.insert(tk.END, f"Capturing packets for IP: {target_ip}\n")
  text_widget.see(tk.END)
  sniff(filter=f"host {target_ip}", prn=lambda pkt: analyze_packet(pkt, text_widget), store=0, iface=interface)


def start_sniffing(target_ip, interface, text_widget):
  sniffer_thread = Thread(target=sniffer, args=(target_ip, interface, text_widget), daemon=True)
  sniffer_thread.start()


def guiPacketAnalysis():
  clear_gui()
  Button(window, text="Back", command=main, width=10).grid(pady=10)
  window.title("Packet Sniffer")

  tk.Label(window, text="Target IP:").grid(row=1, column=0, padx=10, pady=10)
  target_ip_entry = tk.Entry(window, width=30)
  target_ip_entry.grid(row=1, column=1, padx=10, pady=10)

  tk.Label(window, text="Interface:").grid(row=2, column=0, padx=10, pady=10)
  interface_entry = tk.Entry(window, width=30)
  interface_entry.grid(row=2, column=1, padx=10, pady=10)

  text_widget = scrolledtext.ScrolledText(window, width=80, height=20)
  text_widget.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

  start_button = tk.Button(
    window, text="Start Sniffing", command=lambda: start_sniffing(
      target_ip_entry.get().strip(),
      interface_entry.get().strip(),
      text_widget
    )
  )
  start_button.grid(row=4, column=0, columnspan=2, pady=10)

  window.mainloop()



def send_ping(target_ip):
  ip_layer = IP(dst=target_ip)
  icmp_layer = ICMP()
  packet = ip_layer / icmp_layer
  response = sr1(packet, timeout=1, verbose=0)

  if response:
    messagebox.showinfo("Ping Result", f"Received response from {target_ip}: {response.summary()}")
  else:
    messagebox.showwarning("Ping Result", f"No response received from {target_ip}.")

def send_syn(target_ip, target_port):
  ip_layer = IP(dst=target_ip)
  tcp_layer = TCP(dport=target_port, flags='S')
  packet = ip_layer / tcp_layer
  response = sr1(packet, timeout=1, verbose=0)

  if response:
    if response.haslayer(TCP) and response[TCP].flags == 18:
      messagebox.showinfo("SYN Result", f"Received SYN-ACK from {target_ip} on port {target_port}")
    else:
      messagebox.showwarning("SYN Result", f"Received unexpected response: {response.summary()}")
  else:
    messagebox.showwarning("SYN Result", f"No response received from {target_ip} on port {target_port}")

def send_custom_packet(target_port, packet_type, target_ip):
  if not target_ip:
    messagebox.showerror("Error", "Please enter a valid IP address.")
    return

  if packet_type == "Ping":
    send_ping(target_ip)
  elif packet_type == "SYN":
    try:
      send_syn(target_ip, int(target_port))
    except ValueError:
      messagebox.showerror("Error", "Please enter a valid port number.")
  else:
    messagebox.showerror("Error", "Invalid packet type.")

def guiCustomPacketCreationAndTransmission():
  clear_gui()
  Button(window, text="Back", command=main, width=10).pack(pady=10)
  window.title("Custom Packet Sender")

  packet_type_var = tk.StringVar(value="Ping")
  tk.Label(window, text="Select Packet Type:").pack(anchor="w")
  tk.Radiobutton(window, text="Ping", variable=packet_type_var, value="Ping").pack(anchor="w")
  tk.Radiobutton(window, text="SYN", variable=packet_type_var, value="SYN").pack(anchor="w")

  tk.Label(window, text="Target IP Address:").pack(anchor="w")
  target_ip_entry = tk.Entry(window, width=30)
  target_ip_entry.pack(anchor="w")

  tk.Label(window, text="Target Port (for SYN):").pack(anchor="w")
  target_port_entry = tk.Entry(window, width=10)
  target_port_entry.pack(anchor="w")

  submit_button = tk.Button(
    window, text="Send Packet", command= lambda: send_custom_packet(target_port_entry.get().strip(), packet_type_var.get(), target_ip_entry.get().strip())
  )
  submit_button.pack(pady=10)

  window.mainloop()



stop_sniffing = False

def packet_callback(packet):
  global gui_log
  timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  src_ip = dst_ip = protocol = src_port = dst_port = packet_length = None

  if packet.haslayer(IP):
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = ip_layer.proto

  if packet.haslayer(TCP):
    tcp_layer = packet[TCP]
    src_port = tcp_layer.sport
    dst_port = tcp_layer.dport

  if packet.haslayer(UDP):
    udp_layer = packet[UDP]
    src_port = udp_layer.sport
    dst_port = udp_layer.dport

  packet_length = len(packet)

  gui_log.insert(tk.END, f"{timestamp} - {src_ip} -> {dst_ip} ({protocol})\n")
  gui_log.see(tk.END)


def start_sniff():
  global stop_sniffing

  def sniff_packets():
    print("Starting packet capture...")
    sniff(prn=packet_callback, store=0, stop_filter=lambda x: stop_sniffing)

  stop_sniffing = False
  sniff_thread = Thread(target=sniff_packets)
  sniff_thread.setDaemon(True)
  sniff_thread.start()
  gui_status.set("Status: Capturing packets...")


def stop_sniffing_action():
  global stop_sniffing
  stop_sniffing = True
  gui_status.set("Status: Sniffing stopped.")

def guiTrafficMonitoringAndLogging():
  global gui_log, gui_status
  clear_gui()
  Button(window, text="Back", command=main, width=10).pack(pady=10)
  window.title("Network Packet Sniffer")

  gui_status = tk.StringVar(value="Status: Ready")
  gui_log = scrolledtext.ScrolledText(window, wrap=tk.WORD, height=15, width=70)
  gui_log.pack(pady=10)

  btn_start = tk.Button (
    window, text="Start Sniffing", command=start_sniff, bg="green", fg="white"
    )
  btn_start.pack(pady=5)

  btn_stop = tk.Button(window, text="Stop Sniffing", command=stop_sniffing_action, bg="red", fg="white")
  btn_stop.pack(pady=5)

  status_label = tk.Label(window, textvariable=gui_status)
  status_label.pack(pady=10)

  window.mainloop()



def measure_throughput_and_datarate(target_ip, packet_size=1024):
  start_time = time.time()
  sent_bytes = 0

  while True:
    packet = IP(dst=target_ip) / ICMP() / (b"x" * packet_size)
    response = sr1(packet, timeout=1, verbose=0)
    sent_bytes += packet_size

    if time.time() - start_time >= 1:  # Measure throughput every 1 second
      throughput = sent_bytes / (time.time() - start_time)  # Bytes per second
      data_rate = (throughput * 8) / (10**6)  # Megabits per second
      return throughput, data_rate

def measure_latency(target_ip):
  global stop_ping
  stop_ping = False
  latencies = []
  sent_packets = 0
  received_packets = 0
  output_text.delete(1.0, tk.END)
  output_text.insert(tk.END, f"Pinging {target_ip}...\n")
  window.update()

  while not stop_ping:
    start_time = time.time()
    packet = IP(dst=target_ip) / ICMP()
    response = sr1(packet, timeout=1, verbose=0)

    sent_packets += 1
    if response:
      received_packets += 1
      latency = (time.time() - start_time) * 1000
      latencies.append(latency)
      output_text.insert(tk.END, f"64 bytes from {target_ip}: icmp_seq={sent_packets} ttl={response.ttl} time={latency:.2f} ms\n")
      window.update()
    else:
      latencies.append(None)
      output_text.insert(tk.END, f"Request timed out for icmp_seq={sent_packets}\n")
      window.update()
    
    time.sleep(1)

  output_text.insert(tk.END, "\nPing test stopped.\n")
  window.update()
  packet_loss = 100 * (1 - (received_packets / sent_packets)) if sent_packets > 0 else 0
  output_text.insert(tk.END, f"\n--- {target_ip} ping statistics ---\n")
  output_text.insert(tk.END, f"{sent_packets} packets transmitted, {received_packets} received, {packet_loss:.0f}% packet loss\n")

  return latencies


def stop_ping_action():
  global stop_ping
  stop_ping = True

def measure_jitter(latencies):
  valid_latencies = [l for l in latencies if l is not None]
  if len(valid_latencies) > 1:
    return statistics.stdev(valid_latencies)
  return 0

def ping_and_measure(target_ip):
  latencies = measure_latency(target_ip)
  jitter = measure_jitter(latencies)
  throughput, data_rate = measure_throughput_and_datarate(target_ip)

  return {
    "throughput": throughput,
    "data_rate": data_rate,
    "jitter": jitter,
    "latencies": latencies
  }


def start_ping():
  target_ip = ip_entry.get()
  if not target_ip:
    messagebox.showerror("Error", "Please enter a target IP address.")
    return

  result = ping_and_measure(target_ip)
  display_results(result)


def display_results(result):
  output_text.insert(tk.END, "--- Network Performance Metrics ---\n")
  window.update()
  output_text.insert(tk.END, f"Throughput: {result['throughput']:.2f} Bytes/s\n")
  window.update()
  output_text.insert(tk.END, f"Data Rate: {result['data_rate']:.2f} Mbps\n")
  window.update()
  output_text.insert(tk.END, f"Jitter: {result['jitter']:.2f} ms\n")
  window.update()
  output_text.insert(tk.END, "Latency values (ms):\n")
  window.update()
  for latency in result['latencies']:
    output_text.insert(tk.END, f"{latency:.2f}\n" if latency is not None else "Timeout\n")
    window.update()


def guiNetworkPerformanceMeasure():
  clear_gui()
  Button(window, text="Back", command=main, width=10).pack(pady=10)

  window.title("Network Performance Tester")
  frame = tk.Frame(window)
  frame.pack(pady=10)

  tk.Label(frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5)
  global ip_entry
  ip_entry = tk.Entry(frame, width=20)
  ip_entry.grid(row=0, column=1, padx=5, pady=5)

  start_button = tk.Button(frame, text="Start Test", command=start_ping)
  start_button.grid(row=0, column=2, padx=5, pady=5)

  stop_button = tk.Button(frame, text="Stop Test", command=stop_ping_action)
  stop_button.grid(row=0, column=3, padx=5, pady=5)

  output_frame = tk.Frame(window)
  output_frame.pack(pady=10)

  global output_text
  output_text = tk.Text(output_frame, height=30, width=100, wrap=tk.WORD)
  output_text.pack()

  window.mainloop()



def main():
  clear_gui()
  window.title("Network Scanner Tool")
  window.geometry("800x500")
  
  Button(window, text="Network Discover", command=guiNetworkDiscovery, width=50).pack(pady=30)
  Button(window, text="Packet Analysis", command=guiPacketAnalysis, width=50).pack(pady=30)
  Button(window, text="Custom Packet Creation and Transmission", command=guiCustomPacketCreationAndTransmission, width=50).pack(pady=30)
  Button(window, text="Traffic Monitoring and Logging", command=guiTrafficMonitoringAndLogging, width=50).pack(pady=30)
  Button(window, text="Network performance measure", command=guiNetworkPerformanceMeasure, width=50).pack(pady=30)
  window.mainloop()


def clear_gui():
  for widget in window.winfo_children():
    widget.destroy()


main()