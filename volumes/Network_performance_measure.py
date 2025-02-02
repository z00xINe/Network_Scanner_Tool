from scapy.all import IP, ICMP, sr1
import time
import statistics

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
    latencies = []
    sent_packets = 0
    received_packets = 0
    print(f"Pinging {target_ip}...")

    try:
        while True:
            start_time = time.time()
            packet = IP(dst=target_ip) / ICMP()
            response = sr1(packet, timeout=1, verbose=0)

            sent_packets += 1
            if response:
                received_packets += 1
                latency = (time.time() - start_time) * 1000
                latencies.append(latency)
                print(f"64 bytes from {target_ip}: icmp_seq={sent_packets} ttl={response.ttl} time={latency:.2f} ms")
            else:
                print(f"Request timed out for icmp_seq={sent_packets}")
            
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\nPing test stopped by user.")
        packet_loss = 100 * (1 - (received_packets / sent_packets)) if sent_packets > 0 else 0

        print(f"\n--- {target_ip} ping statistics ---")
        print(f"{sent_packets} packets transmitted, {received_packets} received, {packet_loss:.0f}% packet loss")

        return latencies

def measure_jitter(latencies):
    if len(latencies) > 1:
        return statistics.stdev(latencies)
    return 0

def ping_and_measure(target_ip, log_file="network_performance.log"):
    latencies = measure_latency(target_ip)
    jitter = measure_jitter(latencies)
    throughput, data_rate = measure_throughput_and_datarate(target_ip)

    with open(log_file, "a") as file:
        file.write(f"\n--- Network Performance Metrics for {target_ip} ---\n")
        file.write(f"Throughput: {throughput:.2f} Bytes/s\n")
        file.write(f"Data Rate: {data_rate:.2f} Mbps\n")
        file.write(f"Jitter: {jitter:.2f} ms\n")
        file.write("Latency values (ms):\n")
        for latency in latencies:
            file.write(f"{latency:.2f}\n")

    print(f"Network performance metrics for {target_ip} logged to {log_file}")

target_ip = input("Enter the target IP: ")
ping_and_measure(target_ip)
