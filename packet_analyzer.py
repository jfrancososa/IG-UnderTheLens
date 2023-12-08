from scapy.all import rdpcap, IP, TCP, Raw
from collections import Counter
import matplotlib.pyplot as plt

# Read the pcap file
file_path = "test.pcapng"
packets = rdpcap(file_path)

# Analyze packet lengths
packet_lengths = [len(packet) for packet in packets]
plt.figure(figsize=(12, 6))
plt.hist(packet_lengths, bins=50, facecolor='blue', alpha=0.7)
plt.title('Packet Lengths Histogram')
plt.xlabel('Packet Length')
plt.ylabel('Frequency')
plt.show()

# Protocol Distribution
protocols = [packet[IP].proto for packet in packets if IP in packet]
protocol_counts = Counter(protocols)
plt.figure(figsize=(12, 6))
plt.bar(protocol_counts.keys(), protocol_counts.values())
plt.title('Protocol Distribution')
plt.xlabel('Protocol')
plt.ylabel('Frequency')
plt.show()

# Time Analysis (Packet rates over time)
timestamps = [packet.time for packet in packets]
plt.figure(figsize=(12, 6))
plt.plot(timestamps, range(len(timestamps)))
plt.title('Packet Rates Over Time')
plt.xlabel('Time')
plt.ylabel('Packet Count')
plt.show()

# Combined Source and Destination IP Analysis
src_ips = [packet[IP].src for packet in packets if IP in packet]
dst_ips = [packet[IP].dst for packet in packets if IP in packet]
combined_ips = src_ips + dst_ips
ip_counts = Counter(combined_ips)
common_ips_most_common = ip_counts.most_common(5)

plt.figure(figsize=(12, 6))
plt.bar([ip[0] for ip in common_ips_most_common], [ip[1] for ip in common_ips_most_common])
plt.title('Top 5 Common IPs (Source and Destination)')
plt.xlabel('IP Address')
plt.ylabel('Count')
plt.xticks(rotation=45)
plt.show()

# TCP Flag Analysis
tcp_flags = [str(packet[TCP].flags) for packet in packets if TCP in packet]
flag_counts = Counter(tcp_flags)
plt.figure(figsize=(12, 6))
plt.bar(flag_counts.keys(), flag_counts.values())
plt.title('TCP Flag Distribution')
plt.xlabel('TCP Flags')
plt.ylabel('Frequency')
plt.show()

# HTTPS Traffic Analysis
https_traffic = [pkt for pkt in packets if TCP in pkt and (pkt[TCP].sport == 443 or pkt[TCP].dport == 443)]
print(f"Total HTTPS Packets: {len(https_traffic)}")

# Packet Size Distribution for HTTPS Traffic
https_packet_sizes = [len(pkt) for pkt in https_traffic]
plt.figure(figsize=(12, 6))
plt.hist(https_packet_sizes, bins=50)
plt.title('HTTPS Packet Size Distribution')
plt.xlabel('Packet Size (bytes)')
plt.ylabel('Frequency')
plt.show()

# Payload Analysis
payloads = [packet[Raw].load for packet in packets if Raw in packet]
for payload in payloads[:10]:
    print("Payload:", payload)

# Flow Analysis
flows = {}
for packet in packets:
    if IP in packet:
        flow = (packet[IP].src, packet[IP].dst, packet[IP].proto)
        if flow not in flows:
            flows[flow] = []
        flows[flow].append(packet)

for flow, pkts in flows.items():
    print(f"Flow: {flow}, Packet Count: {len(pkts)}")
