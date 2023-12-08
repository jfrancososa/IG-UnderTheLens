from scapy.all import *
from collections import Counter
import matplotlib.pyplot as plt
# Reading the pcap file
file_path = "test.pcapng"
packets = rdpcap(file_path)
# Create a single figure
fig, axs = plt.subplots(6, figsize=(15, 20))
fig.tight_layout(pad=5.0)
# Analyze packet lengths
packet_lengths = [len(packet) for packet in packets]
axs[0].hist(packet_lengths, bins=50, facecolor='blue', alpha=0.7)
axs[0].set_title('Packet Lengths Histogram')
axs[0].set_xlabel('Packet Length')
axs[0].set_ylabel('Frequency')
# Protocol Distribution
protocols = [packet[IP].proto for packet in packets if IP in packet]
protocol_counts = Counter(protocols)
axs[1].bar(protocol_counts.keys(), protocol_counts.values())
axs[1].set_title('Protocol Distribution')
axs[1].set_xlabel('Protocol')
axs[1].set_ylabel('Frequency')
# Time Analysis (Packet rates over time)
timestamps = [packet.time for packet in packets]
axs[2].plot(timestamps, range(len(timestamps)))
axs[2].set_title('Packet Rates Over Time')
axs[2].set_xlabel('Time')
axs[2].set_ylabel('Packet Count')
# Source IP Analysis
src_ips = [packet[IP].src for packet in packets if IP in packet]
src_counts = Counter(src_ips)
src_common = src_counts.most_common(5)
src_ips = [ip[0] for ip in src_common]
src_vals = [ip[1] for ip in src_common]
axs[3].bar(src_ips, src_vals)
axs[3].set_title('Top 5 Source IPs')
axs[3].set_xlabel('Source IP')
axs[3].set_ylabel('Count')
axs[3].tick_params(axis='x', rotation=45)
# Destination IP Analysis
dst_ips = [packet[IP].dst for packet in packets if IP in packet]
dst_counts = Counter(dst_ips)
dst_common = dst_counts.most_common(5)
dst_ips = [ip[0] for ip in dst_common]
dst_vals = [ip[1] for ip in dst_common]
axs[4].bar(dst_ips, dst_vals)
axs[4].set_title('Top 5 Destination IPs')
axs[4].set_xlabel('Destination IP')
axs[4].set_ylabel('Count')
axs[4].tick_params(axis='x', rotation=45)
# TCP Flag Analysis
tcp_flags = [str(packet[TCP].flags) for packet in packets if TCP in packet]
flag_counts = Counter(tcp_flags)
axs[5].bar(flag_counts.keys(), flag_counts.values())
axs[5].set_title('TCP Flag Distribution')
axs[5].set_xlabel('TCP Flags')
axs[5].set_ylabel('Frequency')
# Display the figure with all subplots
plt.show()
