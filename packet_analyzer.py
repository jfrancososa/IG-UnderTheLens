from scapy.all import rdpcap
import matplotlib.pyplot as plt

# Read the pcap file
file_path = "test.pcapng"
packets = rdpcap(file_path)

# Analyze packet lengths
packet_lengths = [len(packet) for packet in packets]

# Plot histogram of packet lengths
plt.hist(packet_lengths, bins=50, facecolor='blue', alpha=0.7)
plt.title('Packet Lengths Histogram')
plt.xlabel('Packet Length')
plt.ylabel('Frequency')
plt.grid(True)
plt.show()
