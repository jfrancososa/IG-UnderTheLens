from collections import Counter
from scapy.all import rdpcap, IP, Raw, TCP

#Encryption Analysis (SSL/TLS Packets):
packets = rdpcap("test.pcapng")
ssl_packets = [packet for packet in packets if TCP in packet and (packet[TCP].sport == 443 or packet[TCP].dport == 443)]
print(f"Total SSL/TLS packets (based on port 443): {len(ssl_packets)}")

#Detailed Protocol Analysis:
packets = rdpcap("test.pcapng")
protocols = [packet[IP].proto for packet in packets if IP in packet]
protocol_counts = Counter(protocols)
print(protocol_counts)

#Endpoint Communication Analysis:
ip_endpoints = [(packet[IP].src, packet[IP].dst) for packet in packets if IP in packet]
endpoints_count = Counter(ip_endpoints)
print(endpoints_count.most_common(10))

#payload analysis
payloads = [packet.load for packet in packets if Raw in packet]
for payload in payloads[:10]:
    print(payload)
    

# Time Based Traffic
import matplotlib.pyplot as plt

timestamps = [packet.time for packet in packets]
plt.plot(timestamps, range(len(timestamps)))
plt.xlabel('Time')
plt.ylabel('Packet Count')
plt.title('Packet Rates Over Time')
plt.show()

#flow analysis
from scapy.utils import PcapReader

flows = {}
for packet in PcapReader("test.pcapng"):
    if IP in packet:
        flow = (packet[IP].src, packet[IP].dst, packet[IP].proto)
        if flow not in flows:
            flows[flow] = []
        flows[flow].append(packet)

for flow, packets in flows.items():
    print(f"Flow: {flow}, Packet Count: {len(packets)}")
