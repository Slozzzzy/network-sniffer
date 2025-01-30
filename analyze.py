from scapy.all import IP, TCP, UDP, ARP

def analyze_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"

        print(f"Protocol: {protocol} | Source: {src_ip} → Destination: {dst_ip}")

    if packet.haslayer(ARP):  # Example of detecting ARP spoofing
        print(f"ARP Packet: {packet.summary()}")
