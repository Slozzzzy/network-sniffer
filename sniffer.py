from scapy.all import sniff, ARP, wrpcap
from analyze import analyze_packet  # Import function from analyze.py
import time, os
from GetIface import get_network_interfaces

save_dir = os.path.join(os.getcwd(), "captured_packets")
os.makedirs(save_dir, exist_ok=True)

packets =[]
show_iface = ', '.join(get_network_interfaces()) #display all the available network interfaces
print('Select your network interface (as 0, 1, 2, so on) : ' + show_iface)
selected_face = input()
if (int(selected_face) < 0 or int(selected_face) > len(get_network_interfaces())) : #simple error handling
    exit()
iface = get_network_interfaces()[int(selected_face)] 

def packet_callback(packet):
    analyze_packet(packet)
    packets.append(packet)  # Add packet to list
    print(packet.summary())  # Print summary
sniff(iface=iface, prn=packet_callback, store=True)

pcap_path = os.path.join(save_dir, "captured.pcap")
sniff(prn=lambda x: wrpcap(pcap_path, x, append=True))
print("Packets saved to " + save_dir)

arp_table = {}
def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet.op == 2:  # ARP Reply
        mac = packet.hwsrc
        ip = packet.psrc

        if ip in arp_table and arp_table[ip] != mac:
            print(f"[!] ALERT: ARP Spoofing Detected! {ip} is being spoofed.")
        else:
            arp_table[ip] = mac


pps_threshold = 100
packet_count = 0

def count_packets(packet):
    global packet_count
    packet_count += 1

while True:
    if packet_count > pps_threshold:
        print(f"[!] ALERT: High Traffic Spike! {packet_count} packets/sec")
    packet_count = 0
    time.sleep(1)
