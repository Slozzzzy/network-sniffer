from scapy.all import sniff, ARP, wrpcap, PcapWriter
from analyze import analyze_packet  # Import function from analyze.py
import time, os, threading, signal, sys
from GetIface import get_network_interfaces

save_dir = os.path.join(os.getcwd(), "captured_packets")
os.makedirs(save_dir, exist_ok=True)

stop_sniffing = threading.Event()
def signal_handler(sig, frame):
    print("\n[!] Stopping packet capture...")
    stop_sniffing.set()  # Signal all sniffer threads to stop
    time.sleep(1)  # Give threads time to exit
    sys.exit(0)

packets =[]
show_iface = ', '.join(get_network_interfaces()) #display all the available network interfaces
print('Select your network interface (as 0, 1, 2, so on) : ' + show_iface)
selected_face = input()
if (int(selected_face) < 0 or int(selected_face) > len(get_network_interfaces())) : #simple error handling
    exit()
iface = get_network_interfaces()[int(selected_face)] 

pcap_path = os.path.join(save_dir, "captured.pcap")
pcap_writer = PcapWriter(pcap_path, append=True, sync=True)

print("Packets saved to " + save_dir)
def packet_callback(packet):
    analyze_packet(packet)
    packets.append(packet)  # Add packet to list
    print(packet.summary())  # Print summary
    pcap_writer.write(packet)

arp_table = {}
pps_threshold = 100
packet_count = 0

def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet.op == 2:  # ARP Reply
        mac = packet.hwsrc
        ip = packet.psrc

        if ip in arp_table and arp_table[ip] != mac:
            print(f"[!] ALERT: ARP Spoofing Detected! {ip} is being spoofed.")
        else:
            arp_table[ip] = mac

def count_packets(packet):
    global packet_count
    packet_count += 1

threading.Thread(target=lambda: sniff(iface=iface, prn=packet_callback, store=True, stop_filter=lambda x: stop_sniffing.is_set()), daemon=True).start()
threading.Thread(target=lambda: sniff(iface=iface, filter="arp", prn=detect_arp_spoof, store=False, stop_filter=lambda x: stop_sniffing.is_set()), daemon=True).start()
threading.Thread(target=lambda: sniff(iface=iface, filter="tcp or udp", prn=count_packets, store=False, timeout=1, stop_filter=lambda x: stop_sniffing.is_set()), daemon=True).start()
signal.signal(signal.SIGINT, signal_handler)

while True:
    if packet_count > pps_threshold:
        print(f"[!] ALERT: High Traffic Spike! {packet_count} packets/sec")
    packet_count = 0
    time.sleep(1)
