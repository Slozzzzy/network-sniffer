import os
import platform

def get_network_interfaces():
    system = platform.system()

    if system == "Linux" or system == "Darwin": 
        command = "ls /sys/class/net"
    elif system == "Windows":
        command = "wmic nic get NetConnectionID"
    else:
        print(f"Unsupported OS: {system}")
        return []

    interfaces = os.popen(command).read().strip().split("\n")

    interfaces = [iface.strip() for iface in interfaces if iface.strip() and "NetConnectionID" not in iface]

    return interfaces

