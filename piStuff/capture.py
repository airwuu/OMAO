import subprocess
import json
import os
import sys
import time

# --- CONFIGURATION ---
NETWORK_INTERFACE = "eth0"  # Change to your interface (e.g., wlan0, enp0s3)
LOG_FILE = "iot_defender_dhcp.log"

# Track MAC addresses seen in this session to avoid duplicate alerts
devices_seen = set()

def check_threat_intel(mac_addr, hostname):
    """
    Placeholder: Check if the device's MAC or Hostname is suspicious.
    """
    print(f"[*] Analyzing {hostname} ({mac_addr}) against threat database...")
    # Add your API calls or local blacklist checks here
    return False 

def isolate_device(mac_addr):
    """
    Placeholder: Block the device using iptables or another method.
    """
    print(f"[!] ACTION TAKEN: Isolating device {mac_addr} from network.")
    # Example: os.system(f"iptables -A FORWARD -m mac --mac-source {mac_addr} -j DROP")

def handle_new_device(mac_addr, hostname):
    """
    The core logic triggered when a DHCP join is detected.
    """
    if mac_addr in devices_seen:
        return # Skip if we've already handled this device this session
    
    devices_seen.add(mac_addr)
    print("\n" + "="*50)
    print(f"[!] NEW DEVICE JOINED THE NETWORK")
    print(f"    MAC Address: {mac_addr}")
    print(f"    Hostname:    {hostname}")
    print("="*50)

    is_malicious = check_threat_intel(mac_addr, hostname)
    if is_malicious:
        isolate_device(mac_addr)
    else:
        print(f"[*] Device {mac_addr} allowed for now.")

def start_monitoring():
    print(f"[*] Starting IoT Defender on interface '{NETWORK_INTERFACE}'...")
    print(f"[*] Filtering for DHCP Discover/Request (New Joins)...")

    # Tshark command focused specifically on DHCP handshake packets
    tshark_cmd = [
        "tshark", "-l", "-i", NETWORK_INTERFACE, 
        "-T", "ek",
        "-f", "udp port 67 or udp port 68", # BPF filter for speed
        "-e", "dhcp.option.dhcp",           # Type (1=Discover, 3=Request)
        "-e", "dhcp.hw.mac_addr",          # MAC of the device
        "-e", "dhcp.option.hostname"        # Hostname of the device
    ]   

    # Start tshark process
    process = subprocess.Popen(
        tshark_cmd, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.DEVNULL, 
        text=True
    )

    with open(LOG_FILE, 'a') as log_file:
        try:
            for line in process.stdout:
                # 1. Log the raw JSON to a file
                log_file.write(line)
                log_file.flush()

                try:
                    data = json.loads(line)
                    if "layers" not in data:
                        continue
                    
                    layers = data["layers"]
                    
                    # Extract DHCP specific fields
                    # Tshark 'ek' format uses underscores in keys
                    msg_types = layers.get("dhcp_option_dhcp", [])
                    mac_addrs = layers.get("dhcp_hw_mac_addr", [])
                    hostnames = layers.get("dhcp_option_hostname", ["Unknown"])

                    if msg_types and mac_addrs:
                        msg_type = msg_types[0]
                        mac_addr = mac_addrs[0]
                        hostname = hostnames[0]

                        # Trigger on DHCP Discover (1) or Request (3)
                        if msg_type in ["1", "3"]:
                            handle_new_device(mac_addr, hostname)

                except json.JSONDecodeError:
                    continue 

        except KeyboardInterrupt:
            print("\n[*] Shutting down IoT Defender...")
            process.terminate()

if __name__ == "__main__":
    # Check for Root
    if os.geteuid() != 0:
        print("[!] ERROR: This script must be run as root (sudo) to capture packets.")
        sys.exit(1)

    # Basic check to see if Tshark is installed
    if subprocess.call(["which", "tshark"], stdout=subprocess.DEVNULL) != 0:
        print("[!] ERROR: Tshark is not installed. Please install it (sudo apt install tshark).")
        sys.exit(1)
        
    start_monitoring()
