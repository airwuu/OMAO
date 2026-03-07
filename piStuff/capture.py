import subprocess
import json
import requests
import time
import os
import threat_db

# config
NETWORK_INTERFACE = "eth0"          # Change to your active interface (e.g., wlp2s0, eth0)
LOG_FILE = "tshark_history.json"     # Where raw packets are appended
LEARNING_DURATION = 10               # Seconds to spend building the baseline before enforcing

# state
baseline_profile = {} # { ip: {dest_ips: set(), fingerprints: set()} }
banned_devices = set()

# adds normal behavior to device profile during learning phase 
def update_baseline(src_ip, dst_ip, ja3):
    if src_ip not in baseline_profile:
        baseline_profile[src_ip] = {"ips": set(), "ja3s": set()}
    
    baseline_profile[src_ip]["ips"].add(dst_ip)
    baseline_profile[src_ip]["ja3s"].add(ja3)

# checks abuse.ch database
def check_threat_intel(ip_address, ja3_hash, ja3_db):    
    is_bad_ja3 = threat_db.analyze_fingerprint(ja3_hash, ja3_db)
    if is_bad_ja3:
        return True

    print(f"- JA3 is clean. Checking IP: {ip_address}")
    return False

# kill switch
def isolate_device(source_ip):
    if source_ip in banned_devices:
        return # Already banned, prevent spamming iptables
        
    print(f"\n[!!!] CRITICAL THREAT CONFIRMED. INITIATING KILL SWITCH ON {source_ip} [!!!]\n")
    
    try:
        # Drops all traffic routed FROM this infected device
        subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-s", source_ip, "-j", "DROP"], check=True)
        # Drops all traffic routed TO this infected device
        subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-d", source_ip, "-j", "DROP"], check=True)
        
        banned_devices.add(source_ip)
        print(f"[*] {source_ip} has been successfully isolated from the network.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to execute iptables: {e}")

# ---------------------------------------------------
# main loop 
def start_monitoring():
    ja3_blacklist = threat_db.get_threat_database()
    
    script_start_time = time.time()

    print(f"[*] Starting IoT Defender on interface '{NETWORK_INTERFACE}'...")
    print(f"[*] Entering LEARNING PHASE for {LEARNING_DURATION} seconds...")
    tshark_cmd = [
        "tshark", "-l", "-i", NETWORK_INTERFACE, 
        "-T", "ek",
        "-e", "frame.protocols", 
        "-e", "eth.src", "-e", "eth.dst", 
        "-e", "ip.src", "-e", "ip.dst", 
        "-e", "tcp.dstport", "-e", "udp.dstport",
        "-e", "tls.handshake.ja3",
        "-e", "dhcp.hw.mac_addr", "-e", "dhcp.option.hostname"
    ]   

    process = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, text=True)

    with open(LOG_FILE, 'a') as log_file:
        try:
            for line in process.stdout:
                # 1. Append raw JSON to our permanent log file
                log_file.write(line)
                log_file.flush() 
                
                # 2. Parse the packet
                try:
                    data = json.loads(line)
                    if "layers" not in data:
                        continue
                        
                    layers = data["layers"]
                    src_ip = layers.get("ip_src", [""])[0]
                    dst_ip = layers.get("ip_dst", [""])[0]
                    ja3 = layers.get("tls_handshake_ja3", [""])[0]
                    
                    if not (src_ip and dst_ip and ja3):
                        continue # Skip malformed packets
                        
                    # 3. Time-based Logic Routing
                    elapsed_time = time.time() - script_start_time
                    
                    if elapsed_time < LEARNING_DURATION:
                        # We are still learning what is normal
                        update_baseline(src_ip, dst_ip, ja3)
                        # Optional: Print a dot to show it's working without spamming the screen
                        print(".", end="", flush=True) 
                        
                    else:
                        # We are now ENFORCING the baseline
                        if elapsed_time - LEARNING_DURATION < 1:
                            print("\n\n[*] LEARNING PHASE COMPLETE. ENTERING ACTIVE MONITORING.[*]\n")
                            time.sleep(1) 
                            
                        # Check if the device is doing something new
                        profile = baseline_profile.get(src_ip, {"ips": set(), "ja3s": set()})
                        
                        is_new_ip = dst_ip not in profile["ips"]
                        is_new_ja3 = ja3 not in profile["ja3s"]
                        
                        if is_new_ip or is_new_ja3:
                            print(f"\n[*] Deviation detected for {src_ip} -> {dst_ip} [JA3: {ja3}]")
                            
                            is_malicious = check_threat_intel(dst_ip, ja3, ja3_blacklist)
                            if is_malicious:
                                isolate_device(src_ip)
                            else:
                                print(f"[*] Deviation is benign. Updating baseline for {src_ip}.")
                                update_baseline(src_ip, dst_ip, ja3)
                                
                except json.JSONDecodeError:
                    continue # Ignore Tshark indexing lines
                    
        except KeyboardInterrupt:
            print("\n[*] Shutting down IoT Defender...")
            process.terminate()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] ERROR: This script must be run as root (sudo).")
        exit(1)
        
    start_monitoring()
