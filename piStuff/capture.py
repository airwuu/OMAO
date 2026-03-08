import subprocess
import json
import requests
import time
import os
import threat_db

# config
NETWORK_INTERFACE = "wlan0"          # Change to your active interface (e.g., wlp2s0, eth0)
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

    print(f"[*] Checking IP: {ip_address}")
    return False

# kill switch
def isolate_device(source_ip):
    if source_ip in banned_devices:
        return 
        
    print(f"\n[!] Dropping all traffic from {source_ip}")
    
    try:
        subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-s", source_ip, "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-d", source_ip, "-j", "DROP"], check=True)
        
        banned_devices.add(source_ip)
        print(f"[-] {source_ip} has been successfully isolated from the network.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to execute iptables: {e}")

# ---------------------------------------------------
# extracts src, dst, and ja3 from tshark JSON
def parse_packet(line):
    try:
        data = json.loads(line)
        layers = data.get("layers", {})

        src = layers.get("ip_src", [None])[0]
        dst = layers.get("ip_dst", [None])[0]
        ja3 = layers.get("tls_handshake_ja3", [None])[0]

        return src, dst, ja3
    except:
        return None, None, None

# checks deviations 
def process_threat(src, dst, ja3, database):
    if src in banned_devices:
            return

    prof = baseline_profile.get(src, {"ips": set(), "ja3s": set()})
    
    if dst not in prof["ips"] or ja3 not in prof["ja3s"]:
        print(f"\n[*] New Signature: {src} -> {dst}")
        
        if check_threat_intel(dst, ja3, database):
            isolate_device(src)
        else:
            print(f"[*] Signature verified benign.")
            update_baseline(src, dst, ja3)

# main loop
def start_monitoring():
    db = threat_db.get_threat_database()
    script_start_time = time.time()
    last_tick = script_start_time
    active_alert_shown = False

    cmd = [
        "tshark", "-l", "-i", NETWORK_INTERFACE, 
        "-T", "ek",
        "-e", "frame.protocols", 
        "-e", "eth.src", "-e", "eth.dst", 
        "-e", "ip.src", "-e", "ip.dst", 
        "-e", "tcp.dstport", "-e", "udp.dstport",
        "-e", "tls.handshake.ja3",
        "-e", "dhcp.hw.mac_addr", "-e", "dhcp.option.hostname"
    ]   
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    print("")
    print(f"[*] Monitoring {NETWORK_INTERFACE}...")

    print("")
    print(f"[*] Learning phase: {LEARNING_DURATION}s remaining...")

    with open(LOG_FILE, 'a') as log_file:
        try:
            while True:
                try:
                    line = process.stdout.readline()
                except IOError:
                    line = None
                current_time = time.time()
                elapsed = current_time - script_start_time

                if elapsed < LEARNING_DURATION:
                    if current_time - last_tick >= 1:
                        remaining = int(LEARNING_DURATION - elapsed)
                        print(f"[*] Learning phase {int(LEARNING_DURATION - elapsed)}s remaining...", flush=True)
                        last_tick = current_time
                elif not active_alert_shown:
                    print(f"\n\n{'='*40}")
                    print("[*] Monitoring active.")
                    print(f"{'='*40}\n")
                    active_alert_shown = True
              
                if line.strip().isdigit():
                    continue

                log_file.write(line)
                src, dst, ja3 = parse_packet(line)
                
                if not src or not dst:
                    continue

                if elapsed < LEARNING_DURATION:
                    update_baseline(src, dst, ja3)
                    if ja3:
                        print(f"\nLearning fingerprint: {ja3[:10]}... (from {src})", end="", flush=True)
                    else:
                        print(".", end="", flush=True) 
                else:
                    if ja3:
                        process_threat(src, dst, ja3, db)
                    else: 
                        pass

        except KeyboardInterrupt:
            print("\n[*] Stopping...")
            process.terminate()
            
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] ERROR: This script must be run as root (sudo).")
        exit(1)
        
    start_monitoring()
