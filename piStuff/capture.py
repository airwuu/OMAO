import datetime
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from mac_vendor_lookup import MacLookup
from threat_db import get_threat_database, analyze_fingerprint

# --- CONFIGURATION ---
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "eth0").strip() or "eth0"
LOG_FILE = os.getenv("LOG_FILE", "iot_defender_dhcp.log").strip() or "iot_defender_dhcp.log"
SUPABASE_DEVICES_TABLE = os.getenv("SUPABASE_DEVICES_TABLE", "devices").strip() or "devices"
SUPABASE_METRICS_TABLE = os.getenv("SUPABASE_METRICS_TABLE", "device_metrics").strip() or "device_metrics"


def read_bool_env(name: str, default_value: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default_value

    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False

    print(f"[!] ERROR: {name} must be a boolean value (true/false), received '{raw}'.")
    sys.exit(1)


def read_positive_float_env(name: str, default_value: float) -> float:
    raw = os.getenv(name, str(default_value)).strip() or str(default_value)
    try:
        value = float(raw)
    except ValueError:
        print(f"[!] ERROR: {name} must be numeric, received '{raw}'.")
        sys.exit(1)

    if value <= 0:
        print(f"[!] ERROR: {name} must be greater than 0.")
        sys.exit(1)

    return value


def read_positive_int_env(name: str, default_value: int) -> int:
    raw = os.getenv(name, str(default_value)).strip() or str(default_value)
    try:
        value = int(raw)
    except ValueError:
        print(f"[!] ERROR: {name} must be an integer, received '{raw}'.")
        sys.exit(1)

    if value <= 0:
        print(f"[!] ERROR: {name} must be greater than 0.")
        sys.exit(1)

    return value


DHCP_DUPLICATE_WINDOW_SEC = read_positive_float_env("DHCP_DUPLICATE_WINDOW_SEC", 20)
DISCONNECT_TIMEOUT_SEC = read_positive_float_env("DISCONNECT_TIMEOUT_SEC", 60)
METRICS_SAMPLE_INTERVAL_SEC = read_positive_float_env("METRICS_SAMPLE_INTERVAL_SEC", 10)
PING_COUNT = read_positive_int_env("PING_COUNT", 3)
PING_TIMEOUT_SEC = read_positive_float_env("PING_TIMEOUT_SEC", 1)
SHOW_PACKET_LOGS = read_bool_env("SHOW_PACKET_LOGS", True)
DISCONNECT_SCAN_INTERVAL_SEC = min(5.0, max(1.0, DISCONNECT_TIMEOUT_SEC / 4.0))
PING_REPLY_TIMEOUT_SEC = max(1, int(round(PING_TIMEOUT_SEC)))

PING_PACKET_LOSS_PATTERN = re.compile(r"(\d+(?:\.\d+)?)%\s*packet loss")
PING_AVERAGE_RTT_PATTERN = re.compile(r"=\s*[\d.]+/([\d.]+)/[\d.]+/[\d.]+\s*ms")

# Track recent MAC address activity to suppress duplicate Discover/Request bursts.
recent_devices: dict[str, float] = {}
device_registry: dict[str, dict[str, object]] = {}
device_registry_lock = threading.Lock()
traffic_counters: dict[str, dict[str, int]] = {}
traffic_counters_lock = threading.Lock()

# Traffic analysis trackers
traffic_short_term: dict[str, dict[str, int]] = {}
traffic_long_term: dict[str, dict[str, int]] = {}
traffic_analysis_lock = threading.Lock()

# Initialize the vendor lookup tool globally
vendor_scanner = MacLookup() 


def check_threat_intel(mac_addr, hostname, ja3_hash=None):
    print(f"[*] Analyzing {hostname} ({mac_addr}) against threat database...")
    
    # 1. NEW: Check JA3 if a hash was captured
    if ja3_hash:
        if analyze_fingerprint(ja3_hash, ja3_db):
            return True # Malicious fingerprint match!

    # 2. Existing Hostname check
    BLACKLIST_HOSTNAMES = ["malicious-device", "hack-box"]
    if hostname.lower() in BLACKLIST_HOSTNAMES:
        return True

    return False


def isolate_device(mac_addr):
    """
    Blocks the device from communicating through the Pi using iptables.
    """
    print(f"[!] ACTION TAKEN: Cutting network access for {mac_addr}.")
    try:
        # This command drops any packet coming from this specific MAC address
        subprocess.run([
            "sudo", "iptables", "-A", "FORWARD", 
            "-m", "mac", "--mac-source", mac_addr, 
            "-j", "DROP"
        ], check=True)
        print(f"[*] iptables rule added: {mac_addr} is now isolated.")
    except Exception as e:
        print(f"[!] Failed to isolate device {mac_addr}: {e}")


def required_env(name):
    value = os.getenv(name, "").strip()
    if value:
        return value

    print(f"[!] ERROR: Missing required environment variable: {name}")
    sys.exit(1)


def current_timestamp_utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_mac(raw_mac):
    return raw_mac.strip().lower().replace("-", ":").replace(".", ":")


def build_device_id(mac_addr):
    compact = "".join(character for character in mac_addr if character.isalnum())
    return f"mac-{compact}"


def fallback_device_name(hostname, mac_addr):
    if hostname and hostname.strip() and hostname.strip().lower() != "unknown":
        return hostname.strip()

    compact = "".join(character for character in mac_addr if character.isalnum())
    suffix = compact[-6:] if compact else "unknown"
    return f"device-{suffix}"


def first_value(layers, *keys):
    for key in keys:
        value = layers.get(key)
        if isinstance(value, list):
            for entry in value:
                if isinstance(entry, (str, int, float)):
                    text = str(entry).strip()
                    if text:
                        return text
        elif isinstance(value, (str, int, float)):
            text = str(value).strip()
            if text:
                return text

    return None


def parse_dhcp_message_type(raw_value):
    if raw_value is None:
        return None

    text = str(raw_value).strip().lower()
    if not text:
        return None

    try:
        return int(text, 0)
    except ValueError:
        digits = "".join(character for character in text if character.isdigit())
        if not digits:
            return None
        try:
            return int(digits)
        except ValueError:
            return None


def parse_integer(raw_value):
    if raw_value is None:
        return None

    text = str(raw_value).strip()
    if not text:
        return None

    try:
        return int(text, 0)
    except ValueError:
        digits = "".join(character for character in text if character.isdigit())
        if not digits:
            return None
        try:
            return int(digits)
        except ValueError:
            return None


def normalize_ip(*candidates):
    for candidate in candidates:
        if not candidate:
            continue

        value = candidate.strip()
        if not value:
            continue

        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            continue

        if parsed.is_unspecified or parsed.is_multicast or parsed.is_reserved or parsed.is_loopback:
            continue

        if value == "255.255.255.255":
            continue

        return str(parsed)

    return "0.0.0.0"


def should_skip_duplicate(mac_addr, message_type):
    # Allow DHCP ACK/OFFER-style packets to refresh IP quickly after Discover/Request.
    if message_type == 5:
        return False

    now = time.time()
    previous_seen = recent_devices.get(mac_addr)

    if previous_seen is not None and now - previous_seen < DHCP_DUPLICATE_WINDOW_SEC:
        return True

    recent_devices[mac_addr] = now

    # Bound memory growth for long-running sessions.
    if len(recent_devices) > 5000:
        cutoff = now - (DHCP_DUPLICATE_WINDOW_SEC * 2)
        stale_keys = [key for key, timestamp in recent_devices.items() if timestamp < cutoff]
        for key in stale_keys:
            recent_devices.pop(key, None)

    return False


class SupabaseWriter:
    def __init__(self, base_url, service_role_key, devices_table, metrics_table):
        self.base_url = base_url.rstrip("/")
        self.service_role_key = service_role_key
        self.devices_table = devices_table
        self.metrics_table = metrics_table
        self.encoded_devices_table = urllib.parse.quote(self.devices_table, safe="")
        self.encoded_metrics_table = urllib.parse.quote(self.metrics_table, safe="")

    def _post(self, path, payload, prefer_header):
        endpoint = f"{self.base_url}{path}"
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            method="POST"
        )
        request.add_header("apikey", self.service_role_key)
        request.add_header("Authorization", f"Bearer {self.service_role_key}")
        request.add_header("Content-Type", "application/json")
        request.add_header("Prefer", prefer_header)

        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status >= 300:
                    response_body = response.read().decode("utf-8", errors="replace")
                    raise RuntimeError(
                        f"Supabase request failed ({response.status}) for {path}: {response_body}"
                    )
        except urllib.error.HTTPError as error:
            response_body = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Supabase request failed ({error.code}) for {path}: {response_body}"
            ) from error
        except urllib.error.URLError as error:
            raise RuntimeError(f"Supabase request error for {path}: {error.reason}") from error

    def _get(self, path):
        endpoint = f"{self.base_url}{path}"
        request = urllib.request.Request(
            endpoint,
            method="GET"
        )
        request.add_header("apikey", self.service_role_key)
        request.add_header("Authorization", f"Bearer {self.service_role_key}")
        request.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status >= 300:
                    response_body = response.read().decode("utf-8", errors="replace")
                    raise RuntimeError(
                        f"Supabase GET failed ({response.status}) for {path}: {response_body}"
                    )
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            response_body = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Supabase GET failed ({error.code}) for {path}: {response_body}"
            ) from error
        except urllib.error.URLError as error:
            raise RuntimeError(f"Supabase request error for {path}: {error.reason}") from error

    def upsert_device(self, device_id, mac_addr, hostname, ip_addr, status):
        timestamp = current_timestamp_utc()
        safe_hostname = fallback_device_name(hostname, mac_addr)

        try:
            # Look up the manufacturer (e.g., "Espressif Inc" or "Apple")
            vendor = vendor_scanner.lookup(mac_addr)
        except Exception:
            vendor = "Unknown Vendor"

        # Simple logic to determine the 'type'
        v_lower = vendor.lower()
        h_lower = safe_hostname.lower()
        
        if "espressif" in v_lower or "esp" in h_lower:
            device_type = "smart_home"
        elif "apple" in v_lower or "samsung" in v_lower or "mobile" in h_lower:
            device_type = "mobile"
        elif "raspberry" in v_lower:
            device_type = "gateway"
        else:
            device_type = "iot"  # Default if we aren't sure

        device_row = [{
            "id": device_id,
            "name": safe_hostname,
            "type": device_type,
            "vendor": vendor,
            "model": "Unknown",
            "ip": ip_addr,
            "mac": mac_addr,
            "device_category": "iot",
            "last_seen_at": timestamp,
            "status": status,
            # We don't overwrite traffic_baseline or avg_pkts_per_sec here, 
            # they are updated in the anomaly_analysis_worker.
        }]

        self._post(
            f"/rest/v1/{self.encoded_devices_table}?on_conflict=id",
            device_row,
            "resolution=merge-duplicates,return=minimal"
        )

    def insert_metric(self, device_id, latency_ms, packet_loss_pct, block_events=0, network_activity_kbps=0.0):
        timestamp = current_timestamp_utc()

        metric_row = [{
            "device_id": device_id,
            "recorded_at": timestamp,
            "latency_ms": round(float(latency_ms), 2),
            "packet_loss_pct": round(float(packet_loss_pct), 2),
            "block_events": int(block_events),
            "network_activity_kbps": round(float(network_activity_kbps), 2)
        }]

        self._post(
            f"/rest/v1/{self.encoded_metrics_table}",
            metric_row,
            "return=minimal"
        )


    def update_device_baseline(self, device_id, baseline_dict, avg_pkts):
        # Dedicated method to update just the learned baseline fields
        payload = [{
            "id": device_id,
            "traffic_baseline": baseline_dict,
            "avg_pkts_per_sec": round(float(avg_pkts), 2)
        }]
        
        # Merge duplicates minimal return updates existing rows based on the id
        self._post(
            f"/rest/v1/{self.encoded_devices_table}?on_conflict=id",
            payload,
            "resolution=merge-duplicates,return=minimal"
        )
        
    def get_all_baselines(self):
        # Fetch mac, traffic_baseline, and avg_pkts_per_sec for all devices
        return self._get(f"/rest/v1/{self.encoded_devices_table}?select=mac,traffic_baseline,avg_pkts_per_sec")


def get_registry_snapshot_for_mac(mac_addr):
    with device_registry_lock:
        state = device_registry.get(mac_addr)
        return dict(state) if state else None


def resolve_device_ip(layers, message_type, known_ip):
    ip_src = first_value(layers, "ip_src")
    ip_dst = first_value(layers, "ip_dst")
    requested_ip = first_value(layers, "dhcp_option_requested_ip_address", "dhcp_option_requested_ip")
    your_ip = first_value(layers, "bootp_ip_your", "bootp_ip_yiaddr")
    client_ip = first_value(layers, "bootp_ip_client", "bootp_ip_ciaddr")
    udp_dstport = parse_integer(first_value(layers, "udp_dstport", "udp_dst_port"))

    ordered_candidates = [requested_ip, your_ip, client_ip]
    if message_type == 5 or udp_dstport == 68:
        ordered_candidates.extend([ip_dst, ip_src])
    else:
        ordered_candidates.extend([ip_src, ip_dst])

    resolved_ip = normalize_ip(*ordered_candidates)
    if resolved_ip == "0.0.0.0" and known_ip and known_ip != "0.0.0.0":
        return known_ip

    return resolved_ip


def upsert_registry_on_presence(mac_addr, hostname, ip_addr, is_malicious):
    now = time.time()
    with device_registry_lock:
        previous = device_registry.get(mac_addr, {})
        previous_ip = str(previous.get("ip", "0.0.0.0"))
        previous_hostname = str(previous.get("name", "Unknown"))
        resolved_ip = ip_addr if ip_addr != "0.0.0.0" else previous_ip
        resolved_hostname = hostname if hostname and hostname.lower() != "unknown" else previous_hostname
        status = "blocked" if is_malicious else "good"
        snapshot = {
            "id": str(previous.get("id", build_device_id(mac_addr))),
            "mac": mac_addr,
            "name": resolved_hostname,
            "ip": resolved_ip,
            "status": status,
            "is_malicious": is_malicious,
            "last_seen_epoch": now
        }
        device_registry[mac_addr] = snapshot
        return dict(snapshot)


def refresh_device_liveness(mac_addr):
    now = time.time()
    with device_registry_lock:
        state = device_registry.get(mac_addr)
        if state is None:
            return None, False

        state["last_seen_epoch"] = now
        status_changed = False
        if state.get("status") == "disconnected":
            state["status"] = "blocked" if bool(state.get("is_malicious")) else "good"
            status_changed = True

        return dict(state), status_changed


def mark_disconnected_devices():
    now = time.time()
    disconnected_snapshots = []

    with device_registry_lock:
        for state in device_registry.values():
            if state.get("status") == "disconnected":
                continue

            last_seen_epoch = float(state.get("last_seen_epoch", 0.0))
            if now - last_seen_epoch < DISCONNECT_TIMEOUT_SEC:
                continue

            state["status"] = "disconnected"
            disconnected_snapshots.append(dict(state))

    return disconnected_snapshots


def record_traffic_destination(src_mac, dst_mac, dst_ip, frame_bytes):
    if frame_bytes <= 0:
        return

    tracked_src = False
    tracked_dst = False
    with device_registry_lock:
        tracked_src = src_mac in device_registry
        tracked_dst = dst_mac in device_registry

    if not tracked_src and not tracked_dst:
        return

    # Update generic traffic counters (upload/download volume)
    with traffic_counters_lock:
        if tracked_src:
            src_counter = traffic_counters.setdefault(src_mac, {"upload_bytes": 0, "download_bytes": 0})
            src_counter["upload_bytes"] += frame_bytes

        if tracked_dst:
            dst_counter = traffic_counters.setdefault(dst_mac, {"upload_bytes": 0, "download_bytes": 0})
            dst_counter["download_bytes"] += frame_bytes

    # Track distinct IP destinations for anomaly detection
    with traffic_analysis_lock:
        # Only tracking outbound behavior (what the device reaches out to)
        if tracked_src and dst_ip and dst_ip != "0.0.0.0":
            src_ips = traffic_short_term.setdefault(src_mac, {})
            src_ips[dst_ip] = src_ips.get(dst_ip, 0) + 1


def consume_network_activity(mac_addr):
    with traffic_counters_lock:
        counters = traffic_counters.setdefault(mac_addr, {"upload_bytes": 0, "download_bytes": 0})
        upload_bytes = int(counters.get("upload_bytes", 0))
        download_bytes = int(counters.get("download_bytes", 0))
        counters["upload_bytes"] = 0
        counters["download_bytes"] = 0

    return upload_bytes, download_bytes


def probe_device(ip_addr):
    ping_cmd = [
        "ping",
        "-n",
        "-c", str(PING_COUNT),
        "-W", str(PING_REPLY_TIMEOUT_SEC),
        ip_addr
    ]

    timeout_seconds = max(3.0, (PING_COUNT * PING_TIMEOUT_SEC) + 3.0)
    try:
        result = subprocess.run(
            ping_cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False
        )
    except subprocess.TimeoutExpired:
        return 0.0, 100.0, False

    combined_output = f"{result.stdout}\n{result.stderr}"

    packet_loss_match = PING_PACKET_LOSS_PATTERN.search(combined_output)
    if packet_loss_match:
        packet_loss_pct = float(packet_loss_match.group(1))
    else:
        packet_loss_pct = 100.0 if result.returncode != 0 else 0.0

    latency_match = PING_AVERAGE_RTT_PATTERN.search(combined_output)
    if latency_match:
        latency_ms = float(latency_match.group(1))
    else:
        latency_ms = 0.0

    success = packet_loss_pct < 100.0
    return latency_ms, packet_loss_pct, success


def metrics_worker(stop_event, supabase_writer):
    while not stop_event.wait(METRICS_SAMPLE_INTERVAL_SEC):
        with device_registry_lock:
            snapshots = [
                dict(state)
                for state in device_registry.values()
                if str(state.get("ip", "0.0.0.0")) != "0.0.0.0"
            ]

        for snapshot in snapshots:
            device_id = str(snapshot["id"])
            mac_addr = str(snapshot["mac"])
            ip_addr = str(snapshot["ip"])

            latency_ms, packet_loss_pct, success = probe_device(ip_addr)
            upload_bytes, download_bytes = consume_network_activity(mac_addr)
            network_activity_kbps = (
                ((upload_bytes + download_bytes) * 8.0) / (METRICS_SAMPLE_INTERVAL_SEC * 1000.0)
            )
            try:
                supabase_writer.insert_metric(
                    device_id,
                    latency_ms,
                    packet_loss_pct,
                    0,
                    network_activity_kbps
                )
            except Exception as error:
                print(f"[!] Supabase metric write failed for {mac_addr}: {error}")

            if not success:
                continue

            refreshed_snapshot, status_changed = refresh_device_liveness(mac_addr)
            if not refreshed_snapshot:
                continue

            if status_changed:
                print(f"[*] Device {mac_addr} is reachable again. Marking as {refreshed_snapshot['status']}.")

            try:
                supabase_writer.upsert_device(
                    str(refreshed_snapshot["id"]),
                    mac_addr,
                    str(refreshed_snapshot["name"]),
                    str(refreshed_snapshot["ip"]),
                    str(refreshed_snapshot["status"])
                )
            except Exception as error:
                print(f"[!] Supabase liveness update failed for {mac_addr}: {error}")


def network_activity_worker(stop_event):
    tshark_cmd = [
        "tshark", "-l", "-p", "-i", NETWORK_INTERFACE,
        "-T", "ek",
        "-f", "ip",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.dst",
        "-e", "frame.len"
    ]

    process = subprocess.Popen(
        tshark_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    if process.stdout is None:
        print("[!] ERROR: Unable to read traffic tshark output stream.")
        return

    try:
        for line in process.stdout:
            if stop_event.is_set():
                break

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            layers = data.get("layers")
            if not isinstance(layers, dict):
                continue

            src_mac = first_value(layers, "eth_src")
            dst_mac = first_value(layers, "eth_dst")
            dst_ip = normalize_ip(first_value(layers, "ip_dst"))
            frame_len = parse_integer(first_value(layers, "frame_len", "frame_cap_len", "frame_frame_len"))

            if not src_mac or not dst_mac or frame_len is None:
                continue

            record_traffic_destination(normalize_mac(src_mac), normalize_mac(dst_mac), dst_ip, frame_len)
    finally:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()


def handle_anomaly(mac_addr, hostname, ip_addr, reason, supabase_writer):
    print("\n" + "!" * 50)
    print("[!!!] ANOMALY DETECTED [!!!]")
    print(f"    MAC Address: {mac_addr}")
    print(f"    Hostname:    {hostname}")
    print(f"    IP Address:  {ip_addr}")
    print(f"    Reason:      {reason}")
    print("!" * 50)

    # 1. Isolate the device immediately
    isolate_device(mac_addr)

    # 2. Update local registry to reflect blocked status
    snapshot = upsert_registry_on_presence(mac_addr, hostname, ip_addr, True)

    # 3. Update Supabase
    try:
        supabase_writer.upsert_device(
            str(snapshot["id"]),
            mac_addr,
            str(snapshot["name"]),
            str(snapshot["ip"]),
            "blocked"
        )
        supabase_writer.insert_metric(str(snapshot["id"]), 0.0, 0.0, 1, 0.0)
    except Exception as error:
        print(f"[!] Supabase anomaly update failed for {mac_addr}: {error}")


def anomaly_analysis_worker(stop_event, supabase_writer):
    # Analyzing every 1 minute
    ANOMALY_CHECK_INTERVAL_SEC = 60.0
    
    # We want a 24-hour learning period. 
    # 24 hours * 60 minutes = 1440 updates for a full cycle. Alpha = 1/1440.
    ALPHA = 1.0 / 1440.0

    while not stop_event.wait(ANOMALY_CHECK_INTERVAL_SEC):
        # 1. Extract short term data and clear it to start fresh for the next minute
        with traffic_analysis_lock:
            current_short_term = traffic_short_term.copy()
            traffic_short_term.clear()

        # 2. Extract current device information
        with device_registry_lock:
            snapshots = {
                mac: dict(state)
                for mac, state in device_registry.items()
            }

        # 3. Process each device that had traffic in the last minute
        for mac_addr, short_term_ips in current_short_term.items():
            snapshot = snapshots.get(mac_addr)
            if not snapshot:
                continue

            # If device is already blocked, skip analysis
            if snapshot.get("status") == "blocked":
                continue

            device_id = str(snapshot["id"])
            hostname = str(snapshot["name"])
            ip_addr = str(snapshot["ip"])
            
            # Calculate short term total packets
            st_total_pkts = sum(short_term_ips.values())
            if st_total_pkts == 0:
                continue
                
            st_pkts_per_sec = st_total_pkts / ANOMALY_CHECK_INTERVAL_SEC

            # Safely get or initialize long term baseline for this MAC
            with traffic_analysis_lock:
                # long_term stores: {"avg_pkts_per_sec": float, "ips": {"ip": percentage(0-1)}}
                lt_data = traffic_long_term.setdefault(mac_addr, {
                    "avg_pkts_per_sec": st_pkts_per_sec, # Initialize with current if empty
                    "ips": {},
                    "updates_count": 0
                })
                
                lt_avg_pkts_per_sec = lt_data["avg_pkts_per_sec"]
                lt_ips = lt_data["ips"]
                updates_count = lt_data["updates_count"]

            # --- Anomaly Detection Logic ---
            is_anomalous = False
            reason = ""

            # Only run anomaly rules if we have built a decent baseline (e.g., at least 5 minutes)
            if updates_count >= 5:
                # Rule 1: Volume Spike (>300% increase over baseline)
                # Ignore very small baselines to avoid false positives on quiet devices
                if lt_avg_pkts_per_sec > 1.0 and st_pkts_per_sec > (lt_avg_pkts_per_sec * 3.0):
                    is_anomalous = True
                    reason = f"Volume spike: {st_pkts_per_sec:.1f} pkts/s (baseline: {lt_avg_pkts_per_sec:.1f} pkts/s)"
                
                # Rule 2: Destination IP Distribution Shifts
                if not is_anomalous:
                    st_distribution = {ip: count / st_total_pkts for ip, count in short_term_ips.items()}
                    for ip, st_percentage in st_distribution.items():
                        lt_percentage = lt_ips.get(ip, 0.0)
                        
                        # New IP or massively increased percentage
                        # E.g., if it was < 1% historically, but is now > 20% of traffic
                        if lt_percentage < 0.01 and st_percentage > 0.20:
                            # And must be a meaningful amount of packets (e.g. > 10 pkts)
                            if short_term_ips[ip] > 10:
                                is_anomalous = True
                                reason = f"Abnormal connection to {ip} ({st_percentage*100:.1f}% of traffic, baseline {lt_percentage*100:.1f}%)"
                                break
                        
                        # Existing IP ratio suddenly spiked severely (e.g. from <10% to >50%)
                        if lt_percentage < 0.10 and st_percentage > 0.50:
                            if short_term_ips[ip] > 20: # Require even more packets to flag existing IPs
                                is_anomalous = True
                                reason = f"Ratio spike to {ip} ({st_percentage*100:.1f}% of traffic, baseline {lt_percentage*100:.1f}%)"
                                break

            # --- Trigger Alert ---
            if is_anomalous:
                handle_anomaly(mac_addr, hostname, ip_addr, reason, supabase_writer)
                # Skip baseline learning if anomalous
                continue

            # --- Baseline Learning (EWMA) ---
            # Re-calculate short term distribution
            st_distribution = {ip: count / st_total_pkts for ip, count in short_term_ips.items()}
            
            with traffic_analysis_lock:
                # Update rolling average for packets per second
                new_avg_pkts = (ALPHA * st_pkts_per_sec) + ((1 - ALPHA) * lt_data["avg_pkts_per_sec"])
                lt_data["avg_pkts_per_sec"] = new_avg_pkts
                
                # Update rolling average for IP distributions
                # First, decay all existing IPs
                for ip in lt_data["ips"]:
                    lt_data["ips"][ip] = lt_data["ips"][ip] * (1 - ALPHA)
                
                # Then add the current minute's contribution
                for ip, st_pct in st_distribution.items():
                    current = lt_data["ips"].get(ip, 0.0)
                    lt_data["ips"][ip] = current + (ALPHA * st_pct)
                    
                # Normalize just to handle any tiny floating point drifts over time
                total_lt_pct = sum(lt_data["ips"].values())
                if total_lt_pct > 0:
                    for ip in lt_data["ips"]:
                        lt_data["ips"][ip] /= total_lt_pct
                        
                lt_data["updates_count"] += 1
                
                # Snapshot for Supabase update
                baseline_to_save = dict(lt_data["ips"])
                avg_to_save = lt_data["avg_pkts_per_sec"]

            # Periodically (or on every update with small scale) sync baseline to Supabase
            try:
                supabase_writer.update_device_baseline(device_id, baseline_to_save, avg_to_save)
            except Exception as error:
                print(f"[!] Supabase baseline update failed for {mac_addr}: {error}")


def disconnect_worker(stop_event, supabase_writer):
    while not stop_event.wait(DISCONNECT_SCAN_INTERVAL_SEC):
        snapshots = mark_disconnected_devices()
        for snapshot in snapshots:
            mac_addr = str(snapshot["mac"])
            print(f"[*] Device {mac_addr} marked disconnected after {DISCONNECT_TIMEOUT_SEC:.0f}s inactivity.")
            try:
                supabase_writer.upsert_device(
                    str(snapshot["id"]),
                    mac_addr,
                    str(snapshot["name"]),
                    str(snapshot["ip"]),
                    "disconnected"
                )
            except Exception as error:
                print(f"[!] Supabase disconnect update failed for {mac_addr}: {error}")


def handle_dhcp_presence(mac_addr, hostname, ip_addr, message_type, supabase_writer, ja3_hash=None):
    normalized_mac = normalize_mac(mac_addr)
    if should_skip_duplicate(normalized_mac, message_type):
        return

    print("\n" + "=" * 50)
    print("[!] DEVICE DHCP ACTIVITY DETECTED")
    print(f"    MAC Address: {normalized_mac}")
    print(f"    Hostname:    {hostname}")
    print(f"    IP Address:  {ip_addr}")
    print(f"    DHCP Type:   {message_type}")
    print("=" * 50)

    previous_snapshot = get_registry_snapshot_for_mac(normalized_mac)
    if message_type == 5 and previous_snapshot is not None:
        is_malicious = bool(previous_snapshot.get("is_malicious"))
    else:
        is_malicious = check_threat_intel(normalized_mac, hostname, ja3_hash)

    if is_malicious:
        isolate_device(normalized_mac)
    else:
        print(f"[*] Device {normalized_mac} allowed for now.")

    snapshot = upsert_registry_on_presence(normalized_mac, hostname, ip_addr, is_malicious)

    try:
        supabase_writer.upsert_device(
            str(snapshot["id"]),
            normalized_mac,
            str(snapshot["name"]),
            str(snapshot["ip"]),
            str(snapshot["status"])
        )
        if is_malicious:
            supabase_writer.insert_metric(str(snapshot["id"]), 0.0, 0.0, 1, 0.0)
        print(f"[*] Supabase updated for device {normalized_mac} ({snapshot['status']}).")
    except Exception as error:
        print(f"[!] Supabase write failed for {normalized_mac}: {error}")


def log_packet_summary(data, layers, message_type, udp_dstport):
    timestamp = str(data.get("timestamp", "?"))
    mac_addr = first_value(layers, "dhcp_hw_mac_addr", "eth_src", "eth_dst") or "unknown"
    hostname = first_value(layers, "dhcp_option_hostname") or "-"
    ip_src = first_value(layers, "ip_src") or "?"
    ip_dst = first_value(layers, "ip_dst") or "?"
    dhcp_labels = {
        1: "discover",
        2: "offer",
        3: "request",
        5: "ack"
    }
    dhcp_type = dhcp_labels.get(message_type, str(message_type) if message_type is not None else "unknown")
    udp_text = str(udp_dstport) if udp_dstport is not None else "?"
    print(
        f"[pkt] ts={timestamp} dhcp={dhcp_type} udp_dst={udp_text} "
        f"mac={mac_addr} ip={ip_src}->{ip_dst} host={hostname}"
    )


def load_baselines(supabase_writer):
    print("[*] Syncing historical baselines from Supabase...")
    try:
        devices = supabase_writer.get_all_baselines()
        loaded_count = 0
        with traffic_analysis_lock:
            for device in devices:
                mac_addr = normalize_mac(device.get("mac", ""))
                baseline_dict = dict(device.get("traffic_baseline") or {})
                avg_pkts = float(device.get("avg_pkts_per_sec") or 0.0)
                
                if mac_addr and baseline_dict:
                    traffic_long_term[mac_addr] = {
                        "avg_pkts_per_sec": avg_pkts,
                        "ips": baseline_dict,
                        "updates_count": 1440 # Assume fully mature baseline
                    }
                    loaded_count += 1
        print(f"[*] Successfully loaded baselines for {loaded_count} devices.")
    except Exception as error:
        print(f"[!] Failed to sync history from Supabase: {error}")


def start_monitoring(supabase_writer):
    print(f"[*] Starting IoT Defender on interface '{NETWORK_INTERFACE}'...")
    print("[*] Filtering for DHCP Discover/Request (new joins + reconnects)...")
    print(f"[*] Duplicate suppression window: {DHCP_DUPLICATE_WINDOW_SEC:.1f} seconds")
    print(f"[*] Disconnect timeout: {DISCONNECT_TIMEOUT_SEC:.1f} seconds")
    print(f"[*] Metrics sample interval: {METRICS_SAMPLE_INTERVAL_SEC:.1f} seconds")
    print(f"[*] Ping probe config: count={PING_COUNT}, timeout={PING_TIMEOUT_SEC:.1f}s")
    print(f"[*] Logging raw packet output to '{LOG_FILE}'")
    print(f"[*] Packet logs to stdout: {'enabled' if SHOW_PACKET_LOGS else 'disabled'}")
    print("[*] Network activity capture: enabled (per-device kbps)")

    tshark_cmd = [
        "tshark", "-l", "-p", "-i", NETWORK_INTERFACE,
        "-T", "ek",
        "-f", "udp port 67 or udp port 68 or tcp port 443", 
        "-e", "dhcp.option.dhcp",
        "-e", "dhcp.hw.mac_addr",
        "-e", "dhcp.option.hostname",
        "-e", "tls.handshake.ja3", 
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "udp.dstport"
    ]
    process = subprocess.Popen(
        tshark_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    if process.stdout is None:
        print("[!] ERROR: Unable to read tshark output stream.")
        sys.exit(1)

    stop_event = threading.Event()
    metrics_thread = threading.Thread(
        target=metrics_worker,
        args=(stop_event, supabase_writer),
        daemon=True
    )
    traffic_thread = threading.Thread(
        target=network_activity_worker,
        args=(stop_event,),
        daemon=True
    )
    anomaly_thread = threading.Thread(
        target=anomaly_analysis_worker,
        args=(stop_event, supabase_writer),
        daemon=True
    )
    disconnect_thread = threading.Thread(
        target=disconnect_worker,
        args=(stop_event, supabase_writer),
        daemon=True
    )
    metrics_thread.start()
    traffic_thread.start()
    anomaly_thread.start()
    disconnect_thread.start()

    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        try:
            for line in process.stdout:
                log_file.write(line)
                log_file.flush()

                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                layers = data.get("layers")
                if not isinstance(layers, dict):
                    continue

                # --- 1. EXTRACT RAW FIELDS ---
                ja3_raw = layers.get("tls_handshake_ja3")
                if isinstance(ja3_raw, list) and len(ja3_raw) > 0:
                    ja3_hash = str(ja3_raw[0])
                else:
                    ja3_hash = ja3_raw

                message_type = parse_dhcp_message_type(
                    first_value(layers, "dhcp_option_dhcp", "dhcp_option_dhcp_message_type")
                )
                udp_dstport = parse_integer(first_value(layers, "udp_dstport", "udp_dst_port"))
                if message_type is None:
                    if udp_dstport == 67: message_type = 3
                    elif udp_dstport == 68: message_type = 5

                # --- 2. FILTER PACKETS ---
                # Skip the packet if it's not DHCP and doesn't have a JA3 hash
                if message_type not in {1, 3, 5} and not ja3_hash:
                    continue

                # --- 3. IDENTIFY DEVICE (Must happen before section 4) ---
                mac_addr = first_value(layers, "dhcp_hw_mac_addr", "eth_src", "eth_dst")
                if not mac_addr:
                    continue

                normalized_mac = normalize_mac(mac_addr)
                previous_snapshot = get_registry_snapshot_for_mac(normalized_mac)
                previous_ip = str(previous_snapshot["ip"]) if previous_snapshot else "0.0.0.0"
                previous_name = str(previous_snapshot["name"]) if previous_snapshot else "Unknown"
                hostname = first_value(layers, "dhcp_option_hostname") or previous_name
                ip_addr = resolve_device_ip(layers, message_type, previous_ip)

                # --- 4. LOGGING ---
                if ja3_hash:
                    print(f"[!] TLS HANDSHAKE: Captured JA3 for {normalized_mac}: {ja3_hash[:15]}...")
                else: 
                    print("[Debug] No JA3 Hash.")
                
                if SHOW_PACKET_LOGS and message_type in {1, 3, 5}:
                    log_packet_summary(data, layers, message_type, udp_dstport)

                # --- 5. EXECUTE THREAT CHECK & SUPABASE UPDATE ---
                # We only call this ONCE per loop to avoid the "stopping/hanging" issue
                try:
                    handle_dhcp_presence(normalized_mac, hostname, ip_addr, message_type, supabase_writer, ja3_hash)
                except Exception as e:
                    print(f"[!] ERROR during device update: {e}")

        except KeyboardInterrupt:
            print("\n[*] Shutting down IoT Defender...")
        finally:
            stop_event.set()
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()

            metrics_thread.join(timeout=2)
            traffic_thread.join(timeout=2)
            anomaly_thread.join(timeout=2)
            disconnect_thread.join(timeout=2)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] ERROR: This script must be run as root (sudo) to capture packets.")
        sys.exit(1)

    if shutil.which("tshark") is None:
        print("[!] ERROR: Tshark is not installed. Please install it (sudo apt install tshark).")
        sys.exit(1)

    if shutil.which("ping") is None:
        print("[!] ERROR: ping is not installed. Please install iputils-ping.")
        sys.exit(1)

    try:
        print("[*] Loading MAC vendor database...")
        # This will use the local cache or download updates if connected to internet
        vendor_scanner.update_vendors() 
    except Exception as e:
        print(f"[!] Warning: Could not update vendor list: {e}. Using local cache.")

    global ja3_db
    ja3_db = get_threat_database()

    supabase_url = required_env("SUPABASE_URL")
    supabase_service_role_key = required_env("SUPABASE_SERVICE_ROLE_KEY")

    writer = SupabaseWriter(
        supabase_url,
        supabase_service_role_key,
        SUPABASE_DEVICES_TABLE,
        SUPABASE_METRICS_TABLE
    )

    # Sync baselines before starting packet capture
    load_baselines(writer)

    start_monitoring(writer)
