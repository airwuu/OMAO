import datetime
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# --- CONFIGURATION ---
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "eth0").strip() or "eth0"
LOG_FILE = os.getenv("LOG_FILE", "iot_defender_dhcp.log").strip() or "iot_defender_dhcp.log"
SUPABASE_DEVICES_TABLE = os.getenv("SUPABASE_DEVICES_TABLE", "devices").strip() or "devices"
SUPABASE_METRICS_TABLE = os.getenv("SUPABASE_METRICS_TABLE", "device_metrics").strip() or "device_metrics"


def read_duplicate_window_seconds() -> float:
    raw = os.getenv("DHCP_DUPLICATE_WINDOW_SEC", "20").strip() or "20"
    try:
        value = float(raw)
    except ValueError:
        print(f"[!] ERROR: DHCP_DUPLICATE_WINDOW_SEC must be numeric, received '{raw}'.")
        sys.exit(1)

    if value <= 0:
        print("[!] ERROR: DHCP_DUPLICATE_WINDOW_SEC must be greater than 0.")
        sys.exit(1)

    return value


DHCP_DUPLICATE_WINDOW_SEC = read_duplicate_window_seconds()

# Track recent MAC address activity to suppress duplicate Discover/Request bursts.
recent_devices = {}


def check_threat_intel(mac_addr, hostname):
    """
    Placeholder: Check if the device's MAC or Hostname is suspicious.
    """
    print(f"[*] Analyzing {hostname} ({mac_addr}) against threat database...")
    # Add your API calls or local blacklist checks here.
    return False


def isolate_device(mac_addr):
    """
    Placeholder: Block the device using iptables or another method.
    """
    print(f"[!] ACTION TAKEN: Isolating device {mac_addr} from network.")
    # Example: os.system(f"iptables -A FORWARD -m mac --mac-source {mac_addr} -j DROP")


def required_env(name):
    value = os.getenv(name, "").strip()
    if value:
        return value

    print(f"[!] ERROR: Missing required environment variable: {name}")
    sys.exit(1)


def current_timestamp_utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_mac(raw_mac):
    return raw_mac.strip().lower().replace("-", ":")


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

        if parsed.is_unspecified or parsed.is_multicast or parsed.is_reserved:
            continue

        if value == "255.255.255.255":
            continue

        return value

    return "0.0.0.0"


def should_skip_duplicate(mac_addr):
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

    def write_join_event(self, mac_addr, hostname, ip_addr, is_malicious):
        timestamp = current_timestamp_utc()
        device_id = build_device_id(mac_addr)
        status = "blocked" if is_malicious else "good"
        safe_hostname = fallback_device_name(hostname, mac_addr)

        device_row = [{
            "id": device_id,
            "name": safe_hostname,
            "type": "unknown",
            "vendor": "Unknown",
            "model": "Unknown",
            "ip": ip_addr,
            "mac": mac_addr,
            "device_category": "iot",
            "last_seen_at": timestamp,
            "status": status
        }]

        metric_row = [{
            "device_id": device_id,
            "recorded_at": timestamp,
            "latency_ms": 0,
            "packet_loss_pct": 0,
            "block_events": 1 if is_malicious else 0
        }]

        encoded_devices_table = urllib.parse.quote(self.devices_table, safe="")
        encoded_metrics_table = urllib.parse.quote(self.metrics_table, safe="")

        self._post(
            f"/rest/v1/{encoded_devices_table}?on_conflict=id",
            device_row,
            "resolution=merge-duplicates,return=minimal"
        )
        self._post(
            f"/rest/v1/{encoded_metrics_table}",
            metric_row,
            "return=minimal"
        )


def handle_new_device(mac_addr, hostname, ip_addr, supabase_writer):
    """
    Core logic triggered when a DHCP join is detected.
    """
    normalized_mac = normalize_mac(mac_addr)
    if should_skip_duplicate(normalized_mac):
        return

    print("\n" + "=" * 50)
    print("[!] NEW DEVICE JOINED THE NETWORK")
    print(f"    MAC Address: {normalized_mac}")
    print(f"    Hostname:    {hostname}")
    print(f"    IP Address:  {ip_addr}")
    print("=" * 50)

    is_malicious = check_threat_intel(normalized_mac, hostname)
    if is_malicious:
        isolate_device(normalized_mac)
    else:
        print(f"[*] Device {normalized_mac} allowed for now.")

    try:
        supabase_writer.write_join_event(normalized_mac, hostname, ip_addr, is_malicious)
        print(f"[*] Supabase updated for device {normalized_mac}.")
    except Exception as error:
        print(f"[!] Supabase write failed for {normalized_mac}: {error}")


def start_monitoring(supabase_writer):
    print(f"[*] Starting IoT Defender on interface '{NETWORK_INTERFACE}'...")
    print("[*] Filtering for DHCP Discover/Request (new joins + reconnects)...")
    print(f"[*] Duplicate suppression window: {DHCP_DUPLICATE_WINDOW_SEC:.1f} seconds")
    print(f"[*] Logging raw packet output to '{LOG_FILE}'")

    # Tshark command focused on DHCP handshake packets.
    tshark_cmd = [
        "tshark", "-l", "-i", NETWORK_INTERFACE,
        "-T", "ek",
        "-f", "udp port 67 or udp port 68",  # BPF filter for speed.
        "-e", "dhcp.option.dhcp",            # Type (1=Discover, 3=Request).
        "-e", "dhcp.hw.mac_addr",            # MAC of the device.
        "-e", "dhcp.option.hostname",        # Hostname of the device.
        "-e", "ip.src",
        "-e", "ip.dst"
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

                message_type = parse_dhcp_message_type(first_value(layers, "dhcp_option_dhcp"))
                if message_type not in {1, 3}:
                    continue

                mac_addr = first_value(layers, "dhcp_hw_mac_addr")
                if not mac_addr:
                    continue

                hostname = first_value(layers, "dhcp_option_hostname") or "Unknown"
                ip_addr = normalize_ip(
                    first_value(layers, "dhcp_ip_your", "bootp_ip_your", "bootp_ip_yiaddr"),
                    first_value(layers, "ip_src"),
                    first_value(layers, "ip_dst")
                )

                handle_new_device(mac_addr, hostname, ip_addr, supabase_writer)
        except KeyboardInterrupt:
            print("\n[*] Shutting down IoT Defender...")
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] ERROR: This script must be run as root (sudo) to capture packets.")
        sys.exit(1)

    if shutil.which("tshark") is None:
        print("[!] ERROR: Tshark is not installed. Please install it (sudo apt install tshark).")
        sys.exit(1)

    supabase_url = required_env("SUPABASE_URL")
    supabase_service_role_key = required_env("SUPABASE_SERVICE_ROLE_KEY")

    writer = SupabaseWriter(
        supabase_url,
        supabase_service_role_key,
        SUPABASE_DEVICES_TABLE,
        SUPABASE_METRICS_TABLE
    )

    start_monitoring(writer)
