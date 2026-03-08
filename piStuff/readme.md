# Pi Capture -> Supabase Ingest

This directory contains a packet capture script that detects DHCP joins and writes live device updates to Supabase for the frontend dashboard.

## 1) Prerequisites

- Raspberry Pi/Linux host with `tshark` installed.
- Root access (`sudo`) to capture packets.
- Supabase project with tables created from `frontend/supabase/schema.sql`.

Install tshark:

```bash
sudo apt update
sudo apt install -y tshark
```

## 2) Required Environment Variables

Set these before running:

```bash
export SUPABASE_URL="https://YOUR_PROJECT_ID.supabase.co"
export SUPABASE_SERVICE_ROLE_KEY="YOUR_SUPABASE_SERVICE_ROLE_KEY"
```

Optional overrides:

```bash
export NETWORK_INTERFACE="eth0"
export LOG_FILE="iot_defender_dhcp.log"
export SUPABASE_DEVICES_TABLE="devices"
export SUPABASE_METRICS_TABLE="device_metrics"
export DHCP_DUPLICATE_WINDOW_SEC="20"
export DISCONNECT_TIMEOUT_SEC="15"
export METRICS_SAMPLE_INTERVAL_SEC="5"
export ANOMALY_CHECK_INTERVAL_SEC="10"
export PING_COUNT="3"
export PING_TIMEOUT_SEC="1"
export SHOW_PACKET_LOGS="true"
```

Notes:

- `SUPABASE_SERVICE_ROLE_KEY` is sensitive. Keep it only on trusted backend hosts and never expose it in frontend code.
- Duplicate suppression only applies to short DHCP bursts. DHCP ACK-style packets can still refresh IP quickly.
- Devices are marked `disconnected` after `DISCONNECT_TIMEOUT_SEC` of inactivity.
- Active ping probes generate the latency/packet-loss series shown in the dashboard at `METRICS_SAMPLE_INTERVAL_SEC`.
- Passive traffic capture generates per-device `network_activity_kbps` so heavy internet usage is visible.
- Traffic anomaly checks run at `ANOMALY_CHECK_INTERVAL_SEC` while keeping a 24-hour rolling baseline.

## 3) Run

From the repo root:

```bash
sudo -E python3 piStuff/capture.py
```

`-E` preserves exported environment variables when running under `sudo`.

## 4) What Gets Written

On DHCP activity and metrics intervals:

- Upsert `devices` by `id` (deterministic from MAC).
- Insert periodic `device_metrics` rows with latency, packet loss, block events, and `network_activity_kbps`.
- `status` is `blocked` when threat intel marks the device malicious, `good` when healthy, and `disconnected` after inactivity timeout.
- Device IP is refreshed from DHCP/server response packets so `wlan0` clients do not stay at `0.0.0.0`.
