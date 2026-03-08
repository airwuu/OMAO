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
```

Notes:

- `SUPABASE_SERVICE_ROLE_KEY` is sensitive. Keep it only on trusted backend hosts and never expose it in frontend code.
- Duplicate suppression only applies to short DHCP bursts. Reconnects after the window are written as new metric events.

## 3) Run

From the repo root:

```bash
sudo -E python3 piStuff/capture.py
```

`-E` preserves exported environment variables when running under `sudo`.

## 4) What Gets Written

On each accepted DHCP join/reconnect event:

- Upsert `devices` by `id` (deterministic from MAC).
- Insert one `device_metrics` row.
- `status` is set to `blocked` when threat intel marks the device malicious; otherwise `good`.
