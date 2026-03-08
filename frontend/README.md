# HackMerced XI IoT Dashboard

This frontend can read telemetry directly from Supabase.

## 1. Configure environment variables

Copy `.env.example` to `.env` and set:

```bash
VITE_SUPABASE_URL=https://YOUR_PROJECT_ID.supabase.co
VITE_SUPABASE_ANON_KEY=YOUR_SUPABASE_ANON_KEY
```

Optional table name overrides:

```bash
VITE_SUPABASE_DEVICES_TABLE=devices
VITE_SUPABASE_METRICS_TABLE=device_metrics
VITE_SUPABASE_ADVISORIES_TABLE=device_advisories
```

If Supabase URL/key are not set, the app falls back to the local mock API.

## 2. Create tables in Supabase

Run [`supabase/schema.sql`](supabase/schema.sql) in the Supabase SQL editor.

## 3. Start the app

```bash
npm install
npm run dev
```

The UI now pulls devices, metrics, and advisories from Supabase.
