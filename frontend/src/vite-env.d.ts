/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_SUPABASE_URL?: string;
  readonly VITE_SUPABASE_ANON_KEY?: string;
  readonly VITE_SUPABASE_DEVICES_TABLE?: string;
  readonly VITE_SUPABASE_METRICS_TABLE?: string;
  readonly VITE_SUPABASE_ADVISORIES_TABLE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
