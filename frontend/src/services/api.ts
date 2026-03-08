import type {
  AdvisoryItem,
  Device,
  DeviceAdvisoryReport,
  DeviceCategory,
  DeviceMetricsSeries,
  DeviceResponse,
  DeviceStatus,
  TimeSeriesPoint
} from "../types";
import { isSupabaseConfigured, supabase } from "./supabaseClient";

const SUPABASE_DEVICES_TABLE = import.meta.env.VITE_SUPABASE_DEVICES_TABLE?.trim() || "devices";
const SUPABASE_METRICS_TABLE = import.meta.env.VITE_SUPABASE_METRICS_TABLE?.trim() || "device_metrics";
const SUPABASE_ADVISORIES_TABLE =
  import.meta.env.VITE_SUPABASE_ADVISORIES_TABLE?.trim() || "device_advisories";

const METRICS_SAMPLE_LIMIT = 60;
const API_RANGE: DeviceMetricsSeries["range"] = "1h";

type JsonRecord = Record<string, unknown>;

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`Request failed (${response.status}): ${path}`);
  }

  return (await response.json()) as T;
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null;
}

function toRows(value: unknown): JsonRecord[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter(isRecord);
}

function readString(row: JsonRecord, ...keys: string[]): string | null {
  for (const key of keys) {
    const value = row[key];
    if (typeof value === "string" && value.trim()) {
      return value;
    }
  }

  return null;
}

function readNumber(row: JsonRecord, ...keys: string[]): number | null {
  for (const key of keys) {
    const value = row[key];
    if (typeof value === "number" && Number.isFinite(value)) {
      return value;
    }
    if (typeof value === "string" && value.trim()) {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) {
        return parsed;
      }
    }
  }

  return null;
}

function toTimestampValue(timestamp: string): number {
  const parsed = Date.parse(timestamp);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function normalizeStatus(value: string | null): DeviceStatus {
  if (value === "suspicious" || value === "blocked" || value === "good" || value === "disconnected") {
    return value;
  }

  return "good";
}

function normalizeCategory(value: string | null): DeviceCategory | undefined {
  if (value === "iot" || value === "home") {
    return value;
  }

  return undefined;
}

function normalizeAdvisoryCategory(value: string | null): AdvisoryItem["category"] {
  return value === "security" ? "security" : "outage";
}

function formatSupabaseError(table: string, error: { message: string }): Error {
  return new Error(`Supabase query failed for "${table}": ${error.message}`);
}

function hasMissingColumnCode(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: string }).code === "42703"
  );
}

function mapDeviceRow(row: JsonRecord): Device | null {
  const id = readString(row, "id");
  if (!id) {
    return null;
  }

  return {
    id,
    name: readString(row, "name") ?? id,
    type: readString(row, "type") ?? "unknown",
    vendor: readString(row, "vendor") ?? "Unknown",
    model: readString(row, "model") ?? "Unknown",
    ip: readString(row, "ip") ?? "0.0.0.0",
    mac: readString(row, "mac") ?? "00:00:00:00:00:00",
    deviceCategory: normalizeCategory(readString(row, "device_category", "deviceCategory")),
    lastSeenAt:
      readString(row, "last_seen_at", "lastSeenAt", "updated_at", "updatedAt") ?? new Date().toISOString(),
    status: normalizeStatus(readString(row, "status"))
  };
}

function mapMetricPoint(row: JsonRecord): {
  timestamp: string;
  latencyMs: number;
  packetLossPct: number;
  blockEvents: number;
} | null {
  const timestamp = readString(row, "recorded_at", "timestamp", "created_at", "createdAt");
  if (!timestamp) {
    return null;
  }

  return {
    timestamp,
    latencyMs: readNumber(row, "latency_ms", "latencyMs", "latency") ?? 0,
    packetLossPct: readNumber(row, "packet_loss_pct", "packetLossPct", "packet_loss", "packetLoss") ?? 0,
    blockEvents: readNumber(row, "block_events", "blockEvents", "blocked_events", "blockedEvents") ?? 0
  };
}

function mapAdvisoryRow(row: JsonRecord): AdvisoryItem | null {
  const title = readString(row, "title");
  if (!title) {
    return null;
  }

  return {
    title,
    source: readString(row, "source") ?? "Supabase",
    url: readString(row, "url") ?? "#",
    publishedAt: readString(row, "published_at", "publishedAt", "created_at", "createdAt") ?? new Date().toISOString(),
    category: normalizeAdvisoryCategory(readString(row, "category"))
  };
}

function mapMetricSeries(deviceId: string, rows: JsonRecord[]): DeviceMetricsSeries {
  const points = rows
    .map(mapMetricPoint)
    .filter((point): point is NonNullable<ReturnType<typeof mapMetricPoint>> => point !== null)
    .sort((left, right) => toTimestampValue(left.timestamp) - toTimestampValue(right.timestamp))
    .slice(-METRICS_SAMPLE_LIMIT);

  const toSeries = (selector: (point: (typeof points)[number]) => number): TimeSeriesPoint[] =>
    points.map((point) => ({
      timestamp: point.timestamp,
      value: selector(point)
    }));

  return {
    deviceId,
    range: API_RANGE,
    latencyMs: toSeries((point) => point.latencyMs),
    packetLossPct: toSeries((point) => point.packetLossPct),
    blockEvents: toSeries((point) => point.blockEvents)
  };
}

function advisorySummary(status: DeviceStatus | null, advisoryCount: number): string {
  if (status === "disconnected") {
    return "Device is currently offline. Check power, Wi-Fi signal, and router connectivity before investigating advisories.";
  }

  if (status === "blocked") {
    return "Network behavior suggests active rate limiting or endpoint block. Investigate upstream service health and firewall rules.";
  }

  if (status === "suspicious") {
    return "Anomalous behavior detected. Review firmware posture and recent provider incidents.";
  }

  if (advisoryCount > 0) {
    return "Recent outage and security findings were pulled from Supabase for this device.";
  }

  return "No high-severity advisories found for this device.";
}

function requireSupabase() {
  if (!supabase) {
    throw new Error("Supabase is not configured.");
  }

  return supabase;
}

async function fetchRowsByDeviceId(table: string, deviceId: string): Promise<JsonRecord[]> {
  const client = requireSupabase();
  const bySnakeCase = await client.from(table).select("*").eq("device_id", deviceId);
  if (!bySnakeCase.error) {
    return toRows(bySnakeCase.data);
  }

  if (!hasMissingColumnCode(bySnakeCase.error)) {
    throw formatSupabaseError(table, bySnakeCase.error);
  }

  const byCamelCase = await client.from(table).select("*").eq("deviceId", deviceId);
  if (byCamelCase.error) {
    throw formatSupabaseError(table, byCamelCase.error);
  }

  return toRows(byCamelCase.data);
}

async function fetchDeviceStatus(deviceId: string): Promise<DeviceStatus | null> {
  const client = requireSupabase();
  const byId = await client.from(SUPABASE_DEVICES_TABLE).select("status").eq("id", deviceId).maybeSingle();

  if (!byId.error) {
    const status = byId.data && isRecord(byId.data) ? readString(byId.data, "status") : null;
    return status ? normalizeStatus(status) : null;
  }

  if (!hasMissingColumnCode(byId.error)) {
    return null;
  }

  const byDeviceId = await client.from(SUPABASE_DEVICES_TABLE).select("status").eq("device_id", deviceId).maybeSingle();
  if (byDeviceId.error) {
    return null;
  }

  const status = byDeviceId.data && isRecord(byDeviceId.data) ? readString(byDeviceId.data, "status") : null;
  return status ? normalizeStatus(status) : null;
}

async function getDevicesFromSupabase(): Promise<Device[]> {
  const client = requireSupabase();
  const { data, error } = await client.from(SUPABASE_DEVICES_TABLE).select("*");

  if (error) {
    throw formatSupabaseError(SUPABASE_DEVICES_TABLE, error);
  }

  return toRows(data)
    .map(mapDeviceRow)
    .filter((device): device is Device => device !== null);
}

async function getMetricsFromSupabase(deviceId: string): Promise<DeviceMetricsSeries> {
  const rows = await fetchRowsByDeviceId(SUPABASE_METRICS_TABLE, deviceId);
  return mapMetricSeries(deviceId, rows);
}

async function getAdvisoriesFromSupabase(deviceId: string): Promise<DeviceAdvisoryReport> {
  const [rows, status] = await Promise.all([
    fetchRowsByDeviceId(SUPABASE_ADVISORIES_TABLE, deviceId),
    fetchDeviceStatus(deviceId)
  ]);

  const items = rows
    .map(mapAdvisoryRow)
    .filter((item): item is AdvisoryItem => item !== null)
    .sort((left, right) => toTimestampValue(right.publishedAt) - toTimestampValue(left.publishedAt));

  const firstRow = rows[0];
  const generatedAt = firstRow ? readString(firstRow, "generated_at", "generatedAt") : null;
  const summary = firstRow ? readString(firstRow, "summary") : null;

  return {
    generatedAt: generatedAt ?? new Date().toISOString(),
    summary: summary ?? advisorySummary(status, items.length),
    items
  };
}

async function deleteDeviceFromSupabase(deviceId: string): Promise<void> {
  const client = requireSupabase();
  const byId = await client.from(SUPABASE_DEVICES_TABLE).delete().eq("id", deviceId);
  if (!byId.error) {
    return;
  }

  if (!hasMissingColumnCode(byId.error)) {
    throw formatSupabaseError(SUPABASE_DEVICES_TABLE, byId.error);
  }

  const byDeviceId = await client.from(SUPABASE_DEVICES_TABLE).delete().eq("device_id", deviceId);
  if (byDeviceId.error) {
    throw formatSupabaseError(SUPABASE_DEVICES_TABLE, byDeviceId.error);
  }
}

async function getDevicesFromMockApi(): Promise<Device[]> {
  const payload = await fetchJson<DeviceResponse>("/api/iot/devices");
  return payload.devices;
}

const useSupabase = isSupabaseConfigured();

export const iotApi = {
  async getDevices(): Promise<Device[]> {
    if (useSupabase) {
      return getDevicesFromSupabase();
    }

    return getDevicesFromMockApi();
  },

  async getMetrics(deviceId: string): Promise<DeviceMetricsSeries> {
    if (useSupabase) {
      return getMetricsFromSupabase(deviceId);
    }

    return fetchJson<DeviceMetricsSeries>(`/api/iot/devices/${deviceId}/metrics?range=1h`);
  },

  async getAdvisories(deviceId: string): Promise<DeviceAdvisoryReport> {
    if (useSupabase) {
      return getAdvisoriesFromSupabase(deviceId);
    }

    return fetchJson<DeviceAdvisoryReport>(`/api/iot/devices/${deviceId}/advisories`);
  },

  async deleteDevice(deviceId: string): Promise<void> {
    if (useSupabase) {
      await deleteDeviceFromSupabase(deviceId);
    }
  }
};
