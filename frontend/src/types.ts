export type DeviceStatus = "good" | "suspicious" | "blocked" | "disconnected";
export type DeviceCategory = "iot" | "home";

export interface Device {
  id: string;
  name: string;
  type: string;
  vendor: string;
  model: string;
  ip: string;
  mac: string;
  deviceCategory?: DeviceCategory;
  lastSeenAt: string;
  status: DeviceStatus;
}

export interface TimeSeriesPoint {
  timestamp: string;
  value: number;
}

export interface DeviceMetricsSeries {
  deviceId: string;
  range: "1h";
  latencyMs: TimeSeriesPoint[];
  packetLossPct: TimeSeriesPoint[];
  blockEvents: TimeSeriesPoint[];
  networkActivityKbps: TimeSeriesPoint[];
}

export interface AdvisoryItem {
  title: string;
  source: string;
  url: string;
  publishedAt: string;
  category: "outage" | "security";
}

export interface DeviceAdvisoryReport {
  generatedAt: string;
  summary: string;
  items: AdvisoryItem[];
}

export interface DeviceResponse {
  generatedAt: string;
  devices: Device[];
}
