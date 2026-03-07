import type { Device, DeviceAdvisoryReport, DeviceMetricsSeries, DeviceResponse } from "../types";

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`Request failed (${response.status}): ${path}`);
  }

  return (await response.json()) as T;
}

export const iotApi = {
  async getDevices(): Promise<Device[]> {
    const payload = await fetchJson<DeviceResponse>("/api/iot/devices");
    return payload.devices;
  },

  async getMetrics(deviceId: string): Promise<DeviceMetricsSeries> {
    return fetchJson<DeviceMetricsSeries>(`/api/iot/devices/${deviceId}/metrics?range=1h`);
  },

  async getAdvisories(deviceId: string): Promise<DeviceAdvisoryReport> {
    return fetchJson<DeviceAdvisoryReport>(`/api/iot/devices/${deviceId}/advisories`);
  }
};
