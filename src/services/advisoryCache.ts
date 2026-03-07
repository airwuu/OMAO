import type { DeviceAdvisoryReport } from "../types";

interface CacheEntry {
  value: DeviceAdvisoryReport;
  expiresAt: number;
}

export class AdvisoryCache {
  private readonly entries = new Map<string, CacheEntry>();

  constructor(private readonly ttlMs: number) {}

  get(deviceId: string, now = Date.now()): DeviceAdvisoryReport | null {
    const cached = this.entries.get(deviceId);
    if (!cached) {
      return null;
    }

    if (cached.expiresAt <= now) {
      this.entries.delete(deviceId);
      return null;
    }

    return cached.value;
  }

  set(deviceId: string, value: DeviceAdvisoryReport, now = Date.now()): void {
    this.entries.set(deviceId, {
      value,
      expiresAt: now + this.ttlMs
    });
  }

  clear(): void {
    this.entries.clear();
  }
}
