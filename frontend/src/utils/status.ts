import type { DeviceStatus } from "../types";

export const STATUS_META: Record<
  DeviceStatus,
  { label: string; color: string; glow: string; summary: string }
> = {
  good: {
    label: "good",
    color: "#6CFF6C",
    glow: "rgba(108, 255, 108, 0.55)",
    summary: "stable"
  },
  suspicious: {
    label: "suspicious",
    color: "#F8F36B",
    glow: "rgba(248, 243, 107, 0.5)",
    summary: "anomalous"
  },
  blocked: {
    label: "blocked",
    color: "#FF6464",
    glow: "rgba(255, 100, 100, 0.55)",
    summary: "rate limited / blocked"
  },
  disconnected: {
    label: "disconnected",
    color: "#7BB8FF",
    glow: "rgba(123, 184, 255, 0.5)",
    summary: "offline"
  }
};

export function statusToClass(status: DeviceStatus): string {
  return `status-${status}`;
}
