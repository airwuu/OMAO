import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DeviceDrawer } from "./DeviceDrawer";

const baseDevice = {
  id: "cam-1",
  name: "Porch Cam",
  type: "security_camera",
  vendor: "Artemis",
  model: "S1",
  ip: "192.168.0.21",
  mac: "00:16:3E:11:22:31",
  status: "good",
  lastSeenAt: "2026-03-07T00:00:00.000Z",
  deviceCategory: "iot"
} as const;

describe("DeviceDrawer", () => {
  it("shows placeholder when no device is selected", () => {
    render(
      <DeviceDrawer
        device={null}
        metrics={null}
        metricsLoading={false}
        metricsError={null}
        advisoryReport={null}
        advisoryLoading={false}
        advisoryError={null}
        deleteLoading={false}
        deleteError={null}
        onDeleteDevice={vi.fn(async () => {})}
        onRefreshAdvisories={vi.fn(async () => {})}
        onClose={vi.fn()}
      />
    );

    expect(screen.getByText("Device Console")).toBeInTheDocument();
  });

  it("renders selected device details and advisory summary", () => {
    render(
      <DeviceDrawer
        device={{ ...baseDevice }}
        metrics={{
          deviceId: "cam-1",
          range: "1h",
          latencyMs: [{ timestamp: "2026-03-07T00:00:00.000Z", value: 20 }],
          packetLossPct: [{ timestamp: "2026-03-07T00:00:00.000Z", value: 0.3 }],
          blockEvents: [{ timestamp: "2026-03-07T00:00:00.000Z", value: 0 }]
        }}
        metricsLoading={false}
        metricsError={null}
        advisoryReport={{
          generatedAt: "2026-03-07T00:00:00.000Z",
          summary: "No high-severity issues found.",
          items: [
            {
              title: "Status normal",
              source: "Mock Feed",
              url: "https://example.com",
              publishedAt: "2026-03-06T22:00:00.000Z",
              category: "outage"
            }
          ]
        }}
        advisoryLoading={false}
        advisoryError={null}
        deleteLoading={false}
        deleteError={null}
        onDeleteDevice={vi.fn(async () => {})}
        onRefreshAdvisories={vi.fn(async () => {})}
        onClose={vi.fn()}
      />
    );

    expect(screen.getByText("Porch Cam")).toBeInTheDocument();
    expect(screen.getByText("Outage + Security Agent")).toBeInTheDocument();
    expect(screen.getByText(/Status normal/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /delete device/i })).toBeInTheDocument();
  });
});
