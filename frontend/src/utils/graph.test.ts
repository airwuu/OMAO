import { describe, expect, it } from "vitest";
import { buildGraphData, HUB_NODE_ID } from "./graph";

const devices = [
  {
    id: "cam-1",
    name: "Camera",
    type: "security_camera",
    vendor: "V",
    model: "M",
    ip: "192.168.1.2",
    mac: "AA",
    status: "good",
    lastSeenAt: "2026-03-07T00:00:00.000Z",
    deviceCategory: "iot"
  },
  {
    id: "thermo-1",
    name: "Thermostat",
    type: "thermostat",
    vendor: "V",
    model: "M",
    ip: "192.168.1.3",
    mac: "BB",
    status: "suspicious",
    lastSeenAt: "2026-03-07T00:00:00.000Z",
    deviceCategory: "iot"
  }
] as const;

describe("buildGraphData", () => {
  it("creates a single hub node and links all devices to it", () => {
    const graph = buildGraphData([...devices]);

    expect(graph.nodes[0]?.id).toBe(HUB_NODE_ID);
    expect(graph.nodes).toHaveLength(3);
    expect(graph.links).toEqual([
      { source: HUB_NODE_ID, target: "cam-1" },
      { source: HUB_NODE_ID, target: "thermo-1" }
    ]);
  });
});
