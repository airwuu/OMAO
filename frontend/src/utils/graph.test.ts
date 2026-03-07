import { describe, expect, it } from "vitest";
import { buildGraphData, HUB_NODE_ID, syncGraphData } from "./graph";

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

const circleDevices = Array.from({ length: 6 }, (_, index) => ({
  id: `node-${index + 1}`,
  name: `Node ${index + 1}`,
  type: "sensor",
  vendor: "V",
  model: "M",
  ip: `192.168.1.${index + 10}`,
  mac: `AA:BB:CC:DD:EE:${String(index).padStart(2, "0")}`,
  status: "good" as const,
  lastSeenAt: "2026-03-07T00:00:00.000Z",
  deviceCategory: "iot" as const
}));

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

  it("positions devices around a full circle instead of one side", () => {
    const graph = buildGraphData(circleDevices);
    const deviceNodes = graph.nodes.filter((node) => node.kind === "device");

    const xCoords = deviceNodes.map((node) => node.fx ?? node.x ?? 0);
    const yCoords = deviceNodes.map((node) => node.fy ?? node.y ?? 0);

    expect(Math.min(...xCoords)).toBeLessThan(0);
    expect(Math.max(...xCoords)).toBeGreaterThan(0);
    expect(Math.min(...yCoords)).toBeLessThan(0);
    expect(Math.max(...yCoords)).toBeGreaterThan(0);
  });
});

describe("syncGraphData", () => {
  it("preserves existing graph objects during polling updates", () => {
    const initial = buildGraphData([...devices]);

    const initialHub = initial.nodes[0];
    const initialCamNode = initial.nodes.find((node) => node.id === "cam-1");
    const initialCamLink = initial.links.find((link) => link.target === "cam-1");

    const updatedDevices = [
      {
        ...devices[0],
        name: "Camera (Renamed)",
        status: "blocked" as const
      },
      devices[1]
    ];
    const next = syncGraphData(initial, updatedDevices);

    const nextCamNode = next.nodes.find((node) => node.id === "cam-1");
    const nextCamLink = next.links.find((link) => link.target === "cam-1");

    expect(next.nodes[0]).toBe(initialHub);
    expect(nextCamNode).toBe(initialCamNode);
    expect(nextCamNode?.label).toBe("Camera (Renamed)");
    expect(nextCamNode?.device?.status).toBe("blocked");
    expect(nextCamLink).toBe(initialCamLink);
  });
});
