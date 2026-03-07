import type { Device } from "../types";

export interface GraphNode {
  id: string;
  label: string;
  kind: "hub" | "device";
  device?: Device;
}

export interface GraphLink {
  source: string;
  target: string;
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

export const HUB_NODE_ID = "local-network-hub";

export function buildGraphData(devices: Device[]): GraphData {
  const deviceNodes = devices.map((device) => ({
    id: device.id,
    label: device.name,
    kind: "device" as const,
    device
  }));

  return {
    nodes: [
      {
        id: HUB_NODE_ID,
        label: "MODEM / LOCAL NETWORK",
        kind: "hub"
      },
      ...deviceNodes
    ],
    links: deviceNodes.map((node) => ({
      source: HUB_NODE_ID,
      target: node.id
    }))
  };
}
