import type { Device } from "../types";

interface GraphCoordinates {
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  fx?: number;
  fy?: number;
}

export interface GraphNode extends GraphCoordinates {
  id: string;
  label: string;
  kind: "hub" | "device";
  device?: Device;
}

export type GraphLinkEndpoint = string | { id?: string };

export interface GraphLink {
  source: GraphLinkEndpoint;
  target: GraphLinkEndpoint;
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

export const HUB_NODE_ID = "local-network-hub";
const HUB_LABEL = "MODEM / LOCAL NETWORK";
const DEVICE_RING_BASE_RADIUS = 180;
const DEVICE_RING_RADIUS_STEP = 7;
const DEVICE_RING_MAX_RADIUS = 320;

function pinHubNode(node: GraphNode & GraphCoordinates): void {
  node.label = HUB_LABEL;
  node.x = 0;
  node.y = 0;
  node.vx = 0;
  node.vy = 0;
  node.fx = 0;
  node.fy = 0;
}

function createHubNode(): GraphNode & GraphCoordinates {
  const hubNode: GraphNode & GraphCoordinates = {
    id: HUB_NODE_ID,
    label: HUB_LABEL,
    kind: "hub"
  };
  pinHubNode(hubNode);
  return hubNode;
}

function createDeviceNode(device: Device): GraphNode & GraphCoordinates {
  return {
    id: device.id,
    label: device.name,
    kind: "device",
    device
  };
}

function applyCircularLayout(deviceNodes: Array<GraphNode & GraphCoordinates>): void {
  if (deviceNodes.length === 0) {
    return;
  }

  const radius = Math.min(
    DEVICE_RING_MAX_RADIUS,
    DEVICE_RING_BASE_RADIUS + deviceNodes.length * DEVICE_RING_RADIUS_STEP
  );

  // Start at top-center and distribute all IoT nodes evenly around the hub.
  const startAngle = -Math.PI / 2;
  deviceNodes.forEach((node, index) => {
    const angle = startAngle + (index * 2 * Math.PI) / deviceNodes.length;
    const x = Math.cos(angle) * radius;
    const y = Math.sin(angle) * radius;

    node.x = x;
    node.y = y;
    node.vx = 0;
    node.vy = 0;
    node.fx = x;
    node.fy = y;
  });
}

function getEndpointId(endpoint: GraphLinkEndpoint): string | null {
  if (typeof endpoint === "string") {
    return endpoint;
  }

  if (endpoint && typeof endpoint.id === "string") {
    return endpoint.id;
  }

  return null;
}

export function buildGraphData(devices: Device[]): GraphData {
  const deviceNodes = devices.map((device) => createDeviceNode(device));
  applyCircularLayout(deviceNodes);

  return {
    nodes: [
      createHubNode(),
      ...deviceNodes
    ],
    links: deviceNodes.map((node) => ({
      source: HUB_NODE_ID,
      target: node.id
    }))
  };
}

export function syncGraphData(previous: GraphData, devices: Device[]): GraphData {
  const previousHub = previous.nodes.find((node) => node.kind === "hub");
  const hubNode = (previousHub ?? createHubNode()) as GraphNode & GraphCoordinates;
  pinHubNode(hubNode);

  const previousDeviceNodes = previous.nodes.filter(
    (node): node is GraphNode & GraphCoordinates => node.kind === "device"
  );
  const remainingDevices = new Map(devices.map((device) => [device.id, device]));

  // Preserve existing node objects so polling updates don't restart graph layout.
  const nextDeviceNodes: Array<GraphNode & GraphCoordinates> = [];
  for (const previousNode of previousDeviceNodes) {
    const device = remainingDevices.get(previousNode.id);
    if (!device) {
      continue;
    }

    previousNode.label = device.name;
    previousNode.device = device;
    nextDeviceNodes.push(previousNode);
    remainingDevices.delete(previousNode.id);
  }

  for (const device of devices) {
    if (!remainingDevices.has(device.id)) {
      continue;
    }
    nextDeviceNodes.push(createDeviceNode(device));
    remainingDevices.delete(device.id);
  }

  applyCircularLayout(nextDeviceNodes);

  const previousLinksByTarget = new Map<string, GraphLink>();
  for (const link of previous.links) {
    const targetId = getEndpointId(link.target);
    if (targetId) {
      previousLinksByTarget.set(targetId, link);
    }
  }

  const nextLinks = nextDeviceNodes.map((node) => {
    const link = previousLinksByTarget.get(node.id);
    if (!link) {
      return {
        source: HUB_NODE_ID,
        target: node.id
      };
    }

    link.source = HUB_NODE_ID;
    link.target = node.id;
    return link;
  });

  return {
    nodes: [hubNode, ...nextDeviceNodes],
    links: nextLinks
  };
}
