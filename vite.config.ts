import react from "@vitejs/plugin-react";
import { URL } from "node:url";
import { defineConfig, type Plugin } from "vite";

type DeviceStatus = "good" | "suspicious" | "blocked";
type DeviceCategory = "iot" | "home";

interface DeviceSeed {
  id: string;
  name: string;
  type: string;
  vendor: string;
  model: string;
  ip: string;
  mac: string;
  category: DeviceCategory;
  statusPattern: DeviceStatus[];
}

interface AdvisoryItem {
  title: string;
  source: string;
  url: string;
  publishedAt: string;
  category: "outage" | "security";
}

const DEVICE_CATALOG: DeviceSeed[] = [
  {
    id: "cam-garage-01",
    name: "Garage Cam",
    type: "security_camera",
    vendor: "Artemis",
    model: "Sentinel S2",
    ip: "192.168.0.21",
    mac: "00:16:3E:11:22:31",
    category: "iot",
    statusPattern: ["good", "good", "suspicious", "good", "good", "blocked"]
  },
  {
    id: "thermo-main-01",
    name: "Main Thermostat",
    type: "thermostat",
    vendor: "ThermIQ",
    model: "T-900",
    ip: "192.168.0.11",
    mac: "00:16:3E:11:22:10",
    category: "iot",
    statusPattern: ["good", "good", "good", "suspicious", "good", "good"]
  },
  {
    id: "fridge-kitchen-01",
    name: "Kitchen Fridge",
    type: "smart_fridge",
    vendor: "FrostByte",
    model: "FB-XR",
    ip: "192.168.0.15",
    mac: "00:16:3E:11:22:15",
    category: "iot",
    statusPattern: ["good", "suspicious", "good", "good", "good", "good"]
  },
  {
    id: "cam-porch-01",
    name: "Porch Cam",
    type: "security_camera",
    vendor: "Artemis",
    model: "Sentinel Mini",
    ip: "192.168.0.24",
    mac: "00:16:3E:11:22:34",
    category: "iot",
    statusPattern: ["good", "good", "good", "good", "suspicious", "good"]
  },
  {
    id: "lock-front-01",
    name: "Front Door Lock",
    type: "smart_lock",
    vendor: "LatchLink",
    model: "LK-2",
    ip: "192.168.0.40",
    mac: "00:16:3E:11:22:40",
    category: "iot",
    statusPattern: ["good", "good", "suspicious", "good", "good", "good"]
  },
  {
    id: "sensor-basement-01",
    name: "Basement Sensor",
    type: "leak_sensor",
    vendor: "HydraSafe",
    model: "HS-L1",
    ip: "192.168.0.44",
    mac: "00:16:3E:11:22:44",
    category: "iot",
    statusPattern: ["good", "good", "good", "good", "good", "suspicious"]
  },
  {
    id: "laptop-den-01",
    name: "Den Laptop",
    type: "laptop",
    vendor: "Random",
    model: "N/A",
    ip: "192.168.0.60",
    mac: "00:16:3E:11:22:60",
    category: "home",
    statusPattern: ["good"]
  },
  {
    id: "phone-airwu-01",
    name: "Airwu Phone",
    type: "phone",
    vendor: "Random",
    model: "N/A",
    ip: "192.168.0.61",
    mac: "00:16:3E:11:22:61",
    category: "home",
    statusPattern: ["good"]
  }
];

const ADVISORY_SEED: Record<string, AdvisoryItem[]> = {
  "cam-garage-01": [
    {
      title: "Regional cloud relay slowdown reported for Sentinel series",
      source: "Vendor Status",
      url: "https://status.example.com/sentinel",
      publishedAt: "2026-03-06T18:15:00.000Z",
      category: "outage"
    },
    {
      title: "Credential stuffing attempts observed against camera portals",
      source: "Threat Intel Feed",
      url: "https://security.example.com/camera-advisory",
      publishedAt: "2026-03-05T22:41:00.000Z",
      category: "security"
    }
  ],
  "thermo-main-01": [
    {
      title: "API latency spike affecting thermostat telemetry ingest",
      source: "NetOps Bulletin",
      url: "https://netops.example.com/incident/therm-220",
      publishedAt: "2026-03-07T02:10:00.000Z",
      category: "outage"
    }
  ],
  "fridge-kitchen-01": [
    {
      title: "Firmware 4.1 patch available for authentication bypass CVE",
      source: "Vendor Security Advisory",
      url: "https://advisories.example.com/frostbyte-4-1",
      publishedAt: "2026-03-04T11:30:00.000Z",
      category: "security"
    }
  ]
};

function hashSeed(text: string): number {
  let hash = 2166136261;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function nextRandom(seed: number): [number, number] {
  const next = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
  return [next, next / 4294967296];
}

function currentStatus(device: DeviceSeed): DeviceStatus {
  const slot = Math.floor(Date.now() / 60000) % device.statusPattern.length;
  return device.statusPattern[slot];
}

function liveDevicePayload(device: DeviceSeed) {
  const status = currentStatus(device);
  const lastSeenDelta = status === "blocked" ? 110_000 : 20_000;

  return {
    id: device.id,
    name: device.name,
    type: device.type,
    vendor: device.vendor,
    model: device.model,
    ip: device.ip,
    mac: device.mac,
    deviceCategory: device.category,
    lastSeenAt: new Date(Date.now() - lastSeenDelta).toISOString(),
    status
  };
}

function metricsFor(deviceId: string, status: DeviceStatus) {
  const samples = 60;
  const now = Date.now();
  const minute = 60_000;

  let seed = hashSeed(`${deviceId}:${Math.floor(now / minute)}`);
  const latencyMs: Array<{ timestamp: string; value: number }> = [];
  const packetLossPct: Array<{ timestamp: string; value: number }> = [];
  const blockEvents: Array<{ timestamp: string; value: number }> = [];

  const latencyBase = status === "good" ? 18 : status === "suspicious" ? 110 : 360;
  const lossBase = status === "good" ? 0.3 : status === "suspicious" ? 3.5 : 22;
  const blockBase = status === "blocked" ? 2 : status === "suspicious" ? 0.4 : 0;

  for (let offset = samples - 1; offset >= 0; offset -= 1) {
    let randomValue: number;
    [seed, randomValue] = nextRandom(seed);
    const timestamp = new Date(now - offset * minute).toISOString();
    const drift = Math.sin((samples - offset) / 4) * (status === "blocked" ? 25 : 5);

    const latency = Math.max(1, Math.round(latencyBase + drift + randomValue * (status === "blocked" ? 85 : 35)));

    [seed, randomValue] = nextRandom(seed);
    const loss = Math.max(0, Number((lossBase + randomValue * (status === "blocked" ? 8 : 2.8)).toFixed(2)));

    [seed, randomValue] = nextRandom(seed);
    const events = Math.max(0, Math.round(blockBase + randomValue * (status === "blocked" ? 2 : 1)));

    latencyMs.push({ timestamp, value: latency });
    packetLossPct.push({ timestamp, value: loss });
    blockEvents.push({ timestamp, value: events });
  }

  return { deviceId, range: "1h", latencyMs, packetLossPct, blockEvents };
}

function advisoryFor(deviceId: string, status: DeviceStatus) {
  const seededItems = ADVISORY_SEED[deviceId] ?? [];
  const statusSummary =
    status === "blocked"
      ? "Network behavior suggests active rate limiting or endpoint block. Investigate upstream service health and firewall rules."
      : status === "suspicious"
        ? "Anomalous behavior detected. Review firmware posture and recent provider incidents."
        : "No high-severity issues found in mock feeds for this device at this time.";

  const fallbackItems: AdvisoryItem[] =
    seededItems.length > 0
      ? []
      : [
          {
            title: "No device-specific outage listed in current feed snapshot",
            source: "Local Agent Mock",
            url: "https://status.example.com/",
            publishedAt: new Date(Date.now() - 86_400_000).toISOString(),
            category: "outage"
          }
        ];

  return {
    generatedAt: new Date().toISOString(),
    summary: statusSummary,
    items: [...seededItems, ...fallbackItems]
  };
}

function jsonResponse(res: {
  statusCode: number;
  setHeader: (name: string, value: string) => void;
  end: (body?: string) => void;
}, payload: unknown, statusCode = 200) {
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(payload));
}

function iotMockApiPlugin(): Plugin {
  const handler = (
    req: { method?: string; url?: string },
    res: {
      statusCode: number;
      setHeader: (name: string, value: string) => void;
      end: (body?: string) => void;
    },
    next: () => void
  ) => {
    if (!req.url || req.method !== "GET") {
      next();
      return;
    }

    const requestUrl = new URL(req.url, "http://localhost");
    const { pathname } = requestUrl;

    if (!pathname.startsWith("/api/iot")) {
      next();
      return;
    }

    if (pathname === "/api/iot/devices") {
      const devices = DEVICE_CATALOG.map(liveDevicePayload).filter((device) => device.deviceCategory === "iot");
      jsonResponse(res, { generatedAt: new Date().toISOString(), devices });
      return;
    }

    const metricsMatch = pathname.match(/^\/api\/iot\/devices\/([^/]+)\/metrics$/);
    if (metricsMatch) {
      const deviceId = metricsMatch[1];
      const device = DEVICE_CATALOG.find((entry) => entry.id === deviceId && entry.category === "iot");
      if (!device) {
        jsonResponse(res, { message: "Device not found" }, 404);
        return;
      }

      const status = currentStatus(device);
      jsonResponse(res, metricsFor(deviceId, status));
      return;
    }

    const advisoriesMatch = pathname.match(/^\/api\/iot\/devices\/([^/]+)\/advisories$/);
    if (advisoriesMatch) {
      const deviceId = advisoriesMatch[1];
      const device = DEVICE_CATALOG.find((entry) => entry.id === deviceId && entry.category === "iot");
      if (!device) {
        jsonResponse(res, { message: "Device not found" }, 404);
        return;
      }

      const status = currentStatus(device);
      jsonResponse(res, advisoryFor(deviceId, status));
      return;
    }

    jsonResponse(res, { message: "Unknown endpoint" }, 404);
  };

  return {
    name: "iot-mock-api",
    configureServer(server) {
      server.middlewares.use(handler);
    },
    configurePreviewServer(server) {
      server.middlewares.use(handler);
    }
  };
}

export default defineConfig({
  plugins: [react(), iotMockApiPlugin()]
});
