import { useCallback, useEffect, useMemo, useState } from "react";
import type { RealtimeChannel } from "@supabase/supabase-js";
import { DeviceDrawer } from "./components/DeviceDrawer";
import { GraphView } from "./components/GraphView";
import { StatusStrip } from "./components/StatusStrip";
import { useAdvisoryReport } from "./hooks/useAdvisoryReport";
import { iotApi } from "./services/api";
import { supabase } from "./services/supabaseClient";
import type { Device, DeviceMetricsSeries } from "./types";

const DEFAULT_POLL_INTERVAL_MS = 2_000;
const REALTIME_REFRESH_DEBOUNCE_MS = 250;
const SUPABASE_DEVICES_TABLE = import.meta.env.VITE_SUPABASE_DEVICES_TABLE?.trim() || "devices";
const SUPABASE_METRICS_TABLE = import.meta.env.VITE_SUPABASE_METRICS_TABLE?.trim() || "device_metrics";

function readPositiveIntEnv(rawValue: string | undefined, fallbackValue: number): number {
  if (!rawValue) {
    return fallbackValue;
  }

  const parsed = Number(rawValue);
  if (Number.isFinite(parsed) && parsed > 0) {
    const normalized = Math.floor(parsed);
    if (normalized >= 1) {
      return normalized;
    }
  }

  return fallbackValue;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function formatPollingInterval(ms: number): string {
  return ms % 1000 === 0 ? `${ms / 1000}s` : `${ms}ms`;
}

const DEVICE_POLL_INTERVAL_MS = readPositiveIntEnv(
  import.meta.env.VITE_DEVICE_POLL_INTERVAL_MS,
  DEFAULT_POLL_INTERVAL_MS
);
const METRICS_POLL_INTERVAL_MS = readPositiveIntEnv(
  import.meta.env.VITE_METRICS_POLL_INTERVAL_MS,
  DEFAULT_POLL_INTERVAL_MS
);

function areStableDeviceFieldsEqual(previous: Device[], next: Device[]): boolean {
  if (previous.length !== next.length) {
    return false;
  }

  for (let index = 0; index < previous.length; index += 1) {
    const previousDevice = previous[index];
    const nextDevice = next[index];

    if (
      previousDevice.id !== nextDevice.id ||
      previousDevice.name !== nextDevice.name ||
      previousDevice.type !== nextDevice.type ||
      previousDevice.vendor !== nextDevice.vendor ||
      previousDevice.model !== nextDevice.model ||
      previousDevice.ip !== nextDevice.ip ||
      previousDevice.mac !== nextDevice.mac ||
      previousDevice.status !== nextDevice.status ||
      previousDevice.deviceCategory !== nextDevice.deviceCategory
    ) {
      return false;
    }
  }

  return true;
}

export default function App() {
  const fallbackPollingLabel = formatPollingInterval(Math.max(DEVICE_POLL_INTERVAL_MS, METRICS_POLL_INTERVAL_MS));
  const [devices, setDevices] = useState<Device[]>([]);
  const [devicesError, setDevicesError] = useState<string | null>(null);
  const [devicesLoading, setDevicesLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);

  const [metrics, setMetrics] = useState<DeviceMetricsSeries | null>(null);
  const [metricsLoading, setMetricsLoading] = useState(false);
  const [metricsError, setMetricsError] = useState<string | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const selectedDevice = useMemo(
    () => devices.find((device) => device.id === selectedDeviceId) ?? null,
    [devices, selectedDeviceId]
  );

  const handleSelectDevice = useCallback((device: Device) => {
    setSelectedDeviceId(device.id);
  }, []);

  const handleClearSelection = useCallback(() => {
    setSelectedDeviceId(null);
  }, []);

  const handleDeleteDevice = useCallback(async (deviceId: string) => {
    setDeleteLoading(true);
    setDeleteError(null);

    try {
      await iotApi.deleteDevice(deviceId);
      setDevices((currentDevices) => currentDevices.filter((device) => device.id !== deviceId));
      setSelectedDeviceId((currentId) => (currentId === deviceId ? null : currentId));
      setMetrics((currentMetrics) => (currentMetrics?.deviceId === deviceId ? null : currentMetrics));
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : "Unable to delete device.";
      setDeleteError(message);
    } finally {
      setDeleteLoading(false);
    }
  }, []);

  const {
    report: advisoryReport,
    loading: advisoryLoading,
    error: advisoryError,
    refresh: refreshAdvisories
  } = useAdvisoryReport(selectedDeviceId);

  useEffect(() => {
    let active = true;
    let pending = false;
    let refetchAfterPending = false;
    let queuedRefreshId: number | null = null;

    const fetchDevices = async () => {
      if (pending) {
        refetchAfterPending = true;
        return;
      }

      pending = true;
      try {
        setDevicesError(null);
        const response = await iotApi.getDevices();

        if (!active) {
          return;
        }

        const iotOnlyDevices = response.filter((device) => device.deviceCategory !== "home");
        setDevices((currentDevices) =>
          areStableDeviceFieldsEqual(currentDevices, iotOnlyDevices) ? currentDevices : iotOnlyDevices
        );
        setLastUpdated(new Date().toISOString());

        setSelectedDeviceId((currentId) => {
          if (!currentId) {
            return currentId;
          }

          return iotOnlyDevices.some((device) => device.id === currentId) ? currentId : null;
        });
      } catch (requestError) {
        if (!active) {
          return;
        }

        const message = requestError instanceof Error ? requestError.message : "Unable to load device list.";
        setDevicesError(message);
      } finally {
        if (active) {
          setDevicesLoading(false);
        }
        pending = false;
        if (active && refetchAfterPending) {
          refetchAfterPending = false;
          void fetchDevices();
        }
      }
    };

    const queueDeviceRefresh = (delayMs = REALTIME_REFRESH_DEBOUNCE_MS) => {
      if (!active) {
        return;
      }

      if (queuedRefreshId !== null) {
        window.clearTimeout(queuedRefreshId);
      }

      queuedRefreshId = window.setTimeout(() => {
        queuedRefreshId = null;
        void fetchDevices();
      }, delayMs);
    };

    void fetchDevices();
    const intervalId = window.setInterval(() => {
      void fetchDevices();
    }, DEVICE_POLL_INTERVAL_MS);

    let channel: RealtimeChannel | null = null;
    if (supabase) {
      channel = supabase
        .channel("dashboard-devices")
        .on("postgres_changes", { event: "*", schema: "public", table: SUPABASE_DEVICES_TABLE }, () => {
          queueDeviceRefresh();
        })
        .subscribe((status) => {
          if (status === "SUBSCRIBED") {
            queueDeviceRefresh(0);
          }
        });
    }

    return () => {
      active = false;
      window.clearInterval(intervalId);
      if (queuedRefreshId !== null) {
        window.clearTimeout(queuedRefreshId);
      }
      if (channel && supabase) {
        void supabase.removeChannel(channel);
      }
    };
  }, []);

  useEffect(() => {
    if (!selectedDeviceId) {
      setMetrics(null);
      setMetricsError(null);
      setMetricsLoading(false);
      setDeleteError(null);
      setDeleteLoading(false);
      return;
    }

    let active = true;
    let pending = false;
    let refetchAfterPending = false;
    let queuedRefreshId: number | null = null;
    setMetrics(null);

    const fetchMetrics = async () => {
      if (pending) {
        refetchAfterPending = true;
        return;
      }

      pending = true;
      setMetricsLoading(true);
      setMetricsError(null);
      try {
        const payload = await iotApi.getMetrics(selectedDeviceId);
        if (!active) {
          return;
        }
        setMetrics(payload);
      } catch (requestError) {
        if (!active) {
          return;
        }
        const message = requestError instanceof Error ? requestError.message : "Unable to load telemetry.";
        setMetricsError(message);
      } finally {
        if (active) {
          setMetricsLoading(false);
        }
        pending = false;
        if (active && refetchAfterPending) {
          refetchAfterPending = false;
          void fetchMetrics();
        }
      }
    };

    const queueMetricRefresh = (delayMs = REALTIME_REFRESH_DEBOUNCE_MS) => {
      if (!active) {
        return;
      }

      if (queuedRefreshId !== null) {
        window.clearTimeout(queuedRefreshId);
      }

      queuedRefreshId = window.setTimeout(() => {
        queuedRefreshId = null;
        void fetchMetrics();
      }, delayMs);
    };

    void fetchMetrics();
    const intervalId = window.setInterval(() => {
      void fetchMetrics();
    }, METRICS_POLL_INTERVAL_MS);

    let channel: RealtimeChannel | null = null;
    if (supabase) {
      channel = supabase
        .channel(`dashboard-metrics-${selectedDeviceId}`)
        .on("postgres_changes", { event: "INSERT", schema: "public", table: SUPABASE_METRICS_TABLE }, (payload) => {
          if (!isRecord(payload.new)) {
            return;
          }

          const changedDeviceId =
            typeof payload.new.device_id === "string"
              ? payload.new.device_id
              : typeof payload.new.deviceId === "string"
                ? payload.new.deviceId
                : null;
          if (changedDeviceId !== selectedDeviceId) {
            return;
          }

          queueMetricRefresh();
        })
        .subscribe((status) => {
          if (status === "SUBSCRIBED") {
            queueMetricRefresh(0);
          }
        });
    }

    return () => {
      active = false;
      window.clearInterval(intervalId);
      if (queuedRefreshId !== null) {
        window.clearTimeout(queuedRefreshId);
      }
      if (channel && supabase) {
        void supabase.removeChannel(channel);
      }
    };
  }, [selectedDeviceId]);

  return (
    <div className="crt-app">
      <svg className="crt-filter-defs" aria-hidden="true" focusable="false">
        <defs>
          <filter
            id="crt-glass-v2"
            x="-6%"
            y="-6%"
            width="112%"
            height="112%"
            colorInterpolationFilters="sRGB"
          >
            <feImage
              href="/crt-lens-map-v2.svg"
              x="0"
              y="0"
              width="100%"
              height="100%"
              preserveAspectRatio="none"
              result="lensMap"
            />
            <feDisplacementMap
              in="SourceGraphic"
              in2="lensMap"
              scale="11"
              xChannelSelector="R"
              yChannelSelector="G"
            />
          </filter>
        </defs>
      </svg>
      <div className="crt-overlay" aria-hidden="true" />
      <header className="app-header">
        <div>
          <p className="app-header__kicker">Techy Home in Merced</p>
          <h1>IOT Device Watch</h1>
        </div>
        <p className="muted">{`hub-and-spoke topology | live updates + ${fallbackPollingLabel} fallback polling`}</p>
      </header>

      <StatusStrip devices={devices} lastUpdated={lastUpdated} />

      {devicesError ? <p className="error-text app-error">{devicesError}</p> : null}
      {devicesLoading ? <p className="muted app-loading">Booting telemetry pipeline...</p> : null}

      <main className="workspace">
        <section className="workspace__graph-column">
          <GraphView
            devices={devices}
            selectedDevice={selectedDevice}
            selectedId={selectedDeviceId}
            metrics={metrics}
            metricsLoading={metricsLoading}
            metricsError={metricsError}
            onSelect={handleSelectDevice}
            onClearSelection={handleClearSelection}
          />
          <div className="quick-select" aria-label="Quick device selector">
            {devices.map((device) => (
              <button
                key={device.id}
                type="button"
                className={`device-chip ${selectedDeviceId === device.id ? "device-chip--selected" : ""}`}
                onClick={() => setSelectedDeviceId(device.id)}
              >
                {device.name}
              </button>
            ))}
          </div>
        </section>

        <DeviceDrawer
          device={selectedDevice}
          metrics={metrics}
          metricsLoading={metricsLoading}
          metricsError={metricsError}
          advisoryReport={advisoryReport}
          advisoryLoading={advisoryLoading}
          advisoryError={advisoryError}
          deleteLoading={deleteLoading}
          deleteError={deleteError}
          onDeleteDevice={handleDeleteDevice}
          onRefreshAdvisories={refreshAdvisories}
          onClose={handleClearSelection}
        />
      </main>
    </div>
  );
}
