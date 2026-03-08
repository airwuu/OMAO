import { useCallback, useEffect, useMemo, useState } from "react";
import { DeviceDrawer } from "./components/DeviceDrawer";
import { GraphView } from "./components/GraphView";
import { StatusStrip } from "./components/StatusStrip";
import { useAdvisoryReport } from "./hooks/useAdvisoryReport";
import { iotApi } from "./services/api";
import type { Device, DeviceMetricsSeries } from "./types";

const POLLING_INTERVAL_MS = 10_000;

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

    const fetchDevices = async () => {
      if (pending) {
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
      }
    };

    void fetchDevices();
    const intervalId = window.setInterval(() => {
      void fetchDevices();
    }, POLLING_INTERVAL_MS);

    return () => {
      active = false;
      window.clearInterval(intervalId);
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
    setMetrics(null);

    const fetchMetrics = async () => {
      if (pending) {
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
      }
    };

    void fetchMetrics();
    const intervalId = window.setInterval(() => {
      void fetchMetrics();
    }, POLLING_INTERVAL_MS);

    return () => {
      active = false;
      window.clearInterval(intervalId);
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
        <p className="muted">hub-and-spoke topology | 10s telemetry polling</p>
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
