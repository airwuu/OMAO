import { useEffect, useMemo, useState } from "react";
import { DeviceDrawer } from "./components/DeviceDrawer";
import { GraphView } from "./components/GraphView";
import { StatusStrip } from "./components/StatusStrip";
import { useAdvisoryReport } from "./hooks/useAdvisoryReport";
import { iotApi } from "./services/api";
import type { Device, DeviceMetricsSeries } from "./types";

const POLLING_INTERVAL_MS = 10_000;

export default function App() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [devicesError, setDevicesError] = useState<string | null>(null);
  const [devicesLoading, setDevicesLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);

  const [metrics, setMetrics] = useState<DeviceMetricsSeries | null>(null);
  const [metricsLoading, setMetricsLoading] = useState(false);
  const [metricsError, setMetricsError] = useState<string | null>(null);

  const selectedDevice = useMemo(
    () => devices.find((device) => device.id === selectedDeviceId) ?? null,
    [devices, selectedDeviceId]
  );

  const {
    report: advisoryReport,
    loading: advisoryLoading,
    error: advisoryError,
    refresh: refreshAdvisories
  } = useAdvisoryReport(selectedDeviceId);

  useEffect(() => {
    let active = true;

    const fetchDevices = async () => {
      try {
        setDevicesError(null);
        const response = await iotApi.getDevices();

        if (!active) {
          return;
        }

        const iotOnlyDevices = response.filter((device) => device.deviceCategory !== "home");
        setDevices(iotOnlyDevices);
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
      return;
    }

    let active = true;
    setMetrics(null);

    const fetchMetrics = async () => {
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
    <>
      <svg className="crt-filter-defs" aria-hidden="true" focusable="false">
        <defs>
          <filter
            id="crt-glass-v2"
            x="-8%"
            y="-8%"
            width="116%"
            height="116%"
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
              scale="22"
              xChannelSelector="R"
              yChannelSelector="G"
              result="curvedGraphic"
            />
            <feTurbulence
              type="fractalNoise"
              baseFrequency="0.0042 0.0056"
              numOctaves="2"
              seed="17"
              stitchTiles="stitch"
              result="noiseRaw"
            >
              <animate
                attributeName="baseFrequency"
                dur="11s"
                values="0.0042 0.0056;0.0052 0.0041;0.0042 0.0056"
                repeatCount="indefinite"
              />
            </feTurbulence>
            <feComponentTransfer in="noiseRaw" result="noiseMap">
              <feFuncR type="linear" slope="0.07" intercept="0.465" />
              <feFuncG type="linear" slope="0.07" intercept="0.465" />
              <feFuncB type="linear" slope="0.07" intercept="0.465" />
            </feComponentTransfer>
            <feDisplacementMap
              in="curvedGraphic"
              in2="noiseMap"
              scale="2.4"
              xChannelSelector="R"
              yChannelSelector="G"
              result="glassBody"
            />
            <feGaussianBlur in="SourceAlpha" stdDeviation="1.8" result="alphaBlur" />
            <feSpecularLighting
              in="alphaBlur"
              surfaceScale="2.2"
              specularConstant="0.55"
              specularExponent="18"
              lightingColor="#d8ffd8"
              result="specLight"
            >
              <fePointLight x="-2200" y="-1600" z="3400" />
            </feSpecularLighting>
            <feComposite in="specLight" in2="SourceAlpha" operator="in" result="specMask" />
            <feComposite
              in="glassBody"
              in2="specMask"
              operator="arithmetic"
              k1="0"
              k2="1"
              k3="0.24"
              k4="0"
              result="withSpec"
            />
            <feComposite in="withSpec" in2="SourceAlpha" operator="in" />
          </filter>
        </defs>
      </svg>

      <div className="crt-app">
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
              onSelect={(device) => setSelectedDeviceId(device.id)}
              onClearSelection={() => setSelectedDeviceId(null)}
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
            onRefreshAdvisories={refreshAdvisories}
            onClose={() => setSelectedDeviceId(null)}
          />
        </main>
      </div>
    </>
  );
}
