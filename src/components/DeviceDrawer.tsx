import type { Device, DeviceAdvisoryReport, DeviceMetricsSeries } from "../types";
import { STATUS_META, statusToClass } from "../utils/status";
import { AdvisoryPanel } from "./AdvisoryPanel";
import { MetricCard } from "./MetricCard";

interface DeviceDrawerProps {
  device: Device | null;
  metrics: DeviceMetricsSeries | null;
  metricsLoading: boolean;
  metricsError: string | null;
  advisoryReport: DeviceAdvisoryReport | null;
  advisoryLoading: boolean;
  advisoryError: string | null;
  onRefreshAdvisories: () => Promise<void>;
  onClose: () => void;
}

export function DeviceDrawer({
  device,
  metrics,
  metricsLoading,
  metricsError,
  advisoryReport,
  advisoryLoading,
  advisoryError,
  onRefreshAdvisories,
  onClose
}: DeviceDrawerProps) {
  return (
    <aside className={`drawer ${device ? "drawer--open" : ""}`} aria-live="polite">
      <div className="drawer__content">
        {device ? (
          <>
            <header className="drawer__header">
              <div>
                <h2>{device.name}</h2>
                <p>{device.vendor} {device.model}</p>
              </div>
              <button type="button" className="terminal-button" onClick={onClose}>
                Close
              </button>
            </header>

            <div className="device-meta">
              <p>
                Status: <span className={`status-pill ${statusToClass(device.status)}`}>{STATUS_META[device.status].summary}</span>
              </p>
              <p>Type: {device.type}</p>
              <p>IP: {device.ip}</p>
              <p>MAC: {device.mac}</p>
              <p>Last seen: {new Date(device.lastSeenAt).toLocaleTimeString()}</p>
            </div>

            <section className="metrics-grid" aria-label="Device metrics">
              {metricsLoading && !metrics ? <p className="muted">Loading telemetry...</p> : null}
              {metricsError ? <p className="error-text">{metricsError}</p> : null}
              {metrics ? (
                <>
                  <MetricCard title="Latency" unit="ms" data={metrics.latencyMs} stroke="#6CFF6C" />
                  <MetricCard title="Packet Loss" unit="%" data={metrics.packetLossPct} stroke="#F8F36B" />
                  <MetricCard title="Block Events" unit="count" data={metrics.blockEvents} stroke="#FF6464" />
                </>
              ) : null}
            </section>

            <AdvisoryPanel
              report={advisoryReport}
              loading={advisoryLoading}
              error={advisoryError}
              onRefresh={onRefreshAdvisories}
            />
          </>
        ) : (
          <div className="drawer__placeholder">
            <h2>Device Console</h2>
            <p>Select an IoT node from the graph to inspect metrics and recent outage/security findings.</p>
          </div>
        )}
      </div>
    </aside>
  );
}
