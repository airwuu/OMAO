import { memo } from "react";
import type { Device, DeviceAdvisoryReport, DeviceMetricsSeries } from "../types";
import { STATUS_META, statusToClass } from "../utils/status";
import { AdvisoryPanel } from "./AdvisoryPanel";

interface DeviceDrawerProps {
  device: Device | null;
  metrics: DeviceMetricsSeries | null;
  metricsLoading: boolean;
  metricsError: string | null;
  advisoryReport: DeviceAdvisoryReport | null;
  advisoryLoading: boolean;
  advisoryError: string | null;
  deleteLoading: boolean;
  deleteError: string | null;
  onDeleteDevice: (deviceId: string) => Promise<void>;
  onRefreshAdvisories: () => Promise<void>;
  onClose: () => void;
}

export const DeviceDrawer = memo(function DeviceDrawer({
  device,
  metrics,
  metricsLoading,
  metricsError,
  advisoryReport,
  advisoryLoading,
  advisoryError,
  deleteLoading,
  deleteError,
  onDeleteDevice,
  onRefreshAdvisories,
  onClose
}: DeviceDrawerProps) {
  const handleDeleteClick = async () => {
    if (!device || deleteLoading) {
      return;
    }

    if (!window.confirm(`Delete "${device.name}" from the dashboard?`)) {
      return;
    }

    await onDeleteDevice(device.id);
  };

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

            <div className="drawer__actions">
              <button
                type="button"
                className="terminal-button terminal-button--danger"
                onClick={() => {
                  void handleDeleteClick();
                }}
                disabled={deleteLoading}
              >
                {deleteLoading ? "Deleting..." : "Delete Device"}
              </button>
              {deleteError ? <p className="error-text">{deleteError}</p> : null}
            </div>

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
});
