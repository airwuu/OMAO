import type { Device } from "../types";
import { STATUS_META, statusToClass } from "../utils/status";

interface StatusStripProps {
  devices: Device[];
  lastUpdated: string | null;
}

export function StatusStrip({ devices, lastUpdated }: StatusStripProps) {
  const counts = devices.reduce(
    (accumulator, device) => {
      accumulator[device.status] += 1;
      return accumulator;
    },
    {
      good: 0,
      suspicious: 0,
      blocked: 0,
      disconnected: 0
    }
  );

  return (
    <section className="status-strip" aria-label="Network status summary">
      <div className="status-strip__item">
        <p className="status-strip__label">IoT devices tracked</p>
        <p className="status-strip__value">{devices.length}</p>
      </div>

      {(["good", "suspicious", "blocked", "disconnected"] as const).map((status) => (
        <div className={`status-strip__item ${statusToClass(status)}`} key={status}>
          <p className="status-strip__label">{STATUS_META[status].label}</p>
          <p className="status-strip__value">{counts[status]}</p>
        </div>
      ))}

      <div className="status-strip__item">
        <p className="status-strip__label">Last refresh</p>
        <p className="status-strip__value status-strip__value--small">
          {lastUpdated ? new Date(lastUpdated).toLocaleTimeString() : "--:--:--"}
        </p>
      </div>
    </section>
  );
}
