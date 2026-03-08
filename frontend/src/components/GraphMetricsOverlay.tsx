import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import type { Device, DeviceMetricsSeries, TimeSeriesPoint } from "../types";

interface GraphMetricsOverlayProps {
  device: Device | null;
  metrics: DeviceMetricsSeries | null;
  metricsLoading: boolean;
  metricsError: string | null;
}

interface MiniMetricProps {
  title: string;
  unit: string;
  data: TimeSeriesPoint[];
  stroke: string;
}

function formatTick(value: string): string {
  const date = new Date(value);
  return `${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
}

function MiniMetric({ title, unit, data, stroke }: MiniMetricProps) {
  return (
    <article className="graph-mini-metric">
      <header className="graph-mini-metric__header">
        <h4>{title}</h4>
        <span>{unit}</span>
      </header>
      <div className="graph-mini-metric__chart">
        <ResponsiveContainer width="100%" height={88}>
          <LineChart data={data} margin={{ top: 8, right: 8, bottom: 2, left: -22 }}>
            <CartesianGrid stroke="rgba(108, 255, 108, 0.12)" strokeDasharray="2 4" />
            <XAxis dataKey="timestamp" tickFormatter={formatTick} tick={{ fill: "#8FC28F", fontSize: 9 }} minTickGap={16} />
            <YAxis tick={{ fill: "#8FC28F", fontSize: 9 }} width={38} />
            <Tooltip
              contentStyle={{
                background: "#061206",
                border: "1px solid rgba(108, 255, 108, 0.3)",
                borderRadius: "4px",
                color: "#D8FFD8",
                fontSize: "0.72rem"
              }}
              labelFormatter={(label) => new Date(label).toLocaleTimeString()}
            />
            <Line type="monotone" dataKey="value" stroke={stroke} strokeWidth={2} dot={false} isAnimationActive={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </article>
  );
}

export function GraphMetricsOverlay({
  device,
  metrics,
  metricsLoading,
  metricsError
}: GraphMetricsOverlayProps) {
  if (!device) {
    return null;
  }

  return (
    <aside className="graph-metrics-overlay" aria-label="Selected node metrics">
      {metricsLoading && !metrics ? <p className="muted">Loading telemetry...</p> : null}
      {metricsError ? <p className="error-text">{metricsError}</p> : null}

      {metrics ? (
        <div className="graph-mini-metrics-grid">
          <MiniMetric title="Latency" unit="ms" data={metrics.latencyMs} stroke="#6CFF6C" />
          <MiniMetric title="Packet Loss" unit="%" data={metrics.packetLossPct} stroke="#F8F36B" />
          <MiniMetric title="Net Activity" unit="kbps" data={metrics.networkActivityKbps} stroke="#7BB8FF" />
          <MiniMetric title="Block Events" unit="count" data={metrics.blockEvents} stroke="#FF6464" />
        </div>
      ) : null}
    </aside>
  );
}
