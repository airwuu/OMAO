import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import type { TimeSeriesPoint } from "../types";

interface MetricCardProps {
  title: string;
  unit: string;
  data: TimeSeriesPoint[];
  stroke: string;
}

function formatTick(value: string): string {
  const date = new Date(value);
  return `${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
}

export function MetricCard({ title, unit, data, stroke }: MetricCardProps) {
  return (
    <article className="metric-card">
      <header className="metric-card__header">
        <h4>{title}</h4>
        <span>{unit}</span>
      </header>
      <div className="metric-card__body">
        <ResponsiveContainer width="100%" height={150}>
          <LineChart data={data} margin={{ top: 8, right: 12, bottom: 4, left: -20 }}>
            <CartesianGrid stroke="rgba(108, 255, 108, 0.14)" strokeDasharray="2 4" />
            <XAxis
              dataKey="timestamp"
              tickFormatter={formatTick}
              tick={{ fill: "#8FC28F", fontSize: 10 }}
              tickMargin={8}
              minTickGap={28}
            />
            <YAxis tick={{ fill: "#8FC28F", fontSize: 10 }} width={44} />
            <Tooltip
              contentStyle={{
                background: "#071507",
                border: "1px solid rgba(108, 255, 108, 0.35)",
                color: "#D8FFD8",
                borderRadius: "4px"
              }}
              labelFormatter={(label) => new Date(label).toLocaleTimeString()}
            />
            <Line
              type="monotone"
              dataKey="value"
              stroke={stroke}
              strokeWidth={2}
              dot={false}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </article>
  );
}
