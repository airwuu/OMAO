import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import type { Device } from "../types";
import { buildGraphData, type GraphNode } from "../utils/graph";
import { STATUS_META } from "../utils/status";

interface GraphViewProps {
  devices: Device[];
  selectedId: string | null;
  onSelect: (device: Device) => void;
}

interface GraphSize {
  width: number;
  height: number;
}

const INITIAL_SIZE: GraphSize = {
  width: 960,
  height: 520
};

export function GraphView({ devices, selectedId, onSelect }: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const graphRef = useRef<any>(null);
  const [size, setSize] = useState<GraphSize>(INITIAL_SIZE);
  const graphData = useMemo(() => buildGraphData(devices), [devices]);

  useEffect(() => {
    const target = containerRef.current;
    if (!target) {
      return;
    }

    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) {
        return;
      }

      setSize({
        width: Math.max(320, entry.contentRect.width),
        height: Math.max(280, entry.contentRect.height)
      });
    });

    observer.observe(target);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!graphRef.current) {
      return;
    }

    graphRef.current.d3Force("charge").strength(-180);
    graphRef.current.d3Force("link").distance(140);

    const timeoutId = window.setTimeout(() => {
      graphRef.current?.zoomToFit(500, 30);
    }, 350);

    return () => window.clearTimeout(timeoutId);
  }, [graphData.nodes.length]);

  return (
    <section className="graph-shell" aria-label="IoT topology graph">
      <div className="legend" aria-label="Severity legend">
        <span><i style={{ backgroundColor: STATUS_META.good.color }} />good</span>
        <span><i style={{ backgroundColor: STATUS_META.suspicious.color }} />suspicious</span>
        <span><i style={{ backgroundColor: STATUS_META.blocked.color }} />blocked</span>
      </div>
      <div className="graph-shell__canvas" ref={containerRef}>
        <ForceGraph2D
          ref={graphRef}
          width={size.width}
          height={size.height}
          graphData={graphData}
          enableNodeDrag={false}
          backgroundColor="transparent"
          linkColor={() => "rgba(108, 255, 108, 0.25)"}
          linkWidth={1}
          cooldownTicks={80}
          nodeRelSize={6}
          onNodeClick={(node) => {
            const typedNode = node as GraphNode;
            if (typedNode.kind === "device" && typedNode.device) {
              onSelect(typedNode.device);
            }
          }}
          nodeLabel={(node) => {
            const typedNode = node as GraphNode;
            if (typedNode.kind === "hub") {
              return typedNode.label;
            }

            const status = typedNode.device?.status ?? "good";
            return `${typedNode.label} (${status})`;
          }}
          nodeCanvasObject={(node, ctx, globalScale) => {
            const typedNode = node as GraphNode;
            const label = typedNode.label;
            const isHub = typedNode.kind === "hub";

            const radius = isHub ? 16 : 10;
            const nodeStatus = typedNode.device?.status ?? "good";
            const color = isHub ? "#9BFF9B" : STATUS_META[nodeStatus].color;
            const glow = isHub ? "rgba(155, 255, 155, 0.55)" : STATUS_META[nodeStatus].glow;

            ctx.beginPath();
            ctx.arc(node.x ?? 0, node.y ?? 0, radius, 0, 2 * Math.PI, false);
            ctx.fillStyle = color;
            ctx.shadowColor = glow;
            ctx.shadowBlur = 14;
            ctx.fill();
            ctx.shadowBlur = 0;

            if (!isHub && typedNode.id === selectedId) {
              ctx.beginPath();
              ctx.arc(node.x ?? 0, node.y ?? 0, radius + 4, 0, 2 * Math.PI, false);
              ctx.strokeStyle = "#F8F36B";
              ctx.lineWidth = 2;
              ctx.stroke();
            }

            const fontSize = isHub ? 13 : 10;
            ctx.font = `${fontSize / globalScale}px "Share Tech Mono", monospace`;
            ctx.fillStyle = "#B8FFB8";
            ctx.textAlign = "center";
            ctx.fillText(label, node.x ?? 0, (node.y ?? 0) + radius + 12 / globalScale);
          }}
        />
      </div>
    </section>
  );
}
