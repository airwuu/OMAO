import { memo, useCallback, useEffect, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import type { Device, DeviceMetricsSeries } from "../types";
import { buildGraphData, syncGraphData, type GraphData, type GraphNode } from "../utils/graph";
import { STATUS_META } from "../utils/status";
import { GraphMetricsOverlay } from "./GraphMetricsOverlay";

interface GraphViewProps {
  devices: Device[];
  selectedDevice: Device | null;
  selectedId: string | null;
  metrics: DeviceMetricsSeries | null;
  metricsLoading: boolean;
  metricsError: string | null;
  onSelect: (device: Device) => void;
  onClearSelection: () => void;
}

interface GraphSize {
  width: number;
  height: number;
}

const INITIAL_SIZE: GraphSize = {
  width: 960,
  height: 520
};
const FOCUS_ZOOM_LEVEL = 2.3;
const FOCUS_ANIMATION_MS = 850;
const OVERVIEW_PADDING = 45;

export const GraphView = memo(function GraphView({
  devices,
  selectedDevice,
  selectedId,
  metrics,
  metricsLoading,
  metricsError,
  onSelect,
  onClearSelection
}: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const graphRef = useRef<any>(null);
  const cursorStyleRef = useRef<"default" | "pointer">("default");
  const [size, setSize] = useState<GraphSize>(INITIAL_SIZE);
  const [graphData, setGraphData] = useState<GraphData>(() => buildGraphData(devices));
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  useEffect(() => {
    setGraphData((current) => syncGraphData(current, devices));
  }, [devices]);

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

    graphRef.current.d3Force("charge").strength(-30);
    graphRef.current.d3Force("link").distance(1);

    const timeoutId = window.setTimeout(() => {
      graphRef.current?.zoomToFit(500, 45);
    }, 350);

    return () => window.clearTimeout(timeoutId);
  }, [graphData.nodes.length]);

  useEffect(() => {
    if (!selectedId || !graphRef.current) {
      return;
    }

    const targetNode = graphData.nodes.find((node) => node.id === selectedId);
    if (!targetNode) {
      return;
    }

    const targetX = targetNode.x ?? targetNode.fx ?? 0;
    const targetY = targetNode.y ?? targetNode.fy ?? 0;

    graphRef.current.centerAt(targetX, targetY, FOCUS_ANIMATION_MS);
    graphRef.current.zoom(FOCUS_ZOOM_LEVEL, FOCUS_ANIMATION_MS);
  }, [graphData.nodes, selectedId]);

  const handleBackgroundClick = useCallback(() => {
    graphRef.current?.zoomToFit(FOCUS_ANIMATION_MS, OVERVIEW_PADDING);
    onClearSelection();
  }, [onClearSelection]);

  const handleNodeHover = useCallback((node: unknown) => {
    const typedNode = node as GraphNode | null;
    const nextHoveredId = typedNode?.id ?? null;

    setHoveredNodeId((current) => (current === nextHoveredId ? current : nextHoveredId));

    const nextCursorStyle: "default" | "pointer" = typedNode ? "pointer" : "default";
    if (cursorStyleRef.current === nextCursorStyle) {
      return;
    }

    cursorStyleRef.current = nextCursorStyle;
    const canvas = graphRef.current?.canvas?.() as HTMLCanvasElement | undefined;
    if (canvas) {
      canvas.style.cursor = nextCursorStyle;
    }
  }, []);

  const handleNodeClick = useCallback(
    (node: unknown) => {
      const typedNode = node as GraphNode;

      if (typedNode.kind === "hub") {
        graphRef.current?.zoomToFit(FOCUS_ANIMATION_MS, OVERVIEW_PADDING);
        onClearSelection();
        return;
      }

      if (typedNode.kind === "device" && typedNode.device) {
        const targetX = typedNode.x ?? typedNode.fx ?? 0;
        const targetY = typedNode.y ?? typedNode.fy ?? 0;
        graphRef.current?.centerAt(targetX, targetY, FOCUS_ANIMATION_MS);
        graphRef.current?.zoom(FOCUS_ZOOM_LEVEL, FOCUS_ANIMATION_MS);
        onSelect(typedNode.device);
      }
    },
    [onClearSelection, onSelect]
  );

  const getNodeLabel = useCallback((node: unknown) => {
    const typedNode = node as GraphNode;
    if (typedNode.kind === "hub") {
      return typedNode.label;
    }

    const status = typedNode.device?.status ?? "good";
    return `${typedNode.label} (${status})`;
  }, []);

  const drawNode = useCallback(
    (node: unknown, ctx: CanvasRenderingContext2D) => {
      const typedNode = node as GraphNode;
      const label = typedNode.label;
      const isHub = typedNode.kind === "hub";
      const isHovered = typedNode.id === hoveredNodeId;

      const baseRadius = isHub ? 16 : 10;
      const radius = isHovered ? baseRadius + 2 : baseRadius;
      const nodeStatus = typedNode.device?.status ?? "good";
      const color = isHub ? "#9BFF9B" : STATUS_META[nodeStatus].color;
      const glow = isHub ? "rgba(155, 255, 155, 0.55)" : STATUS_META[nodeStatus].glow;

      ctx.beginPath();
      ctx.arc(typedNode.x ?? 0, typedNode.y ?? 0, radius, 0, 2 * Math.PI, false);
      ctx.fillStyle = color;
      ctx.shadowColor = glow;
      ctx.shadowBlur = isHovered ? 20 : 14;
      ctx.fill();
      ctx.shadowBlur = 0;

      if (isHovered) {
        ctx.beginPath();
        ctx.arc(typedNode.x ?? 0, typedNode.y ?? 0, radius + 5, 0, 2 * Math.PI, false);
        ctx.strokeStyle = "rgba(248, 243, 107, 0.9)";
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      if (!isHub && typedNode.id === selectedId) {
        ctx.beginPath();
        ctx.arc(typedNode.x ?? 0, typedNode.y ?? 0, radius + 4, 0, 2 * Math.PI, false);
        ctx.strokeStyle = "#F8F36B";
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      const fontSize = isHub ? 12 : 9;
      const labelOffset = radius + fontSize + 4;
      ctx.font = `${fontSize}px "Share Tech Mono", monospace`;
      ctx.fillStyle = "#B8FFB8";
      ctx.textAlign = "center";
      ctx.fillText(label, typedNode.x ?? 0, (typedNode.y ?? 0) + labelOffset);
    },
    [hoveredNodeId, selectedId]
  );

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
          cooldownTicks={0}
          nodeRelSize={6}
          onBackgroundClick={handleBackgroundClick}
          onNodeHover={handleNodeHover}
          onNodeClick={handleNodeClick}
          nodeLabel={getNodeLabel}
          nodeCanvasObject={drawNode}
        />
      </div>
      <GraphMetricsOverlay
        device={selectedDevice}
        metrics={metrics}
        metricsLoading={metricsLoading}
        metricsError={metricsError}
      />
    </section>
  );
});
