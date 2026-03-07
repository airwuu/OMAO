import type { DeviceAdvisoryReport } from "../types";

interface AdvisoryPanelProps {
  report: DeviceAdvisoryReport | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => Promise<void>;
}

export function AdvisoryPanel({ report, loading, error, onRefresh }: AdvisoryPanelProps) {
  return (
    <section className="advisory-panel">
      <header className="advisory-panel__header">
        <h3>Outage + Security Agent</h3>
        <button type="button" className="terminal-button" onClick={() => void onRefresh()} disabled={loading}>
          {loading ? "Scanning..." : "Re-scan"}
        </button>
      </header>

      {loading && !report ? <p className="muted">Collecting feed snapshots...</p> : null}
      {error ? <p className="error-text">{error}</p> : null}

      {report ? (
        <>
          <p className="advisory-summary">{report.summary}</p>
          <p className="muted">Generated {new Date(report.generatedAt).toLocaleString()}</p>
          <ul className="advisory-list">
            {report.items.map((item) => (
              <li key={`${item.url}-${item.publishedAt}`}>
                <p className="advisory-title">[{item.category}] {item.title}</p>
                <p>
                  <a href={item.url} target="_blank" rel="noreferrer">
                    {item.source}
                  </a>{" "}
                  · {new Date(item.publishedAt).toLocaleString()}
                </p>
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </section>
  );
}
