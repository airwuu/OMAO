import { useCallback, useEffect, useMemo, useState } from "react";
import { AdvisoryCache } from "../services/advisoryCache";
import { iotApi } from "../services/api";
import type { DeviceAdvisoryReport } from "../types";

const CACHE_TTL_MS = 30 * 60 * 1000;

interface UseAdvisoryReportResult {
  report: DeviceAdvisoryReport | null;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
}

export function useAdvisoryReport(deviceId: string | null): UseAdvisoryReportResult {
  const cache = useMemo(() => new AdvisoryCache(CACHE_TTL_MS), []);
  const [report, setReport] = useState<DeviceAdvisoryReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    async (options?: { force?: boolean }) => {
      if (!deviceId) {
        setReport(null);
        setLoading(false);
        setError(null);
        return;
      }

      if (!options?.force) {
        const cached = cache.get(deviceId);
        if (cached) {
          setReport(cached);
          setLoading(false);
          setError(null);
          return;
        }
      }

      setReport(null);
      setLoading(true);
      setError(null);
      try {
        const freshReport = await iotApi.getAdvisories(deviceId);
        cache.set(deviceId, freshReport);
        setReport(freshReport);
      } catch (requestError) {
        const message =
          requestError instanceof Error ? requestError.message : "Unable to fetch advisory findings.";
        setError(message);
      } finally {
        setLoading(false);
      }
    },
    [cache, deviceId]
  );

  useEffect(() => {
    void load();
  }, [load]);

  const refresh = useCallback(async () => {
    await load({ force: true });
  }, [load]);

  return { report, loading, error, refresh };
}
