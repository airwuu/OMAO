import { describe, expect, it } from "vitest";
import { AdvisoryCache } from "./advisoryCache";

const sampleReport = {
  generatedAt: "2026-03-07T00:00:00.000Z",
  summary: "sample",
  items: []
};

describe("AdvisoryCache", () => {
  it("returns cached value before ttl expiration", () => {
    const cache = new AdvisoryCache(1_000);
    cache.set("dev-1", sampleReport, 100);

    expect(cache.get("dev-1", 900)).toEqual(sampleReport);
  });

  it("invalidates stale cache entries", () => {
    const cache = new AdvisoryCache(1_000);
    cache.set("dev-1", sampleReport, 100);

    expect(cache.get("dev-1", 1_101)).toBeNull();
    expect(cache.get("dev-1", 1_102)).toBeNull();
  });
});
