import { describe, expect, it } from "vitest";
import { STATUS_META, statusToClass } from "./status";

describe("status utils", () => {
  it("maps all severity states to classes", () => {
    expect(statusToClass("good")).toBe("status-good");
    expect(statusToClass("suspicious")).toBe("status-suspicious");
    expect(statusToClass("blocked")).toBe("status-blocked");
  });

  it("exposes color metadata for each status", () => {
    expect(STATUS_META.good.color).toMatch(/^#/);
    expect(STATUS_META.suspicious.color).toMatch(/^#/);
    expect(STATUS_META.blocked.color).toMatch(/^#/);
  });
});
