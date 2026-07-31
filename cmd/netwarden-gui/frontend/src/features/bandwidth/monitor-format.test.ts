import { describe, expect, it } from "vitest"
import { formatBytes, formatRate } from "./monitor-format"

describe("bandwidth monitor formatting", () => {
  it("selects readable rate units", () => {
    expect(formatRate(800)).toBe("800 bps")
    expect(formatRate(1_500)).toBe("1.5 Kbps")
    expect(formatRate(2_500_000)).toBe("2.50 Mbps")
  })

  it("selects readable usage units", () => {
    expect(formatBytes(900)).toBe("900 B")
    expect(formatBytes(1_500)).toBe("1.5 KB")
    expect(formatBytes(2_500_000)).toBe("2.50 MB")
  })
})
