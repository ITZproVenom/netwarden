import { describe, expect, it } from "vitest"
import { bandwidthValidation, parseMbps } from "./validation"

describe("bandwidth validation", () => {
  it("converts decimal Mbps to integer bits per second", () => {
    expect(parseMbps("2.5")).toBe(2_500_000)
  })

  it("allows one unlimited direction", () => {
    expect(bandwidthValidation("10", "")).toBe("")
  })

  it("requires at least one limit and rejects unsafe numbers", () => {
    expect(bandwidthValidation("", "")).toContain("download or upload")
    expect(parseMbps("-1")).toBeNull()
    expect(parseMbps("Infinity")).toBeNull()
  })
})
