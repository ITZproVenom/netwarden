import { describe, expect, it } from "vitest"
import { formatDate, formatRelativeDate } from "./format"

describe("formatDate", () => {
  it("handles a missing observation timestamp", () => {
    expect(formatDate("")).toBe("Never")
  })

  it("formats a valid observation timestamp", () => {
    expect(formatDate("2026-07-28T06:00:00Z")).not.toContain("Invalid")
  })

  it("formats relative timestamps against a fixed time", () => {
    const now = new Date("2026-07-28T06:05:00Z").getTime()
    expect(formatRelativeDate("2026-07-28T06:00:00Z", now)).toMatch(/5 minutes ago/)
  })
})
