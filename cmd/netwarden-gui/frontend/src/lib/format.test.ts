import { describe, expect, it } from "vitest"
import { formatDate } from "./format"

describe("formatDate", () => {
  it("handles a missing observation timestamp", () => {
    expect(formatDate("")).toBe("Never")
  })

  it("formats a valid observation timestamp", () => {
    expect(formatDate("2026-07-28T06:00:00Z")).not.toContain("Invalid")
  })
})
