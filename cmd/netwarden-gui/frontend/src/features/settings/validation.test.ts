import { describe, expect, it } from "vitest"
import { validateGatewayMAC, validateRange } from "./validation"

describe("settings validation", () => {
  it("validates bounded whole numbers", () => {
    expect(validateRange(10, 5, 30, "Interval")).toBeUndefined()
    expect(validateRange(4, 5, 30, "Interval")).toContain("between 5 and 30")
    expect(validateRange(5.5, 5, 30, "Interval")).toContain("whole number")
  })

  it("accepts canonical MAC separators and rejects malformed addresses", () => {
    expect(validateGatewayMAC("")).toBeUndefined()
    expect(validateGatewayMAC("00:11:22:33:44:55")).toBeUndefined()
    expect(validateGatewayMAC("00-11-22-33-44-55")).toBeUndefined()
    expect(validateGatewayMAC("00:11:22:33:44")).toBeDefined()
  })
})
