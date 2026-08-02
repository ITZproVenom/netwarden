import type { Device } from "@/lib/wails/types"

export type DeviceSortKey = "name" | "ip" | "vendor" | "type" | "role" | "lastSeen" | "online" | "controlState"
export type DevicePreferences = {
  query: string
  presence: string
  role: string
  sortBy: DeviceSortKey
  descending: boolean
}

export const defaultDevicePreferences: DevicePreferences = {
  query: "",
  presence: "online",
  role: "Device",
  sortBy: "name",
  descending: false,
}

export const isControlEligible = (device: Device) =>
  device.online && device.role === "Device" && device.controlState === ""

export const isIPv4Address = (address: string) => {
  const octets = address.split(".")
  return octets.length === 4 && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)
}
