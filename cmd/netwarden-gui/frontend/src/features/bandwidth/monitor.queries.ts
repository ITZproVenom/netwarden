import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { queryKeys } from "@/lib/query-keys"
import { wailsClient } from "@/lib/wails/client"
import { toast } from "sonner"
import { announce } from "@/lib/accessibility"
import { errorMessage } from "@/lib/errors"

export const useBandwidthMonitors = (enabled: boolean) =>
  useQuery({ queryKey: queryKeys.bandwidthMonitors, queryFn: wailsClient.bandwidthMonitors, enabled, retry: false })

export const useBandwidthMeasurements = (enabled: boolean) =>
  useQuery({
    queryKey: queryKeys.bandwidthMeasurements,
    queryFn: wailsClient.bandwidthMeasurements,
    enabled,
    retry: false,
    refetchInterval: enabled ? 1000 : false,
  })

export const useBandwidthHealth = (enabled: boolean) => useQuery({ queryKey: queryKeys.bandwidthHealth, queryFn: wailsClient.bandwidthMonitorHealth, enabled, retry: false, refetchInterval: enabled ? 5000 : false })

export const useBandwidthHistory = (mac: string, range: string, enabled: boolean) => useQuery({
  queryKey: queryKeys.bandwidthHistory(mac, range), queryFn: () => wailsClient.bandwidthHistory(mac, range), enabled: enabled && Boolean(mac), retry: false,
})

export function useStartBandwidthMonitor() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ ip, mac }: { ip: string; mac: string }) => wailsClient.startBandwidthMonitor(ip, mac),
    onSuccess: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: queryKeys.bandwidthMonitors }),
        client.invalidateQueries({ queryKey: queryKeys.status }),
      ])
      toast.success("Bandwidth monitoring started")
      announce("Bandwidth monitoring started")
    },
    onError: (error) => {
      const message = errorMessage(error)
      toast.error("Could not start bandwidth monitoring", { description: message })
      announce(`Could not start bandwidth monitoring. ${message}`, "assertive")
    },
  })
}

export function useStopBandwidthMonitor() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (mac: string) => wailsClient.stopBandwidthMonitor(mac),
    onSuccess: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: queryKeys.bandwidthMonitors }),
        client.invalidateQueries({ queryKey: queryKeys.status }),
      ])
      toast.success("Bandwidth monitoring stopped")
      announce("Bandwidth monitoring stopped")
    },
    onError: (error) => {
      const message = errorMessage(error)
      toast.error("Could not stop bandwidth monitoring", { description: message })
      announce(`Could not stop bandwidth monitoring. ${message}`, "assertive")
    },
  })
}

export function useStartAllBandwidthMonitors() {
  const client = useQueryClient()
  return useMutation({ mutationFn: wailsClient.startAllBandwidthMonitors, onSuccess: async () => {
    await client.invalidateQueries({ queryKey: queryKeys.runtime }); toast.success("Monitoring started for all eligible devices")
  }, onError: (error) => toast.error("Could not monitor all devices", { description: errorMessage(error) }) })
}

export function useStopAllBandwidthMonitors() {
  const client = useQueryClient()
  return useMutation({ mutationFn: wailsClient.stopAllBandwidthMonitors, onSuccess: async () => {
    await client.invalidateQueries({ queryKey: queryKeys.runtime }); toast.success("All available monitoring routes stopped")
  }, onError: (error) => toast.error("Could not stop all monitors", { description: errorMessage(error) }) })
}
