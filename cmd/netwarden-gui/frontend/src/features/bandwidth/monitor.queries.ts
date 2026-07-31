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
