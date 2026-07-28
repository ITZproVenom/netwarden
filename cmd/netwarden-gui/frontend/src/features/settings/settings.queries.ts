import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { queryKeys } from "@/lib/query-keys"
import { wailsClient } from "@/lib/wails/client"
import { errorMessage } from "@/lib/errors"

export function useSetGatewayMAC() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: wailsClient.setGatewayMAC,
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: queryKeys.bootstrap })
      toast.success("Gateway baseline updated")
    },
    onError: (error) => toast.error("Could not update gateway baseline", { description: errorMessage(error) }),
  })
}

export const useHistorySummary = () => useQuery({ queryKey: queryKeys.history, queryFn: wailsClient.historySummary })
export const useMonitoringSettings = () =>
  useQuery({ queryKey: queryKeys.monitoringSettings, queryFn: wailsClient.monitoringSettings })

export function useSetMonitoringSettings() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: wailsClient.setMonitoringSettings,
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: queryKeys.runtime })
      toast.success("Monitoring settings saved")
    },
    onError: (error) => toast.error("Could not save monitoring settings", { description: errorMessage(error) }),
  })
}

export function usePruneHistory() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: wailsClient.pruneHistory,
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: queryKeys.runtime })
      toast.success("History pruned")
    },
    onError: (error) => toast.error("Could not prune history", { description: errorMessage(error) }),
  })
}

export function useClearHistory() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: wailsClient.clearHistory,
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: queryKeys.runtime })
      toast.success("History cleared")
    },
    onError: (error) => toast.error("Could not clear history", { description: errorMessage(error) }),
  })
}
