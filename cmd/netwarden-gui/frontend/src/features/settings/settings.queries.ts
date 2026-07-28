import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { queryKeys } from "@/lib/query-keys"
import { wailsClient } from "@/lib/wails/client"

export function useSetGatewayMAC() {
  const client = useQueryClient()
  return useMutation({ mutationFn: wailsClient.setGatewayMAC, onSuccess: async () => { await client.invalidateQueries({ queryKey: queryKeys.bootstrap }); toast.success("Gateway baseline updated") }, onError: error => toast.error("Could not update gateway baseline", { description: String(error) }) })
}

export const useHistorySummary = () => useQuery({ queryKey: queryKeys.history, queryFn: wailsClient.historySummary })

export function usePruneHistory() {
  const client = useQueryClient()
  return useMutation({ mutationFn: wailsClient.pruneHistory, onSuccess: async () => { await client.invalidateQueries({ queryKey: queryKeys.runtime }); toast.success("History pruned") }, onError: error => toast.error("Could not prune history", { description: String(error) }) })
}

export function useClearHistory() {
  const client = useQueryClient()
  return useMutation({ mutationFn: wailsClient.clearHistory, onSuccess: async () => { await client.invalidateQueries({ queryKey: queryKeys.runtime }); toast.success("History cleared") }, onError: error => toast.error("Could not clear history", { description: String(error) }) })
}
