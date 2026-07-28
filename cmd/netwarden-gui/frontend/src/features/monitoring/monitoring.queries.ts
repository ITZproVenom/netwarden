import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { queryKeys } from "@/lib/query-keys"
import { wailsClient } from "@/lib/wails/client"

export const useBootstrap = () => useQuery({ queryKey: queryKeys.bootstrap, queryFn: wailsClient.bootstrap })
export const useRuntimeStatus = () => useQuery({ queryKey: queryKeys.status, queryFn: wailsClient.status, refetchInterval: 5_000 })

export function useRuntimeAction<TVariables = void>(action: (variables: TVariables) => Promise<unknown>, success: string) {
  const client = useQueryClient()
  return useMutation({ mutationFn: action, onSuccess: async () => { await client.invalidateQueries({ queryKey: queryKeys.runtime }); toast.success(success) }, onError: error => toast.error("Action failed", { description: String(error) }) })
}
