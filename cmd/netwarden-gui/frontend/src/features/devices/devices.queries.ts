import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { queryKeys } from "@/lib/query-keys"
import { wailsClient } from "@/lib/wails/client"

export const useDevices = () => useQuery({ queryKey: queryKeys.devices, queryFn: wailsClient.devices })

export function useSetNickname() {
  const client = useQueryClient()
  return useMutation({ mutationFn: ({ mac, nickname }: { mac: string; nickname: string }) => wailsClient.setNickname(mac, nickname), onSuccess: async () => { await client.invalidateQueries({ queryKey: queryKeys.devices }); toast.success("Nickname saved") }, onError: error => toast.error("Could not save nickname", { description: String(error) }) })
}
