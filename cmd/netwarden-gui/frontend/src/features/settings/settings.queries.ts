import { useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { queryKeys } from "@/lib/query-keys"
import { wailsClient } from "@/lib/wails/client"

export function useSetGatewayMAC() {
  const client = useQueryClient()
  return useMutation({ mutationFn: wailsClient.setGatewayMAC, onSuccess: async () => { await client.invalidateQueries({ queryKey: queryKeys.bootstrap }); toast.success("Gateway baseline updated") }, onError: error => toast.error("Could not update gateway baseline", { description: String(error) }) })
}
