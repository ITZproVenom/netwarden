import { useQuery } from "@tanstack/react-query"
import { queryKeys } from "@/lib/query-keys"
import { wailsClient } from "@/lib/wails/client"

export const useConflicts = () => useQuery({ queryKey: queryKeys.conflicts, queryFn: wailsClient.conflicts })
