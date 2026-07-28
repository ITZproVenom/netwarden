import { useEffect, type ReactNode } from "react"
import { QueryClient, QueryClientProvider, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import { ThemeProvider } from "next-themes"
import { subscribeRuntimeEvents } from "@/lib/wails/events"
import { queryKeys } from "@/lib/query-keys"

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 2_000, retry: 1 } } })

function RuntimeEventBridge() {
  const client = useQueryClient()
  useEffect(
    () =>
      subscribeRuntimeEvents({
        onChange: () => client.invalidateQueries({ queryKey: queryKeys.runtime }),
        onError: (message) => {
          toast.error("Runtime error", { description: message })
          client.invalidateQueries({ queryKey: queryKeys.runtime })
        },
      }),
    [client],
  )
  return null
}

export function AppProviders({ children }: { children: ReactNode }) {
  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <RuntimeEventBridge />
          {children}
          <Toaster richColors position="bottom-right" />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  )
}
