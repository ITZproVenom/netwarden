import { useEffect, type ReactNode } from "react"
import { QueryClient, QueryClientProvider, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import { ThemeProvider } from "next-themes"
import { subscribeRuntimeEvents } from "@/lib/wails/events"
import { queryKeys } from "@/lib/query-keys"
import { UnsavedChangesProvider } from "@/app/unsaved-changes"
import { LiveAnnouncer } from "@/components/LiveAnnouncer"
import { announce } from "@/lib/accessibility"

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 2_000, retry: 1 } } })

function RuntimeEventBridge() {
  const client = useQueryClient()
  useEffect(
    () =>
      subscribeRuntimeEvents({
        onChange: (event) => {
          client.invalidateQueries({ queryKey: queryKeys.runtime })
          if (event?.title)
            announce(
              [event.title, event.detail].filter(Boolean).join(". "),
              event.severity === "error" ? "assertive" : "polite",
            )
        },
        onError: (message) => {
          toast.error("Runtime error", { description: message })
          announce(`Runtime error. ${message}`, "assertive")
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
        <UnsavedChangesProvider>
          <TooltipProvider>
            <RuntimeEventBridge />
            <LiveAnnouncer />
            {children}
            <Toaster richColors position="bottom-right" />
          </TooltipProvider>
        </UnsavedChangesProvider>
      </QueryClientProvider>
    </ThemeProvider>
  )
}
