import { AlertTriangle, RefreshCw } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { errorMessage, isBackendUnavailable } from "@/lib/errors"

export function QueryError({
  error,
  retry,
  title = "Could not load data",
}: {
  error: unknown
  retry?: () => void
  title?: string
}) {
  const browser = isBackendUnavailable(error)
  return (
    <Alert variant="destructive">
      <AlertTriangle />
      <AlertTitle>{browser ? "Wails backend unavailable" : title}</AlertTitle>
      <AlertDescription className="flex flex-wrap items-center justify-between gap-3">
        <span>
          {browser
            ? "This page is running in a regular browser. Open it through the Wails application to use native backend features."
            : errorMessage(error)}
        </span>
        {retry && (
          <Button variant="outline" size="sm" onClick={retry}>
            <RefreshCw />
            Retry
          </Button>
        )}
      </AlertDescription>
    </Alert>
  )
}
