import { Ban, LoaderCircle, RotateCcw } from "lucide-react"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"

export function BulkProgress({ count, operation }: { count: number; operation: string }) {
  return (
    <div className="border-b bg-primary/8 px-4 py-4" role="status" aria-live="polite" aria-atomic="true">
      <div className="mb-2 flex items-center justify-between gap-4 text-sm font-medium">
        <span className="flex items-center gap-2">
          <LoaderCircle className="size-4 animate-spin text-primary" />
          {operation}
        </span>
        <span className="text-xs text-muted-foreground">
          {count} target{count === 1 ? "" : "s"}
        </span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-muted" aria-hidden="true">
        <div className="h-full w-2/3 animate-pulse rounded-full bg-primary shadow-[0_0_12px_var(--primary)]" />
      </div>
      <p className="mt-2 text-xs text-muted-foreground">Keep NetWarden open while the network operation completes.</p>
    </div>
  )
}

export function DisconnectSelected({
  count,
  pending,
  disconnect,
}: {
  count: number
  pending: boolean
  disconnect: () => void
}) {
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="destructive" disabled={pending}>
          {pending ? <LoaderCircle className="animate-spin" /> : <Ban />}Disconnect selected ({count})
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Disconnect selected devices?</AlertDialogTitle>
          <AlertDialogDescription>
            This will interrupt gateway access for {count} selected online device{count === 1 ? "" : "s"}. NetWarden
            will roll back previously changed targets if any device fails.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction variant="destructive" onClick={disconnect}>
            Disconnect selected devices
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

export function RestoreAll({ count, pending, restore }: { count: number; pending: boolean; restore: () => void }) {
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="outline" disabled={pending}>
          {pending ? <LoaderCircle className="animate-spin" /> : <RotateCcw />}Restore all ({count})
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Restore all controlled devices?</AlertDialogTitle>
          <AlertDialogDescription>
            This stops active control and restores normal network access for {count} device{count === 1 ? "" : "s"}.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={restore}>Restore all</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
