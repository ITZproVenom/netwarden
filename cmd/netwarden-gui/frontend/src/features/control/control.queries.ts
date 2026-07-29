import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { queryKeys } from "@/lib/query-keys"
import { wailsClient } from "@/lib/wails/client"
import { errorMessage } from "@/lib/errors"
import { announce } from "@/lib/accessibility"

export const useControlAudit = () => useQuery({ queryKey: queryKeys.controlAudit, queryFn: wailsClient.controlAudit })

function useControlAction(action: (target: { ip: string; mac: string }) => Promise<void>, success: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: action,
    onSuccess: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: queryKeys.runtime }),
        client.invalidateQueries({ queryKey: queryKeys.controlAudit }),
      ])
      toast.success(success)
      announce(success)
    },
    onError: (error) => {
      const message = errorMessage(error)
      toast.error("Control request failed", { description: message })
      announce(`Control request failed. ${message}`, "assertive")
    },
  })
}

export const useDisconnectDevice = () =>
  useControlAction((target) => wailsClient.disconnectDevice(target.ip, target.mac), "Device disconnected")
export const useStartContinuousControl = () =>
  useControlAction((target) => wailsClient.startContinuousControl(target.ip, target.mac), "Continuous control started")

export function useDisconnectAllDevices() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: wailsClient.disconnectAllDevices,
    onSuccess: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: queryKeys.runtime }),
        client.invalidateQueries({ queryKey: queryKeys.controlAudit }),
      ])
      toast.success("All eligible devices disconnected")
      announce("Bulk control complete. All eligible devices disconnected")
    },
    onError: (error) => {
      const message = errorMessage(error)
      toast.error("Bulk disconnect failed", { description: message })
      announce(`Bulk disconnect failed. ${message}`, "assertive")
    },
  })
}

function useRecovery(action: (target: { ip: string; mac: string }) => Promise<void>, success: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: action,
    onSuccess: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: queryKeys.runtime }),
        client.invalidateQueries({ queryKey: queryKeys.controlAudit }),
      ])
      toast.success(success)
      announce(success)
    },
    onError: (error) => {
      const message = errorMessage(error)
      toast.error("Recovery failed", { description: message })
      announce(`Recovery failed. ${message}`, "assertive")
    },
  })
}

export const useRestoreControl = () =>
  useRecovery((target) => wailsClient.restoreControl(target.ip, target.mac), "Device restored")
export const useStopContinuousControl = () =>
  useRecovery((target) => wailsClient.stopContinuousControl(target.ip, target.mac), "Continuous control stopped")

export function useRestoreAllControls() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: wailsClient.restoreAllControls,
    onSuccess: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: queryKeys.runtime }),
        client.invalidateQueries({ queryKey: queryKeys.controlAudit }),
      ])
      toast.success("All controlled devices restored")
      announce("Bulk recovery complete. All controlled devices restored")
    },
    onError: (error) => {
      const message = errorMessage(error)
      toast.error("Bulk recovery failed", { description: message })
      announce(`Bulk recovery failed. ${message}`, "assertive")
    },
  })
}
