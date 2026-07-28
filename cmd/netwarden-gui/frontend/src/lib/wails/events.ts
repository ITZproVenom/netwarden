type Handlers = { onChange: () => void; onError: (message: string) => void }

export function subscribeRuntimeEvents(handlers: Handlers) {
  if (!window.runtime?.EventsOn) return () => undefined
  const offNetwork = window.runtime.EventsOn("network:event", handlers.onChange)
  const offChanged = window.runtime.EventsOn("runtime:changed", handlers.onChange)
  const offError = window.runtime.EventsOn("runtime:error", handlers.onError)
  return () => {
    offNetwork()
    offChanged()
    offError()
  }
}
