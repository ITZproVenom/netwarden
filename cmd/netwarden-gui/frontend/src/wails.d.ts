export {}
declare global {
  interface Window {
    go?: { main?: { GUIApp?: Record<string, (...args: any[]) => Promise<any>> } }
    runtime?: {
      EventsOn: (name: string, callback: (...args: any[]) => void) => () => void
      ClipboardSetText?: (text: string) => Promise<boolean>
    }
  }
}
