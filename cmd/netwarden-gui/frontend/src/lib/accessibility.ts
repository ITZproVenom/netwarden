export type AnnouncementPriority = "polite" | "assertive"

export function announce(message: string, priority: AnnouncementPriority = "polite") {
  window.dispatchEvent(new CustomEvent("netwarden:announce", { detail: { message, priority } }))
}
