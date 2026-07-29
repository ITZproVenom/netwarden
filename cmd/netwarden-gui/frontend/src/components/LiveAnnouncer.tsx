import { useEffect, useState } from "react"
import type { AnnouncementPriority } from "@/lib/accessibility"

type Announcement = { message: string; priority: AnnouncementPriority }

export function LiveAnnouncer() {
  const [announcement, setAnnouncement] = useState<Announcement>({ message: "", priority: "polite" })
  useEffect(() => {
    const listener = (event: Event) => {
      const { detail } = event as CustomEvent<Announcement>
      setAnnouncement({ message: "", priority: detail.priority })
      window.setTimeout(() => setAnnouncement(detail), 25)
    }
    window.addEventListener("netwarden:announce", listener)
    return () => window.removeEventListener("netwarden:announce", listener)
  }, [])
  return (
    <div
      className="sr-only"
      role={announcement.priority === "assertive" ? "alert" : "status"}
      aria-live={announcement.priority}
      aria-atomic="true"
    >
      {announcement.message}
    </div>
  )
}
