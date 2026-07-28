export async function copyText(value: string) {
  if (window.runtime?.ClipboardSetText) {
    const copied = await window.runtime.ClipboardSetText(value)
    if (!copied) throw new Error("clipboard rejected the value")
    return
  }
  await navigator.clipboard.writeText(value)
}
