//go:build windows

package main

import "os/exec"

func sendNativeNotification(title, body string) error {
	const script = `$title=$args[0]; $body=$args[1]; Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.NotifyIcon]$n=New-Object System.Windows.Forms.NotifyIcon; $n.Icon=[System.Drawing.SystemIcons]::Shield; $n.BalloonTipTitle=$title; $n.BalloonTipText=$body; $n.Visible=$true; $n.ShowBalloonTip(5000); Start-Sleep -Milliseconds 5500; $n.Dispose()`
	return exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script, title, body).Run()
}
