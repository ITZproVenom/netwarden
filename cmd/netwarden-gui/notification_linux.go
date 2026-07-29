//go:build linux

package main

import "os/exec"

func sendNativeNotification(title, body string) error {
	return exec.Command("notify-send", "--app-name=NetWarden", title, body).Run()
}
