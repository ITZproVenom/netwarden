//go:build darwin

package main

import "os/exec"

func sendNativeNotification(title, body string) error {
	const script = `on run argv
display notification (item 2 of argv) with title (item 1 of argv)
end run`
	return exec.Command("/usr/bin/osascript", "-e", script, title, body).Run()
}
