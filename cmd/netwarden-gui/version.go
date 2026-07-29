package main

const (
	applicationName    = "NetWarden"
	applicationVersion = "2.0.0"
)

// buildVersion may be overridden by release builds with:
// -ldflags "-X main.buildVersion=<commit-or-build-id>"
var buildVersion = "development"
