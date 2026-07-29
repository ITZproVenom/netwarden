package main

const (
	applicationName = "NetWarden"
)

// Release builds override these values with -ldflags. The defaults keep local
// development builds useful without requiring a generated source file.
var (
	applicationVersion = "2.0.0"
	buildVersion       = "development"
)
