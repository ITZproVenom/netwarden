// Command prepare-release synchronizes package metadata before a release build.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var semanticVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$`)

func main() {
	version := flag.String("version", "", "semantic release version without a v prefix")
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	if err := run(*root, *version); err != nil {
		fmt.Fprintln(os.Stderr, "prepare release:", err)
		os.Exit(1)
	}
}

func run(root, version string) error {
	if !semanticVersion.MatchString(version) {
		return errors.New("version must be semantic, for example 2.1.0 or 2.1.0-beta.1")
	}
	path := filepath.Join(root, "cmd", "netwarden-gui", "wails.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var config map[string]any
	if err := json.Unmarshal(contents, &config); err != nil {
		return err
	}
	info, ok := config["info"].(map[string]any)
	if !ok {
		return errors.New("wails.json has no info object")
	}
	info["productVersion"] = version
	updated, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	updated = append(updated, '\n')
	return os.WriteFile(path, updated, 0o644)
}
