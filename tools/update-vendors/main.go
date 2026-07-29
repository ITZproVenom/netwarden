// Command update-vendors rebuilds the embedded vendor database from the
// official IEEE MA-L, MA-M, and MA-S public CSV registries.
package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

const outputPath = "internal/metadata/vendors.json"

type registry struct {
	name       string
	url        string
	prefixSize int
	minimum    int
}

var registries = []registry{
	{name: "MA-L", url: "https://standards-oui.ieee.org/oui/oui.csv", prefixSize: 6, minimum: 30_000},
	{name: "MA-M", url: "https://standards-oui.ieee.org/oui28/mam.csv", prefixSize: 7, minimum: 4_000},
	{name: "MA-S", url: "https://standards-oui.ieee.org/oui36/oui36.csv", prefixSize: 9, minimum: 6_000},
}

type vendorRecord struct {
	Prefix string `json:"macPrefix"`
	Name   string `json:"vendorName"`
}

func main() {
	client := &http.Client{Timeout: 45 * time.Second}
	assignments := make(map[string]string)
	for _, source := range registries {
		records, err := download(client, source)
		if err != nil {
			fatal(err)
		}
		for _, record := range records {
			if existing, ok := assignments[record.Prefix]; ok && existing != record.Name {
				fatal(fmt.Errorf("conflicting assignment %s: %q and %q", record.Prefix, existing, record.Name))
			}
			assignments[record.Prefix] = record.Name
		}
		fmt.Fprintf(os.Stderr, "%s: %d assignments\n", source.name, len(records))
	}

	records := make([]vendorRecord, 0, len(assignments))
	for prefix, name := range assignments {
		records = append(records, vendorRecord{Prefix: formatPrefix(prefix), Name: name})
	}
	sort.Slice(records, func(i, j int) bool {
		left, right := compactPrefix(records[i].Prefix), compactPrefix(records[j].Prefix)
		if left == right {
			return records[i].Name < records[j].Name
		}
		return left < right
	})
	if err := writeAtomically(outputPath, records); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "wrote %d assignments to %s\n", len(records), outputPath)
}

func download(client *http.Client, source registry) ([]vendorRecord, error) {
	request, err := http.NewRequest(http.MethodGet, source.url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "NetWarden vendor database updater")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", source.name, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %s", source.name, response.Status)
	}
	records, err := parseCSV(response.Body, source)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", source.name, err)
	}
	if len(records) < source.minimum {
		return nil, fmt.Errorf("validate %s: got %d assignments, expected at least %d", source.name, len(records), source.minimum)
	}
	return records, nil
}

func parseCSV(input io.Reader, source registry) ([]vendorRecord, error) {
	reader := csv.NewReader(input)
	reader.ReuseRecord = true
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	assignmentColumn, organizationColumn := -1, -1
	for index, value := range header {
		switch strings.TrimSpace(strings.TrimPrefix(value, "\ufeff")) {
		case "Assignment":
			assignmentColumn = index
		case "Organization Name":
			organizationColumn = index
		}
	}
	if assignmentColumn < 0 || organizationColumn < 0 {
		return nil, errors.New("required Assignment and Organization Name columns are missing")
	}
	seen := make(map[string]string)
	for line := 2; ; line++ {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if assignmentColumn >= len(row) || organizationColumn >= len(row) {
			return nil, fmt.Errorf("line %d: incomplete row", line)
		}
		prefix := compactPrefix(row[assignmentColumn])
		name := strings.TrimSpace(row[organizationColumn])
		if len(prefix) != source.prefixSize || !isHex(prefix) {
			return nil, fmt.Errorf("line %d: invalid %s assignment %q", line, source.name, row[assignmentColumn])
		}
		if name == "" {
			return nil, fmt.Errorf("line %d: empty organization name", line)
		}
		// IEEE's public files contain a small number of historical duplicate
		// assignments. The later row is the current public listing, matching the
		// ordering used by IEEE's downloadable data.
		seen[prefix] = name
	}
	records := make([]vendorRecord, 0, len(seen))
	for prefix, name := range seen {
		records = append(records, vendorRecord{Prefix: prefix, Name: name})
	}
	return records, nil
}

func compactPrefix(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsSpace(character) || character == ':' || character == '-' || character == '.' {
			return -1
		}
		return unicode.ToUpper(character)
	}, value)
}

func isHex(value string) bool {
	for _, character := range value {
		if !strings.ContainsRune("0123456789ABCDEF", character) {
			return false
		}
	}
	return true
}

func formatPrefix(prefix string) string {
	var formatted strings.Builder
	formatted.Grow(len(prefix) + len(prefix)/2)
	for index, character := range prefix {
		if index > 0 && index%2 == 0 {
			formatted.WriteByte(':')
		}
		formatted.WriteRune(character)
	}
	return formatted.String()
}

func writeAtomically(path string, records []vendorRecord) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".vendors-*.json")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	encoder := json.NewEncoder(temporary)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(records); err != nil {
		temporary.Close()
		return fmt.Errorf("encode output: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace output: %w", err)
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "update-vendors:", err)
	os.Exit(1)
}
