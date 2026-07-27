// Package metadata enriches device snapshots with user nicknames and embedded
// IEEE OUI vendor information.
package metadata

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/amdzy/NetWarden/internal/device"
)

//go:embed vendors.json
var vendorData []byte

type vendorRecord struct {
	Prefix string `json:"macPrefix"`
	Name   string `json:"vendorName"`
}

var vendorIndex struct {
	sync.Once
	values map[string]string
	err    error
}

type Resolver struct {
	nicknames map[string]string
	vendors   map[string]string
}

func NewResolver(nicknames map[string]string) (*Resolver, error) {
	vendorIndex.Do(func() {
		var records []vendorRecord
		if err := json.Unmarshal(vendorData, &records); err != nil {
			vendorIndex.err = fmt.Errorf("decode embedded vendor database: %w", err)
			return
		}
		vendorIndex.values = make(map[string]string, len(records))
		for _, record := range records {
			prefix := strings.ToUpper(strings.TrimSpace(record.Prefix))
			if prefix != "" && record.Name != "" {
				vendorIndex.values[prefix] = record.Name
			}
		}
	})
	if vendorIndex.err != nil {
		return nil, vendorIndex.err
	}
	copyNicknames := make(map[string]string, len(nicknames))
	for mac, nickname := range nicknames {
		copyNicknames[strings.ToLower(mac)] = nickname
	}
	return &Resolver{nicknames: copyNicknames, vendors: vendorIndex.values}, nil
}

func (r *Resolver) Enrich(snapshot device.Device) device.Metadata {
	result := device.Metadata{Vendor: "Unknown"}
	mac := strings.ToLower(snapshot.MAC)
	if nickname := r.nicknames[mac]; nickname != "" {
		result.Name = nickname
	}
	if len(mac) >= 8 {
		if vendor := r.vendors[strings.ToUpper(mac[:8])]; vendor != "" {
			result.Vendor = vendor
		}
	}
	return result
}
