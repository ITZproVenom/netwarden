package metadata

import (
	"testing"

	"github.com/amdzy/NetWarden/internal/device"
)

func TestResolverAppliesNicknameAndVendor(t *testing.T) {
	resolver, err := NewResolver(map[string]string{"00:00:0c:00:00:01": "Router"})
	if err != nil {
		t.Fatal(err)
	}
	got := resolver.Enrich(device.Device{MAC: "00:00:0c:00:00:01"})
	if got.Name != "Router" || got.Vendor != "Cisco Systems, Inc" {
		t.Fatalf("unexpected metadata: %#v", got)
	}
}

func TestResolverReturnsUnknownVendor(t *testing.T) {
	resolver, err := NewResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := resolver.Enrich(device.Device{MAC: "02:00:00:00:00:01"}); got.Vendor != "Unknown" {
		t.Fatalf("unexpected metadata: %#v", got)
	}
}
