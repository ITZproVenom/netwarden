package helperclient

import (
	"slices"
	"testing"
)

func TestMergeEnvironmentReplacesExistingValues(t *testing.T) {
	merged := mergeEnvironment([]string{"PATH=/bin", "SUDO_ASKPASS=old", "LANG=en"}, map[string]string{
		"SUDO_ASKPASS":      "new",
		"NETWARDEN_ASKPASS": "1",
	})
	if slices.Contains(merged, "SUDO_ASKPASS=old") {
		t.Fatal("old environment value was retained")
	}
	for _, expected := range []string{"PATH=/bin", "LANG=en", "SUDO_ASKPASS=new", "NETWARDEN_ASKPASS=1"} {
		if !slices.Contains(merged, expected) {
			t.Fatalf("missing %q from %v", expected, merged)
		}
	}
}
