package store

import (
	"strings"
	"testing"
)

// A truncated list of reasons must never read as the whole list: an operator
// who fixes the five named users and sees the same count return has been told
// something false about what is left.
func TestDescribeSyncFailuresSaysHowManyItLeftOut(t *testing.T) {
	named := []string{"a: taken", "b: taken", "c: taken", "d: taken", "e: taken"}
	if described := describeSyncFailures(named, 12); !strings.Contains(described, "and 7 more") {
		t.Errorf("describeSyncFailures(5 of 12) = %q, want it to account for the other 7", described)
	}
	if described := describeSyncFailures(named, 5); strings.Contains(described, "more") {
		t.Errorf("describeSyncFailures(5 of 5) = %q, want no claim of more", described)
	}
	if described := describeSyncFailures(nil, 3); described == "" {
		t.Error("describeSyncFailures with nothing named produced an empty reason")
	}
}
