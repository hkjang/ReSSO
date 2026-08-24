package oidc

import "testing"

// at_hash is checked by strict relying parties and ignored by lenient ones, so
// getting it wrong fails for some callers and not others — the kind of break
// that gets attributed to the strict client rather than to the issuer. The
// value here is the worked example published in OpenID Connect Core 3.3.2.11,
// which makes this a check against the specification rather than against
// whatever the code currently does.
//
// The shape is easy to change by accident: the whole digest instead of its
// left half, or standard base64 instead of base64url, both look like tidying.
func TestAccessTokenHashMatchesTheSpecificationsExample(t *testing.T) {
	const accessToken = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
	const published = "77QmUPtjPfzWtF2AnpK9RQ"
	if got := accessTokenHash(accessToken); got != published {
		t.Errorf("accessTokenHash(%q) = %q, want %q", accessToken, got, published)
	}
	// Left half of SHA-256 is 16 bytes, which is 22 base64url characters with
	// no padding. A hash of the wrong length is the give-away for both
	// mistakes above.
	if got := accessTokenHash("any other token"); len(got) != 22 {
		t.Errorf("accessTokenHash produced %d characters (%q), want 22", len(got), got)
	}
}
