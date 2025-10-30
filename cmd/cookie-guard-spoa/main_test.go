package main

import (
	"strings"
	"testing"
)

func TestTokenLooksPlausibleAcceptsLegitTokens(t *testing.T) {
	origNow := nowUnix
	nowUnix = func() int64 { return 1_700_000_000 }
	defer func() { nowUnix = origNow }()

	sec.Store(&secrets{primary: []byte("super-secret-key")})
	defer sec.Store(nil)

	for _, ip := range []string{
		"1.1.1.1",
		"81.36.64.174",
		"255.255.255.255",
		"2001:db8::1",
	} {
		token, _, err := issueToken(ip, "Mozilla/5.0")
		if err != nil {
			t.Fatalf("issueToken failed for %q: %v", ip, err)
		}
		if !tokenLooksPlausible(ip, token) {
			t.Fatalf("expected tokenLooksPlausible to accept token for ip=%q len=%d", ip, len(token))
		}
	}
}

func TestTokenLooksPlausibleRejectsCorruptedTokens(t *testing.T) {
	origNow := nowUnix
	nowUnix = func() int64 { return 1_700_000_000 }
	defer func() { nowUnix = origNow }()

	sec.Store(&secrets{primary: []byte("super-secret-key")})
	defer sec.Store(nil)

	ip := "81.36.64.174"
	token, _, err := issueToken(ip, "Mozilla/5.0")
	if err != nil {
		t.Fatalf("issueToken failed: %v", err)
	}

	// Truncate the payload by one character.
	corrupted := token[:len(token)-1]
	if tokenLooksPlausible(ip, corrupted) {
		t.Fatalf("expected truncated token (len=%d) to be rejected", len(corrupted))
	}

	// Swap in a payload length that is too large.
	corrupted = strings.Replace(token, ".", "A.", 1)
	if tokenLooksPlausible(ip, corrupted) {
		t.Fatalf("expected token with extended payload to be rejected")
	}

	// Provide mismatching IP (should affect the expected payload length calculation).
	if tokenLooksPlausible("10.0.0.1", token) {
		t.Fatalf("expected token to be rejected when evaluated with mismatching ip")
	}
}
