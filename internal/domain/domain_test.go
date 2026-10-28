package domain

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateError(t *testing.T) {
	if got := TruncateError("short"); got != "short" {
		t.Fatalf("got %q", got)
	}
	// "é" is 2 bytes; the "x" prefix shifts the cut point into the middle of a rune.
	got := TruncateError("x" + strings.Repeat("é", MaxErrorBytes))
	if len(got) > MaxErrorBytes || !utf8.ValidString(got) {
		t.Fatalf("len=%d valid=%v", len(got), utf8.ValidString(got))
	}
}
