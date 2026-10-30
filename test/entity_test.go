package test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/idnatiya/netra-vuln-agent/internal/entity"
)

func TestTruncateError(t *testing.T) {
	if got := entity.TruncateError("short"); got != "short" {
		t.Fatalf("got %q", got)
	}
	// "é" is 2 bytes; the "x" prefix shifts the cut point into the middle of a rune.
	got := entity.TruncateError("x" + strings.Repeat("é", entity.MaxErrorBytes))
	if len(got) > entity.MaxErrorBytes || !utf8.ValidString(got) {
		t.Fatalf("len=%d valid=%v", len(got), utf8.ValidString(got))
	}
}
