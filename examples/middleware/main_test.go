package main

import (
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	var out strings.Builder
	if err := run(&out); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"GET", "/posts/1", "-", "401"},
		{"GET", "/posts/1", "forged", "401"},
		{"GET", "/posts/1", "bob-token", "204"},
		{"DELETE", "/posts/1", "bob-token", "403"},
		{"DELETE", "/posts/1", "alice-token", "204"},
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d:\n%s", len(lines), len(want), out.String())
	}
	for i, line := range lines {
		if got := strings.Fields(line); strings.Join(got, " ") != strings.Join(want[i], " ") {
			t.Errorf("line %d = %q, want %q", i, got, want[i])
		}
	}
}
