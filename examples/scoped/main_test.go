package main

import (
	"context"
	"strings"
	"testing"

	"github.com/tpyle/auth/v2"
)

func TestRun(t *testing.T) {
	cheap := auth.WithArgon2Params(auth.Argon2Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	var out strings.Builder
	if err := run(context.Background(), &out, cheap); err != nil {
		t.Fatal(err)
	}
	// user method path -> status
	want := map[[3]string]string{
		{"alice", "DELETE", "/projects/42"}:             "204",
		{"alice", "GET", "/projects/43/docs/1/history"}: "204",
		{"bob", "PUT", "/projects/42/docs/7"}:           "204",
		{"bob", "GET", "/projects/42/docs/8"}:           "204",
		{"bob", "GET", "/projects/43/docs/1"}:           "403",
		{"bob", "DELETE", "/projects/42"}:               "403",
		{"carol", "GET", "/projects/42/docs/7"}:         "204",
		{"carol", "PUT", "/projects/42/docs/7"}:         "403",
		{"carol", "GET", "/projects/42/docs/8"}:         "403",
		{"dave", "GET", "/projects/43/docs/1"}:          "204",
		{"dave", "GET", "/projects/43/docs/1/history"}:  "204",
		{"dave", "PUT", "/projects/42/docs/7"}:          "403",
		{"dave", "DELETE", "/projects/42"}:              "403",
	}
	got := map[[3]string]string{}
	for line := range strings.Lines(out.String()) {
		f := strings.Fields(line)
		if len(f) != 4 {
			t.Fatalf("bad line %q", line)
		}
		got[[3]string{f[0], f[1], f[2]}] = f[3]
	}
	if len(got) != len(users)*len(requests) {
		t.Errorf("got %d results, want %d:\n%s", len(got), len(users)*len(requests), out.String())
	}
	for k, status := range want {
		if got[k] != status {
			t.Errorf("%v = %s, want %s", k, got[k], status)
		}
	}
}
