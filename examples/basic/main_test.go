package main

import (
	"context"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	var out strings.Builder
	if err := run(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	want := `token payload: {"roles":["editor","viewer"]}
alice has role viewer: true
alice has role admin: false
alice can posts:read:   true
alice can posts:delete: true
alice can users:delete: false
`
	if got := out.String(); got != want {
		t.Errorf("output:\n%s\nwant:\n%s", got, want)
	}
}
