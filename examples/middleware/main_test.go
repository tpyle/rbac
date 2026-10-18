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
	want := []string{
		`GET    /posts/1 ""                   401`,
		`GET    /posts/1 "Bearer forged"      401`,
		`GET    /posts/1 "Basic alice-token"  401`,
		`GET    /posts/1 "Bearer bob-token"   204`,
		`DELETE /posts/1 "Bearer bob-token"   403`,
		`DELETE /posts/1 "Bearer alice-token" 204`,
	}
	got := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("output:\n%s\nwant:\n%s", out.String(), strings.Join(want, "\n"))
	}
}
