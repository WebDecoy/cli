package main

import (
	"strings"
	"testing"
)

func TestUsageAndFlagsAreStrict(t *testing.T) {
	for _, args := range [][]string{{}, {"nope"}, {"status", "--setup"}, {"login", "--disconnect"}, {"login", "extra"}} {
		if code := run(args); code != 2 {
			t.Errorf("%v exited %d, want 2", args, code)
		}
	}
	if code := run([]string{"--help"}); code != 0 {
		t.Errorf("--help exited %d", code)
	}
	if code := run([]string{"version"}); code != 0 {
		t.Errorf("version exited %d", code)
	}
}

func TestApprovalLinkNamesThisClient(t *testing.T) {
	if !strings.HasSuffix(approvalURL(), "client_id="+defaultClientID) {
		t.Fatal(approvalURL())
	}
}
