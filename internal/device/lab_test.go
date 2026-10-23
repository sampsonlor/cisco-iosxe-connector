package device

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestLabReadinessFixedCommands(t *testing.T) {
	f := startFixture(t, &fixture{})
	c := testClient(t, f, false, true)
	e, err := c.Readiness(context.Background(), "router-a")
	if err != nil || !e.Complete || len(e.Raw) != 4 {
		t.Fatalf("readiness complete=%v reads=%d err=%v", e.Complete, len(e.Raw), err)
	}
	want := []string{"exec:show clock detail", "exec:show ntp status", "exec:show privilege", "exec:show running-config | include ^netconf|^restconf"}
	if !slices.Equal(f.logs(), want) {
		t.Fatalf("unexpected requests: %v", f.logs())
	}
	for _, event := range e.Audit {
		if strings.Contains(string(event.Operation), "write") {
			t.Fatal("write operation escaped")
		}
	}
	if _, err := c.Readiness(context.Background(), "other"); !errors.Is(err, ErrPolicy) {
		t.Fatal("unapproved readiness target accepted")
	}
}

func TestLabReadinessDeniedDoesNotContinue(t *testing.T) {
	f := startFixture(t, &fixture{cliOutput: "% Authorization failed"})
	c := testClient(t, f, false, true)
	e, err := c.Readiness(context.Background(), "router-a")
	if !errors.Is(err, ErrPermission) || e.Complete || e.Raw != nil || len(f.logs()) != 1 {
		t.Fatal("denied readiness continued or exposed partial success")
	}
}

func TestCLICommandsUseIndependentConnections(t *testing.T) {
	f := startFixture(t, &fixture{oneSession: true})
	c := testClient(t, f, false, true)
	e, err := c.Collect(context.Background(), "router-a")
	if err != nil || !e.Complete || f.auth.Load() != 5 {
		t.Fatalf("single-exec server: complete=%v connections=%d err=%v", e.Complete, f.auth.Load(), err)
	}
	if len(f.logs()) != 5 {
		t.Fatal("fixed reads retried or omitted")
	}
}
