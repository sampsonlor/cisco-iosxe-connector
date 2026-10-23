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
	if err != nil || !e.Complete || len(e.Raw) != 5 {
		t.Fatalf("readiness complete=%v reads=%d err=%v", e.Complete, len(e.Raw), err)
	}
	want := []string{"exec:show clock detail", "exec:show ntp status", "exec:show privilege", "exec:show running-config | include ^netconf|^restconf", "exec:show ip http server status"}
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

func TestPrivateObserverCannotChangeEvidence(t *testing.T) {
	f := startFixture(t, &fixture{})
	c := testClient(t, f, false, true)
	calls := 0
	c.observer = func(op Operation, raw []byte, complete, accepted bool) {
		calls++
		if !complete || !accepted {
			t.Error("successful read marked incomplete")
		}
		clear(raw)
	}
	e, err := c.Collect(context.Background(), "router-a")
	if err != nil || !e.Complete || calls != 5 || !strings.Contains(string(e.Raw[ReadVersion]), "synthetic") {
		t.Fatal("observer modified parser evidence")
	}
}

func TestDisabledNTPIsOnlyAReadinessObservation(t *testing.T) {
	f := startFixture(t, &fixture{commandOutputs: map[string]string{"show ntp status": "\r\n%NTP is not enabled.", "show clock detail": "*12:00:00.000 UTC Fri Oct 23 2026\nNo time source"}})
	c := testClient(t, f, false, true)
	e, err := c.Readiness(context.Background(), "router-a")
	if err != nil || !e.Complete || !strings.Contains(string(e.Raw[ReadNTP]), "not enabled") {
		t.Fatal("disabled NTP was mistaken for unreadable readiness")
	}
	if classifyCLI([]byte("%NTP is not enabled."), nil, false) == nil {
		t.Fatal("NTP observation exception leaked into general inventory validation")
	}
}
