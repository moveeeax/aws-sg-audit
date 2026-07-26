package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/moveeeax/aws-sg-audit/internal/audit"
	"github.com/moveeeax/aws-sg-audit/internal/awsscan"
)

type fakeScanner struct{ sgs []audit.SecurityGroup }

func (f fakeScanner) Scan(context.Context, []string) ([]audit.SecurityGroup, error) {
	return f.sgs, nil
}

func withScanner(t *testing.T, sgs []audit.SecurityGroup) {
	t.Helper()
	orig := scannerFactory
	scannerFactory = func(string) awsscan.Scanner { return fakeScanner{sgs} }
	t.Cleanup(func() { scannerFactory = orig })
}

func run(t *testing.T, args ...string) (string, int, error) {
	t.Helper()
	var out bytes.Buffer
	code, err := Run(args, &out, &out)
	return out.String(), code, err
}

func openSG() audit.SecurityGroup {
	return audit.SecurityGroup{ID: "sg-1", Name: "web", Region: "us-east-1", Attached: true,
		Ingress: []audit.Perm{{Proto: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"0.0.0.0/0"}}}}
}

func TestRunTableFindingsExit1(t *testing.T) {
	withScanner(t, []audit.SecurityGroup{openSG()})
	out, code, err := run(t, "--regions", "us-east-1")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != exitFindings {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(out, "SSH") {
		t.Errorf("expected SSH in output:\n%s", out)
	}
}

func TestRunCleanExit0(t *testing.T) {
	clean := audit.SecurityGroup{ID: "sg-ok", Region: "us-east-1",
		Ingress: []audit.Perm{{Proto: "tcp", FromPort: 443, ToPort: 443, CIDRs: []string{"0.0.0.0/0"}}}}
	withScanner(t, []audit.SecurityGroup{clean})
	out, code, err := run(t, "--regions", "us-east-1")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != exitOK {
		t.Errorf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, "No world-open") {
		t.Errorf("unexpected output: %s", out)
	}
}

func TestRunJSON(t *testing.T) {
	withScanner(t, []audit.SecurityGroup{openSG()})
	out, _, err := run(t, "--regions", "us-east-1", "--format", "json")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var fs []audit.Finding
	if err := json.Unmarshal([]byte(out), &fs); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(fs) != 1 {
		t.Errorf("expected 1 finding, got %d", len(fs))
	}
}

func TestRunSARIF(t *testing.T) {
	withScanner(t, []audit.SecurityGroup{openSG()})
	out, _, err := run(t, "--regions", "us-east-1", "--format", "sarif")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "\"version\": \"2.1.0\"") {
		t.Errorf("expected SARIF doc:\n%s", out)
	}
}

func TestRunRequiresRegions(t *testing.T) {
	withScanner(t, nil)
	if _, code, err := run(t, "--format", "table"); err == nil || code != exitError {
		t.Errorf("expected error+exit2 without --regions, got code=%d err=%v", code, err)
	}
}

func TestFailOnNoneAlwaysZero(t *testing.T) {
	withScanner(t, []audit.SecurityGroup{openSG()})
	_, code, err := run(t, "--regions", "us-east-1", "--fail-on", "none")
	if err != nil {
		t.Fatal(err)
	}
	if code != exitOK {
		t.Errorf("--fail-on none should exit 0 even with findings, got %d", code)
	}
}

func TestFailOnCriticalIgnoresHigh(t *testing.T) {
	// An unattached SSH finding is "high"; --fail-on critical should not trip.
	unattached := audit.SecurityGroup{ID: "sg-2", Region: "us-east-1",
		Ingress: []audit.Perm{{Proto: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"0.0.0.0/0"}}}}
	withScanner(t, []audit.SecurityGroup{unattached})
	_, code, err := run(t, "--regions", "us-east-1", "--fail-on", "critical")
	if err != nil {
		t.Fatal(err)
	}
	if code != exitOK {
		t.Errorf("high finding with --fail-on critical should exit 0, got %d", code)
	}
}
