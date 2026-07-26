package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/moveeeax/aws-sg-audit/internal/audit"
)

func sample() []audit.Finding {
	return []audit.Finding{
		{SGID: "sg-1", SGName: "web", Region: "us-east-1", Proto: "tcp", Port: 22, Service: "SSH", CIDR: "0.0.0.0/0", Severity: audit.High, Attached: true},
		{SGID: "sg-2", SGName: "db", Region: "eu-west-1", Proto: "tcp", Port: 3306, Service: "MySQL", CIDR: "::/0", Severity: audit.High, Attached: false},
	}
}

func TestTable(t *testing.T) {
	var b bytes.Buffer
	Table(&b, sample())
	out := b.String()
	for _, sub := range []string{"SEVERITY", "sg-1", "SSH", "22/tcp", "2 finding(s)"} {
		if !strings.Contains(out, sub) {
			t.Errorf("table missing %q\n%s", sub, out)
		}
	}
}

func TestTableEmpty(t *testing.T) {
	var b bytes.Buffer
	Table(&b, nil)
	if !strings.Contains(b.String(), "No world-open") {
		t.Errorf("unexpected empty table: %s", b.String())
	}
}

func TestJSON(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, sample()); err != nil {
		t.Fatal(err)
	}
	var got []audit.Finding
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(got) != 2 || got[0].Service != "SSH" {
		t.Errorf("unexpected JSON: %+v", got)
	}
}

func TestSARIF(t *testing.T) {
	var b bytes.Buffer
	if err := SARIF(&b, sample()); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v", doc["version"])
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected one run, got %v", doc["runs"])
	}
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
	first := results[0].(map[string]any)
	if first["level"] != "error" {
		t.Errorf("high severity should map to SARIF error, got %v", first["level"])
	}
}

func TestSARIFEmpty(t *testing.T) {
	var b bytes.Buffer
	if err := SARIF(&b, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "\"results\": []") {
		t.Errorf("empty SARIF should have empty results array:\n%s", b.String())
	}
}
