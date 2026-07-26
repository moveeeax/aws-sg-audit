// Package report renders audit findings as table, JSON, or SARIF.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/moveeeax/aws-sg-audit/internal/audit"
)

// Table writes a human-readable table of findings.
func Table(w io.Writer, findings []audit.Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No world-open sensitive ports found.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tREGION\tSECURITY GROUP\tPORT\tSERVICE\tCIDR\tATTACHED")
	for _, f := range findings {
		port := "all"
		if f.Port >= 0 {
			port = fmt.Sprintf("%d/%s", f.Port, f.Proto)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s (%s)\t%s\t%s\t%s\t%t\n",
			f.Severity, f.Region, name(f.SGName), f.SGID, port, f.Service, f.CIDR, f.Attached)
	}
	tw.Flush()
	fmt.Fprintf(w, "\n%d finding(s).\n", len(findings))
}

func name(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// JSON writes findings as a JSON array.
func JSON(w io.Writer, findings []audit.Finding) error {
	if findings == nil {
		findings = []audit.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

// --- SARIF 2.1.0 ---

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID string `json:"id"`
}
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	LogicalLocations []sarifLogical `json:"logicalLocations"`
}
type sarifLogical struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

// sarifLevel maps a severity to a SARIF result level.
func sarifLevel(sev string) string {
	switch sev {
	case audit.Critical, audit.High:
		return "error"
	default:
		return "warning"
	}
}

// SARIF writes findings as a SARIF 2.1.0 document for GitHub code scanning.
func SARIF(w io.Writer, findings []audit.Finding) error {
	ruleSet := map[string]bool{}
	var results []sarifResult
	for _, f := range findings {
		ruleID := "sg-open-" + f.Service
		ruleSet[ruleID] = true
		port := "all ports"
		if f.Port >= 0 {
			port = fmt.Sprintf("port %d/%s", f.Port, f.Proto)
		}
		results = append(results, sarifResult{
			RuleID: ruleID,
			Level:  sarifLevel(f.Severity),
			Message: sarifMessage{Text: fmt.Sprintf(
				"Security group %s (%s) in %s exposes %s (%s) to %s [attached=%t]",
				f.SGID, name(f.SGName), f.Region, f.Service, port, f.CIDR, f.Attached)},
			Locations: []sarifLocation{{LogicalLocations: []sarifLogical{{
				Name: f.SGID, FullyQualifiedName: f.Region + "/" + f.SGID, Kind: "resource"}}}},
		})
	}
	rules := make([]sarifRule, 0, len(ruleSet))
	for id := range ruleSet {
		rules = append(rules, sarifRule{ID: id})
	}
	if results == nil {
		results = []sarifResult{}
	}
	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "aws-sg-audit", InformationURI: "https://github.com/moveeeax/aws-sg-audit", Rules: rules}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
