// Package cmd wires the aws-sg-audit CLI.
package cmd

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/moveeeax/aws-sg-audit/internal/audit"
	"github.com/moveeeax/aws-sg-audit/internal/awsscan"
	"github.com/moveeeax/aws-sg-audit/internal/report"
)

// Exit codes: 0 clean, 1 findings, 2 usage/error.
const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

// scannerFactory is overridable in tests.
var scannerFactory = func(profile string) awsscan.Scanner { return awsscan.New(profile) }

// Run executes the CLI and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) (int, error) {
	var (
		regions     string
		profile     string
		format      string
		publicPorts string
		ignoreTag   string
		failOn      string
	)
	code := exitOK

	root := &cobra.Command{
		Use:           "aws-sg-audit",
		Short:         "Find security groups that leave sensitive ports open to the world",
		Long:          "aws-sg-audit scans AWS security groups across regions and flags world-open\n(0.0.0.0/0 or ::/0) sensitive ports, noting whether each group is attached.",
		Example:       "  aws-sg-audit --regions us-east-1,eu-west-1 --format table\n  aws-sg-audit --regions us-east-1 --format sarif > sg.sarif",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			regionList := splitCSV(regions)
			if len(regionList) == 0 {
				return fmt.Errorf("--regions is required (comma-separated)")
			}
			pub, err := parsePorts(publicPorts)
			if err != nil {
				return err
			}

			sgs, err := scannerFactory(profile).Scan(context.Background(), regionList)
			if err != nil {
				return err
			}
			findings := audit.Audit(sgs, audit.Options{PublicPorts: pub, IgnoreTag: ignoreTag})

			switch format {
			case "table", "":
				report.Table(cmd.OutOrStdout(), findings)
			case "json":
				if err := report.JSON(cmd.OutOrStdout(), findings); err != nil {
					return err
				}
			case "sarif":
				if err := report.SARIF(cmd.OutOrStdout(), findings); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unknown --format %q (table|json|sarif)", format)
			}

			if exceedsThreshold(findings, failOn) {
				code = exitFindings
			}
			return nil
		},
	}

	root.Flags().StringVar(&regions, "regions", "", "comma-separated AWS regions to scan (required)")
	root.Flags().StringVar(&profile, "profile", "", "AWS shared-config profile")
	root.Flags().StringVarP(&format, "format", "f", "table", "output format: table, json, or sarif")
	root.Flags().StringVar(&publicPorts, "public-ports", "80,443", "comma-separated ports treated as intentionally public")
	root.Flags().StringVar(&ignoreTag, "ignore-tag", "sg-audit-ignore", "skip security groups carrying this tag key")
	root.Flags().StringVar(&failOn, "fail-on", "medium", "minimum severity that sets a non-zero exit (medium|high|critical|none)")

	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	if err := root.Execute(); err != nil {
		return exitError, err
	}
	return code, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePorts(s string) (map[int]bool, error) {
	out := map[int]bool{}
	for _, p := range splitCSV(s) {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q in --public-ports", p)
		}
		out[n] = true
	}
	return out, nil
}

var sevRank = map[string]int{"medium": 1, "high": 2, "critical": 3}

func exceedsThreshold(findings []audit.Finding, failOn string) bool {
	if failOn == "none" {
		return false
	}
	min := sevRank[failOn]
	if min == 0 {
		min = sevRank["medium"]
	}
	for _, f := range findings {
		if sevRank[f.Severity] >= min {
			return true
		}
	}
	return false
}
