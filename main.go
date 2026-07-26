package main

import (
	"fmt"
	"os"

	"github.com/moveeeax/aws-sg-audit/cmd"
)

func main() {
	code, err := cmd.Run(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "aws-sg-audit:", err)
	}
	os.Exit(code)
}
