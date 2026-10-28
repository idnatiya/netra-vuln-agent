// Command vuln-agent runs Trivy and keeps the results locally; with central_url
// set it also sends them to central.
package main

import (
	"os"

	"github.com/idnatiya/netra-vuln-agent/internal/delivery/cli"
)

// Set with -ldflags "-X main.version=... -X main.trivyVersion=..." (Makefile).
var (
	version      = "dev"
	trivyVersion = "0.72.0"
)

func main() { os.Exit(cli.Run(os.Args[1:], os.Stdin, version, trivyVersion)) }
