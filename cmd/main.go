// cmd/main.go
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/aliftech/jin/internal/bootstrap"
	"github.com/aliftech/jin/internal/pkg/display"
	"github.com/fatih/color"
)

var (
	red   = color.New(color.FgRed).SprintFunc()
	green = color.New(color.FgGreen).SprintFunc()
	blue  = color.New(color.FgBlue).SprintFunc()
	cyan  = color.New(color.FgCyan).SprintFunc()
)

func main() {
	fmt.Print(cyan(display.BANNER))
	args := os.Args[1:]

	jsonOutput := extractBoolFlag(&args, "--json", "-j")
	deepScan := extractBoolFlag(&args, "--subdomains", "-s")

	if len(args) == 0 {
		fmt.Printf("%s No target provided\n", red("✗"))
		display.PrintHelp()
		os.Exit(1)
	}

	if args[0] == "-h" || args[0] == "--help" {
		display.PrintHelp()
		return
	}

	// Handle direct URL: jin https://example.com [--json]
	if len(args) == 1 && !strings.HasPrefix(args[0], "-") {
		runInfo(args[0], jsonOutput)
		return
	}

	// Handle commands: jin <command> -t <url> [--json]
	command := strings.ToLower(args[0])
	target, ok := extractTarget(args[1:])
	if !ok {
		fmt.Printf("%s Invalid usage\n", red("✗"))
		display.PrintHelp()
		os.Exit(1)
	}

	switch command {
	case "info":
		runInfo(target, jsonOutput)
	case "ports":
		runPorts(target, jsonOutput)
	case "tech-stack":
		runTechStack(target, jsonOutput, deepScan)
	default:
		fmt.Printf("%s Unknown command: %s\n", red("✗"), command)
		display.PrintHelp()
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

func runInfo(url string, jsonOutput bool) {
	fmt.Printf("%s Fetching full server info for %s...\n", blue("⏳"), url)
	handler := bootstrap.NewCLIHandler()
	if err := handler.HandleScan(url, jsonOutput); err != nil {
		fmt.Printf("%s Error: %v\n", red("✗"), err)
		os.Exit(1)
	}
	printDone(jsonOutput)
}

func runPorts(target string, jsonOutput bool) {
	host := cleanHost(target)
	fmt.Printf("%s Scanning open ports on %s...\n", blue("⏳"), host)
	handler := bootstrap.NewPortScanHandler()
	if err := handler.HandleScan(host, jsonOutput, nil); err != nil {
		fmt.Printf("%s Error: %v\n", red("✗"), err)
		os.Exit(1)
	}
	printDone(jsonOutput)
}

func runTechStack(target string, jsonOutput bool, deep bool) {
	if deep {
		fmt.Printf("%s Detecting tech stack for %s (including subdomains + DNS)...\n", blue("⏳"), target)
	} else {
		fmt.Printf("%s Detecting tech stack for %s...\n", blue("⏳"), target)
	}
	handler := bootstrap.NewTechStackHandler()
	if err := handler.HandleScan(target, jsonOutput, deep); err != nil {
		fmt.Printf("%s Error: %v\n", red("✗"), err)
		os.Exit(1)
	}
	printDone(jsonOutput)
}

// printDone prints a short completion marker after human-readable output.
// Skipped for JSON output so piped/parsed output stays clean.
func printDone(jsonOutput bool) {
	if jsonOutput {
		return
	}
	fmt.Printf("%s Done\n", green("✓"))
}

// ---------------------------------------------------------------------------
// Arg parsing helpers
// ---------------------------------------------------------------------------

// extractBoolFlag removes the first occurrence of any of the given flag
// names from args (in place) and reports whether it was present.
func extractBoolFlag(args *[]string, names ...string) bool {
	found := false
	filtered := (*args)[:0:0]
	for _, a := range *args {
		matched := false
		for _, n := range names {
			if a == n {
				matched = true
				break
			}
		}
		if matched {
			found = true
			continue
		}
		filtered = append(filtered, a)
	}
	*args = filtered
	return found
}

// extractTarget looks for "-t <value>" anywhere in args and returns the
// value. Falls back to the first non-flag argument if "-t" isn't present,
// so `jin tech-stack example.com` works alongside `jin tech-stack -t example.com`.
func extractTarget(args []string) (string, bool) {
	for i, a := range args {
		if a == "-t" && i+1 < len(args) {
			return args[i+1], true
		}
	}
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a, true
		}
	}
	return "", false
}

func cleanHost(input string) string {
	host := strings.TrimPrefix(input, "https://")
	host = strings.TrimPrefix(host, "http://")
	if i := strings.Index(host, "/"); i != -1 {
		host = host[:i]
	}
	return host
}