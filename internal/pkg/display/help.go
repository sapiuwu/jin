package display

import (
	"fmt"

	"github.com/fatih/color"
)

var (
	green = color.New(color.FgGreen).SprintFunc()
	cyan  = color.New(color.FgCyan).SprintFunc()
	white = color.New(color.FgWhite).SprintFunc()
)

// PrintHelp displays usage instructions for JIN
func PrintHelp() {
	fmt.Println(white("Usage:"))
	fmt.Println("  " + green("jin <url>                          ") + white("→ Full server reconnaissance"))
	fmt.Println("  " + green("jin [command] -t <target>          ") + white("→ Run specific module"))
	fmt.Println()
	fmt.Println(white("Available Commands:"))
	fmt.Println("  " + cyan("info") + white("        Full server reconnaissance (headers, TLS, security)"))
	fmt.Println("  " + cyan("ports") + white("      Scan for open ports (TCP connect scan)"))
	fmt.Println("  " + cyan("tech-stack") + white(" Fingerprint the technology stack (CMS, server, frameworks, JS libs, CDN)"))
	fmt.Println()
	fmt.Println(white("Flags:"))
	fmt.Println("  " + green("-j, --json") + white("        Output as JSON"))
	fmt.Println("  " + green("-s, --subdomains") + white("  Also discover subdomains + DNS records (tech-stack only)"))
	fmt.Println("  " + green("-h, --help") + white("        Show this help message"))
	fmt.Println()
	fmt.Println(white("Examples:"))
	fmt.Println("  jin https://example.com")
	fmt.Println("  jin ports -t example.com")
	fmt.Println("  jin tech-stack -t example.com")
	fmt.Println("  jin tech-stack -t example.com --subdomains")
	fmt.Println("  jin tech-stack -t example.com --subdomains --json")
}