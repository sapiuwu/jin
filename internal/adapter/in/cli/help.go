package cli

import "fmt"

// help prints usage instructions for JIN.
func (a *App) help() {
	fmt.Fprintln(a.out, a.white("Usage:"))
	fmt.Fprintln(a.out, "  "+a.green("jin                                   ")+a.white("→ Interactive mode (type commands, Ctrl+C to quit)"))
	fmt.Fprintln(a.out, "  "+a.green("jin <url>                          ")+a.white("→ Full server reconnaissance"))
	fmt.Fprintln(a.out, "  "+a.green("jin [command] -t <target>          ")+a.white("→ Run specific module"))
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, a.white("Available Commands:"))
	fmt.Fprintln(a.out, "  "+a.cyan("info")+a.white("        Full server reconnaissance (headers, TLS, security grade)"))
	fmt.Fprintln(a.out, "  "+a.cyan("ports")+a.white("      Scan for open ports (TCP connect scan)"))
	fmt.Fprintln(a.out, "  "+a.cyan("tech-stack")+a.white(" Fingerprint the technology stack (CMS, server, frameworks, JS libs, CDN)"))
	fmt.Fprintln(a.out, "  "+a.cyan("dns")+a.white("         Resolve DNS records (nameservers, MX, TXT)"))
	fmt.Fprintln(a.out, "  "+a.cyan("subdomains")+a.white("  Enumerate subdomains via certificate transparency"))
	fmt.Fprintln(a.out, "  "+a.cyan("whois")+a.white("       Registration data (RDAP) for a domain"))
	fmt.Fprintln(a.out, "  "+a.cyan("scan")+a.white("        Combined info + ports + tech-stack report"))
	fmt.Fprintln(a.out, "  "+a.cyan("diff")+a.white("        Compare two saved JSON reports (jin diff a.json b.json)"))
	fmt.Fprintln(a.out, "  "+a.cyan("completions")+a.white(" Generate shell completions (bash|zsh|fish)"))

	fmt.Fprintln(a.out, a.white("Flags:"))
	fmt.Fprintln(a.out, "  "+a.green("-j, --json")+a.white("            Output as JSON"))
	fmt.Fprintln(a.out, "  "+a.green("-o, --output <file>")+a.white("     Write JSON report to a file"))
	fmt.Fprintln(a.out, "  "+a.green("-s, --subdomains")+a.white("    Also discover subdomains + DNS (tech-stack/scan)"))
	fmt.Fprintln(a.out, "  "+a.green("--cve")+a.white("               Cross-reference detected versions against NVD advisories"))
	fmt.Fprintln(a.out, "  "+a.green("-p, --ports <list>")+a.white("     Custom ports to scan (ports only, comma-separated)"))
	fmt.Fprintln(a.out, "  "+a.green("--min-grade <grade>")+a.white("  CI gate: fail if security grade is below this (info/scan)"))
	fmt.Fprintln(a.out, "  "+a.green("--fail-on-low")+a.white("        CI gate: fail if security grade is below C"))
	fmt.Fprintln(a.out, "  "+a.green("-h, --help")+a.white("            Show this help message"))

	fmt.Fprintln(a.out, a.white("Examples:"))
	fmt.Fprintln(a.out, "  jin")
	fmt.Fprintln(a.out, "  jin https://example.com")
	fmt.Fprintln(a.out, "  jin ports -t example.com -p 80,443")
	fmt.Fprintln(a.out, "  jin tech-stack -t example.com --subdomains --cve --json -o report.json")
	fmt.Fprintln(a.out, "  jin dns -t example.com")
	fmt.Fprintln(a.out, "  jin whois -t example.com")
	fmt.Fprintln(a.out, "  jin scan -t example.com -o scan.json")
	fmt.Fprintln(a.out, "  jin info -t example.com --min-grade B  # CI security gate")
	fmt.Fprintln(a.out, "  jin diff before.json after.json")
}
