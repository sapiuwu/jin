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
	fmt.Fprintln(a.out, "  "+a.cyan("info")+a.white("        Full server reconnaissance (headers, TLS, security)"))
	fmt.Fprintln(a.out, "  "+a.cyan("ports")+a.white("      Scan for open ports (TCP connect scan)"))
	fmt.Fprintln(a.out, "  "+a.cyan("tech-stack")+a.white(" Fingerprint the technology stack (CMS, server, frameworks, JS libs, CDN)"))
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, a.white("Flags:"))
	fmt.Fprintln(a.out, "  "+a.green("-j, --json")+a.white("        Output as JSON"))
	fmt.Fprintln(a.out, "  "+a.green("-s, --subdomains")+a.white("  Also discover subdomains + DNS records (tech-stack only)"))
	fmt.Fprintln(a.out, "  "+a.green("-p, --ports <list>")+a.white("   Custom ports to scan (ports only, comma-separated)"))
	fmt.Fprintln(a.out, "  "+a.green("-h, --help")+a.white("        Show this help message"))
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, a.white("Examples:"))
	fmt.Fprintln(a.out, "  jin")
	fmt.Fprintln(a.out, "  jin https://example.com")
	fmt.Fprintln(a.out, "  jin ports -t example.com")
	fmt.Fprintln(a.out, "  jin ports -t example.com -p 80,443")
	fmt.Fprintln(a.out, "  jin tech-stack -t example.com")
	fmt.Fprintln(a.out, "  jin tech-stack -t example.com --subdomains")
	fmt.Fprintln(a.out, "  jin tech-stack -t example.com --subdomains --json")
}
