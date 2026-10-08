package cli

import (
	"fmt"
	"strconv"
	"strings"
)

// parsedArgs is the result of interpreting raw CLI arguments.
type parsedArgs struct {
	json        bool
	subdomains  bool
	cve         bool
	failOnLow   bool
	help        bool
	output      string
	minGrade    string
	format      string
	interval    int
	customPorts []int
	positionals []string
}

// parseArgs interprets flags and collects the remaining positional
// arguments. Flags may appear anywhere; "-t/--target" and "-p/--ports"
// consume the following token as their value. "-o/--output" consumes the
// path for a JSON report.
func parseArgs(args []string) (parsedArgs, error) {
	var p parsedArgs

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--json", "-j":
			p.json = true
		case "--subdomains", "-s":
			p.subdomains = true
		case "--cve":
			p.cve = true
		case "--fail-on-low":
			p.failOnLow = true
		case "--help", "-h":
			p.help = true
		case "--format":
			if i+1 >= len(args) {
				return p, fmt.Errorf("flag %s requires a value", a)
			}
			i++
			p.format = strings.ToLower(args[i])
		case "--interval":
			if i+1 >= len(args) {
				return p, fmt.Errorf("flag %s requires a value", a)
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil {
				return p, fmt.Errorf("invalid --interval %q: %w", args[i], err)
			}
			p.interval = n
		case "-o", "--output":
			if i+1 >= len(args) {
				return p, fmt.Errorf("flag %s requires a value", a)
			}
			i++
			p.output = args[i]
		case "--min-grade":
			if i+1 >= len(args) {
				return p, fmt.Errorf("flag %s requires a value", a)
			}
			i++
			p.minGrade = args[i]
		case "-p", "--ports":
			if i+1 >= len(args) {
				return p, fmt.Errorf("flag %s requires a value", a)
			}
			i++
			ints, err := parsePortList(args[i])
			if err != nil {
				return p, fmt.Errorf("invalid %s value %q: %w", a, args[i], err)
			}
			p.customPorts = ints
		case "-t", "--target":
			if i+1 >= len(args) {
				return p, fmt.Errorf("flag %s requires a value", a)
			}
			i++
			p.positionals = append(p.positionals, args[i])
		case "--cache-dir", "--nvd-cache-ttl", "--ct-cache-ttl", "--nvd-rate-limit":
			// Startup config flags: their values are applied to the
			// configuration once in main (config.ApplyArgs) before the
			// adapters are built. They are only consumed here so they
			// never leak into the positionals as a bogus target.
			if i+1 >= len(args) {
				return p, fmt.Errorf("flag %s requires a value", a)
			}
			i++
		case "--no-cache":
			// Startup config flag; see the comment above.
		default:
			p.positionals = append(p.positionals, a)
		}
	}

	return p, nil
}

func parsePortList(raw string) ([]int, error) {
	var ports []int
	for _, part := range strings.Split(raw, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		ports = append(ports, n)
	}
	return ports, nil
}
