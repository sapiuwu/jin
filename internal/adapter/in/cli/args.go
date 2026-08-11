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
	help        bool
	customPorts []int
	positionals []string
}

// parseArgs interprets flags and collects the remaining positional
// arguments. Flags may appear anywhere; "-t/--target" and "-p/--ports"
// consume the following token as their value.
func parseArgs(args []string) (parsedArgs, error) {
	var p parsedArgs

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--json", "-j":
			p.json = true
		case "--subdomains", "-s":
			p.subdomains = true
		case "--help", "-h":
			p.help = true
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

// cleanHost strips any scheme and path from a target, leaving a bare
// hostname suitable for a port scan.
func cleanHost(input string) string {
	host := strings.TrimPrefix(input, "https://")
	host = strings.TrimPrefix(host, "http://")
	if i := strings.Index(host, "/"); i != -1 {
		host = host[:i]
	}
	return host
}
