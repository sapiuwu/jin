package cli

import (
	"fmt"
	"strings"
)

// commands and flags exposed by shell completion scripts.
var (
	completionCommands = []string{
		"info", "ports", "tech-stack", "dns", "subdomains", "whois",
		"scan", "diff", "completions", "help", "exit", "quit",
	}
	completionFlags = []string{
		"-t", "--target", "-p", "--ports", "-j", "--json", "-s", "--subdomains",
		"--cve", "-o", "--output", "--min-grade", "--fail-on-low", "-h", "--help",
	}
)

// completionScript returns a shell completion script for the given shell
// ("bash", "zsh", or "fish"). An unknown shell yields an error.
func completionScript(shell string) (string, error) {
	cmds := strings.Join(completionCommands, " ")
	flags := strings.Join(completionFlags, " ")
	switch strings.ToLower(shell) {
	case "bash":
		return fmt.Sprintf(bashCompletion, cmds, flags), nil
	case "zsh":
		return fmt.Sprintf(zshCompletion, cmds, flags), nil
	case "fish":
		return fmt.Sprintf(fishCompletion, cmds, flags), nil
	default:
		return "", fmt.Errorf("unsupported shell %q (use bash, zsh, or fish)", shell)
	}
}

const bashCompletion = `# Jin shell completion for bash
_jin() {
  local cur opts
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  opts="%s %s"
  COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
  return 0
}
complete -F _jin jin
`

const zshCompletion = `# Jin shell completion for zsh
_jin() {
  local -a opts
  opts+=(%s %s)
  _describe 'jin' opts
}
compdef _jin jin
`

const fishCompletion = `# Jin shell completion for fish
complete -c jin -a '%s %s'
`
