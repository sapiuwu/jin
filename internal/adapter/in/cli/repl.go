package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/ergochat/readline"
)

// RunInteractive starts the interactive REPL. The user types existing
// commands (info, ports, tech-stack, or a bare URL), each is executed,
// and the prompt returns afterwards. The program exits on `exit`/`quit`,
// EOF (Ctrl+D), or Ctrl+C — which also aborts any in-flight scan.
func (a *App) RunInteractive() int {
	fmt.Fprint(a.out, a.renderBanner())

	// Ctrl+C cancels the base context, aborting in-flight scans, and is
	// what ultimately ends the REPL loop.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	a.baseCtx = ctx

	rl, err := a.newReadline()
	if err != nil {
		// e.g. stdin is not a terminal; fall back to plain line reading.
		return a.runPlainREPL(ctx)
	}
	defer rl.Close()

	a.printModeHint()

	for {
		if ctx.Err() != nil {
			break
		}
		line, err := rl.Readline()
		if err != nil {
			break // Ctrl+C (ErrInterrupt), Ctrl+D (EOF), or terminal error
		}
		if a.processLine(line) {
			return 0 // exit/quit
		}
	}

	fmt.Fprintln(a.out, "\n👋 Bye!")
	return 0
}

// processLine handles a single interactive command line. It returns true
// when the REPL should terminate (exit/quit).
func (a *App) processLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	switch line {
	case "exit", "quit":
		return true
	case "help":
		a.help()
		return false
	}
	a.execute(strings.Fields(line))
	return false
}

// runPlainREPL is a dependency-free fallback for when the readline
// instance cannot be created (non-interactive stdin, restricted
// terminals). It reads lines from stdin and exits on EOF or Ctrl+C.
func (a *App) runPlainREPL(ctx context.Context) int {
	a.printModeHint()

	lines := make(chan string)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			lines <- strings.TrimSpace(scanner.Text())
		}
	}()

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(a.out, "\n👋 Bye!")
			return 0
		case line, ok := <-lines:
			if !ok {
				fmt.Fprintln(a.out, "\n👋 Bye!")
				return 0
			}
			if a.processLine(line) {
				return 0
			}
		}
	}
}

// newReadline builds a readline instance with history and simple
// command completion, when the terminal allows it.
func (a *App) newReadline() (*readline.Instance, error) {
	return readline.NewEx(&readline.Config{
		Prompt:       a.prompt(),
		HistoryFile:  a.historyPath(),
		HistoryLimit: 500,
		AutoComplete: a.completer(),
	})
}

// prompt returns the interactive prompt, colored when enabled.
func (a *App) prompt() string {
	if a.color {
		return a.cyan("jin> ")
	}
	return "jin> "
}

// historyPath returns where command history is persisted. Empty when no
// home directory is available (history then stays in-memory).
func (a *App) historyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".jin_history")
}

// completer offers tab-completion for the known commands.
func (a *App) completer() readline.AutoCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("info"),
		readline.PcItem("ports"),
		readline.PcItem("tech-stack"),
		readline.PcItem("help"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)
}

// printModeHint announces the interactive mode on first start.
func (a *App) printModeHint() {
	fmt.Fprintln(a.out, a.white("Interactive mode — type a command (help for usage, exit/quit or Ctrl+C to quit)."))
}
