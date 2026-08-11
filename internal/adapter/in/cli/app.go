// Package cli implements the primary (driving) adapter of the application.
// It parses command-line input, invokes the use cases through the driving
// ports, and renders the results. It contains no business logic — every
// decision is delegated to the application layer.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aliftech/jin/internal/port/in"
)

// App is the CLI entry point, wired to the application's driving ports.
type App struct {
	info      in.ServerInfoService
	ports     in.PortScanService
	techstack in.TechStackService
	out       io.Writer
	color     bool
	baseCtx   context.Context // canceled by Ctrl+C in interactive mode
}

// Option configures an App.
type Option func(*App)

// WithWriter overrides the output destination (default: os.Stdout).
func WithWriter(w io.Writer) Option { return func(a *App) { a.out = w } }

// WithColor toggles ANSI color output (default: auto, off if NO_COLOR is set).
func WithColor(enabled bool) Option { return func(a *App) { a.color = enabled } }

// NewApp builds the CLI adapter around the given driving ports.
func NewApp(info in.ServerInfoService, ports in.PortScanService, techstack in.TechStackService, opts ...Option) *App {
	a := &App{
		info:      info,
		ports:     ports,
		techstack: techstack,
		out:       os.Stdout,
		color:     os.Getenv("NO_COLOR") == "",
		baseCtx:   context.Background(),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Run executes a one-shot command line and returns an exit code. It is
// used for direct invocations such as `jin ports -t example.com`.
func (a *App) Run(args []string) int {
	fmt.Fprint(a.out, a.renderBanner())
	return a.execute(args)
}

// execute parses and dispatches a single command invocation. It is shared
// by the one-shot entry point and the interactive REPL, which is why it
// never prints the banner itself.
func (a *App) execute(args []string) int {
	p, err := parseArgs(args)
	if err != nil {
		a.errorf("Invalid usage: %v", err)
		a.help()
		return 1
	}
	if p.help {
		a.help()
		return 0
	}
	if len(p.positionals) == 0 {
		a.errorf("No target provided")
		a.help()
		return 1
	}
	if strings.HasPrefix(p.positionals[0], "-") {
		a.errorf("Unknown flag: %s", p.positionals[0])
		a.help()
		return 1
	}

	// Direct URL: jin https://example.com [--json]
	if len(p.positionals) == 1 {
		return a.runInfo(p.positionals[0], p.json)
	}

	// Commands: jin <command> -t <target> [flags]
	switch command := strings.ToLower(p.positionals[0]); command {
	case "info":
		return a.runInfo(p.positionals[1], p.json)
	case "ports":
		return a.runPorts(p.positionals[1], p.json, p.customPorts)
	case "tech-stack":
		return a.runTechStack(p.positionals[1], p.json, p.subdomains)
	default:
		a.errorf("Unknown command: %s", command)
		a.help()
		return 1
	}
}

// ---------------------------------------------------------------------------
// Command runners
// ---------------------------------------------------------------------------

func (a *App) runInfo(target string, outputJSON bool) int {
	a.status("⏳", "Fetching full server info for %s...", target)
	res, err := a.info.Scan(a.baseCtx, target)
	if err != nil {
		if a.aborted() {
			fmt.Fprintln(a.out, "⏹️  Aborted")
			return 0
		}
		a.errorf("Error: %v", err)
		return 1
	}
	if err := a.renderInfo(res, outputJSON); err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	a.finish(outputJSON)
	return 0
}

func (a *App) runPorts(target string, outputJSON bool, customPorts []int) int {
	host := cleanHost(target)
	a.status("⏳", "Scanning open ports on %s...", host)
	res, err := a.ports.Scan(a.baseCtx, host, customPorts)
	if err != nil {
		if a.aborted() {
			fmt.Fprintln(a.out, "⏹️  Aborted")
			return 0
		}
		a.errorf("Error: %v", err)
		return 1
	}
	if err := a.renderPorts(res, outputJSON); err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	a.finish(outputJSON)
	return 0
}

func (a *App) runTechStack(target string, outputJSON, deep bool) int {
	if deep {
		a.status("⏳", "Detecting tech stack for %s (including subdomains + DNS)...", target)
	} else {
		a.status("⏳", "Detecting tech stack for %s...", target)
	}
	res, err := a.techstack.Scan(a.baseCtx, target, deep)
	if err != nil {
		if a.aborted() {
			fmt.Fprintln(a.out, "⏹️  Aborted")
			return 0
		}
		a.errorf("Error: %v", err)
		return 1
	}
	if err := a.renderTechStack(res, outputJSON); err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	a.finish(outputJSON)
	return 0
}

// aborted reports whether the base context was canceled (e.g. by Ctrl+C
// in interactive mode), in which case a scan error is expected.
func (a *App) aborted() bool {
	return a.baseCtx != nil && a.baseCtx.Err() != nil
}

// finish prints a short completion marker after human-readable output.
// Skipped for JSON output so piped/parsed output stays clean.
func (a *App) finish(outputJSON bool) {
	if outputJSON {
		return
	}
	fmt.Fprintf(a.out, "%s Done\n", a.green("✓"))
}

// ---------------------------------------------------------------------------
// Output & color helpers
// ---------------------------------------------------------------------------

func (a *App) paint(code int, s string) string {
	if !a.color {
		return s
	}
	return fmt.Sprintf("\033[%dm%s\033[0m", code, s)
}

func (a *App) red(s string) string    { return a.paint(31, s) }
func (a *App) green(s string) string  { return a.paint(32, s) }
func (a *App) yellow(s string) string { return a.paint(33, s) }
func (a *App) blue(s string) string   { return a.paint(34, s) }
func (a *App) cyan(s string) string   { return a.paint(36, s) }
func (a *App) white(s string) string  { return a.paint(37, s) }

func (a *App) status(icon, format string, v ...any) {
	fmt.Fprintf(a.out, "%s %s\n", a.blue(icon), fmt.Sprintf(format, v...))
}

func (a *App) errorf(format string, v ...any) {
	fmt.Fprintf(a.out, "%s %s\n", a.red("✗"), fmt.Sprintf(format, v...))
}
