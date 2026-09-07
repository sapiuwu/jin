package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/in"
)

// ---------------------------------------------------------------------------
// cookies
// ---------------------------------------------------------------------------

func (a *App) runCookies(target string, p parsedArgs) int {
	a.status("⏳", "Analyzing cookies for %s...", target)
	res, err := a.cookie.Analyze(a.baseCtx, target)
	if err != nil {
		if a.aborted() {
			fmt.Fprintln(a.out, "⏹️  Aborted")
			return 0
		}
		a.errorf("Error: %v", err)
		return 1
	}
	if a.format == "sarif" {
		a.errorf("SARIF output is only available for security-grade commands (info/headers/scan)")
		return 1
	}
	wantJSON := p.json || a.output != ""
	if wantJSON {
		if err := a.emitJSON(res.Analysis); err != nil {
			a.errorf("Error: %v", err)
			return 1
		}
		a.noteOutput()
		return 0
	}
	a.renderCookies(res)
	a.finish(false)
	return 0
}

// ---------------------------------------------------------------------------
// headers (security-headers focused view of a server-info scan)
// ---------------------------------------------------------------------------

func (a *App) runHeaders(target string, p parsedArgs) int {
	a.status("⏳", "Fetching response headers for %s...", target)
	res, err := a.info.Scan(a.baseCtx, target)
	if err != nil {
		if a.aborted() {
			fmt.Fprintln(a.out, "⏹️  Aborted")
			return 0
		}
		a.errorf("Error: %v", err)
		return 1
	}
	if a.format == "sarif" {
		if err := a.renderSARIF(res); err != nil {
			a.errorf("Error: %v", err)
			return 1
		}
		a.noteOutput()
		return a.applySecurityGate(res.Security, p)
	}
	wantJSON := p.json || a.output != ""
	if wantJSON {
		if err := a.emitJSON(buildInfoEnvelope(res)); err != nil {
			a.errorf("Error: %v", err)
			return 1
		}
		a.noteOutput()
		return 0
	}
	a.renderHeadersHuman(res)
	a.finish(false)
	return a.applySecurityGate(res.Security, p)
}

// ---------------------------------------------------------------------------
// tls
// ---------------------------------------------------------------------------

func (a *App) runTLS(target string, p parsedArgs) int {
	host := cleanHost(target)
	a.status("⏳", "Inspecting TLS configuration of %s...", host)
	res, err := a.tls.Inspect(a.baseCtx, host)
	if err != nil {
		if a.aborted() {
			fmt.Fprintln(a.out, "⏹️  Aborted")
			return 0
		}
		a.errorf("Error: %v", err)
		return 1
	}
	wantJSON := p.json || a.output != ""
	if wantJSON {
		if err := a.emitJSON(res.Report); err != nil {
			a.errorf("Error: %v", err)
			return 1
		}
		a.noteOutput()
		return 0
	}
	a.renderTLS(res)
	a.finish(false)
	return 0
}

// ---------------------------------------------------------------------------
// wayback
// ---------------------------------------------------------------------------

func (a *App) runWayback(target string, p parsedArgs) int {
	domain := cleanHost(target)
	a.status("⏳", "Discovering archived URLs for %s (Wayback Machine)...", domain)
	res, err := a.wayback.List(a.baseCtx, domain)
	if err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	wantJSON := p.json || a.output != ""
	if wantJSON {
		if err := a.emitJSON(res.Result); err != nil {
			a.errorf("Error: %v", err)
			return 1
		}
		a.noteOutput()
		return 0
	}
	a.renderWayback(res)
	a.finish(false)
	return 0
}

// ---------------------------------------------------------------------------
// exposed
// ---------------------------------------------------------------------------

func (a *App) runExposed(target string, p parsedArgs) int {
	a.status("⏳", "Probing %s for exposed files...", target)
	res, err := a.exposed.Check(a.baseCtx, target)
	if err != nil {
		if a.aborted() {
			fmt.Fprintln(a.out, "⏹️  Aborted")
			return 0
		}
		a.errorf("Error: %v", err)
		return 1
	}
	wantJSON := p.json || a.output != ""
	if wantJSON {
		if err := a.emitJSON(res.Result); err != nil {
			a.errorf("Error: %v", err)
			return 1
		}
		a.noteOutput()
		return 0
	}
	a.renderExposed(res)
	a.finish(false)
	return 0
}

// ---------------------------------------------------------------------------
// cdn
// ---------------------------------------------------------------------------

func (a *App) runCDN(target string, p parsedArgs) int {
	domain := cleanHost(target)
	a.status("⏳", "Analyzing CDN/origin exposure for %s...", domain)
	res, err := a.cdn.Detect(a.baseCtx, domain)
	if err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	wantJSON := p.json || a.output != ""
	if wantJSON {
		if err := a.emitJSON(res.Result); err != nil {
			a.errorf("Error: %v", err)
			return 1
		}
		a.noteOutput()
		return 0
	}
	a.renderCDN(res)
	a.finish(false)
	return 0
}

// ---------------------------------------------------------------------------
// watch (periodic rescan + auto-diff)
// ---------------------------------------------------------------------------

func (a *App) runWatch(target string, p parsedArgs) int {
	interval := p.interval
	if interval <= 0 {
		interval = 60
	}
	fmt.Fprintf(a.out, "%s Watching %s every %ds (Ctrl+C to stop)...\n", a.blue("⏳"), target, interval)

	var prev string
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	first := true
	for {
		select {
		case <-a.baseCtx.Done():
			fmt.Fprintln(a.out, "\n👋 Bye!")
			return 0
		case <-ticker.C:
		}

		res, err := a.info.Scan(a.baseCtx, target)
		if err != nil {
			a.errorf("scan error: %v", err)
			continue
		}
		cur, _ := json.Marshal(infoSnapshot(res))
		curStr := string(cur)

		if first {
			first = false
			prev = curStr
			fmt.Fprintf(a.out, "%s baseline captured\n", a.green("✓"))
			continue
		}

		if curStr != prev {
			fmt.Fprintf(a.out, "\n%s change detected at %s\n", a.yellow("~"), time.Now().Format(time.RFC3339))
			if report, err := a.diffStrings(prev, curStr); err == nil && report != "" {
				fmt.Fprintln(a.out, report)
			}
			prev = curStr
		} else {
			fmt.Fprintf(a.out, "%s no change (%s)\n", a.green("✓"), time.Now().Format("15:04:05"))
		}
	}
}

// infoSnapshot is the timestamp-free view of a server-info scan used for
// watch-mode diffing, so that only meaningful changes are reported.
func infoSnapshot(res *in.ServerInfoResult) any {
	env := buildInfoEnvelope(res)
	return struct {
		Data     any                    `json:"data"`
		Security *domain.SecurityReport `json:"security"`
	}{
		Data:     env.Data,
		Security: env.Security,
	}
}

// ---------------------------------------------------------------------------
// update (self-update / version check)
// ---------------------------------------------------------------------------

func (a *App) runUpdate(p parsedArgs) int {
	return a.runVersionCheck(p)
}
