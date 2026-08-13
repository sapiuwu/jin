package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/in"
)

type fullScanReport struct {
	Target     string             `json:"target"`
	Info       *infoEnvelope      `json:"info,omitempty"`
	Ports      []domain.PortInfo  `json:"ports,omitempty"`
	TechStack  *techStackEnvelope `json:"tech_stack,omitempty"`
	ScannedAt  time.Time          `json:"scanned_at"`
	DurationMs int64              `json:"duration_ms"`
}

func (a *App) renderScan(res *in.FullScanResult, wantJSON bool) error {
	if wantJSON {
		r := fullScanReport{
			Target:     res.Target,
			ScannedAt:  time.Now(),
			DurationMs: res.Duration.Milliseconds(),
		}
		if res.Info != nil {
			e := buildInfoEnvelope(res.Info)
			r.Info = &e
		}
		if res.Ports != nil {
			r.Ports = filterOpen(res.Ports.Results)
		}
		if res.TechStack != nil {
			e := buildTechStackEnvelope(res.TechStack)
			r.TechStack = &e
		}
		return a.emitJSON(r)
	}

	if res.Info != nil {
		_ = a.renderInfo(res.Info, false)
	}
	if res.Ports != nil {
		_ = a.renderPorts(res.Ports, false)
	}
	if res.TechStack != nil {
		_ = a.renderTechStack(res.TechStack, false)
	}
	return nil
}

// diffReports loads two saved JSON reports and returns a human-readable
// description of what changed between them (added, removed, changed leaves).
func (a *App) diffReports(fileA, fileB string) (string, error) {
	fa, err := loadFlat(fileA)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", fileA, err)
	}
	fb, err := loadFlat(fileB)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", fileB, err)
	}

	var lines []string
	keys := make(map[string]bool)
	for k := range fa {
		keys[k] = true
	}
	for k := range fb {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	for _, k := range sorted {
		va, oka := fa[k]
		vb, okb := fb[k]
		switch {
		case oka && !okb:
			lines = append(lines, fmt.Sprintf("%s %s = %s", a.red("-"), k, va))
		case !oka && okb:
			lines = append(lines, fmt.Sprintf("%s %s = %s", a.green("+"), k, vb))
		case oka && okb && va != vb:
			lines = append(lines, fmt.Sprintf("%s %s: %s → %s", a.yellow("~"), k, va, vb))
		}
	}
	return joinLines(lines), nil
}

func loadFlat(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var top any
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, err
	}
	out := map[string]string{}
	flatten("", top, out)
	return out, nil
}

func flatten(prefix string, v any, out map[string]string) {
	switch val := v.(type) {
	case map[string]any:
		for k, item := range val {
			flatten(joinPath(prefix, k), item, out)
		}
	case []any:
		for i, item := range val {
			flatten(fmt.Sprintf("%s[%d]", prefix, i), item, out)
		}
	default:
		out[prefix] = fmt.Sprintf("%v", val)
	}
}

func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n"
		}
		out += l
	}
	return out
}
