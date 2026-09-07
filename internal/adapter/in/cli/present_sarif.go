package cli

import (
	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/in"
	"github.com/aliftech/jin/internal/version"
)

// sarifDoc is a minimal SARIF 2.1.0 (Static Analysis Results Format)
// document. Emitting recon findings in SARIF lets Jin feed security gates
// into GitHub code scanning and other SARIF-consuming tooling.
type sarifDoc struct {
	Schema  string         `json:"$schema"`
	Version string         `json:"version"`
	Runs    []sarifRun     `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool        `json:"tool"`
	Results []sarifResult    `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	ShortDescription sarifText          `json:"shortDescription"`
	Properties       sarifRuleProps     `json:"properties"`
}

type sarifRuleProps struct {
	SecuritySeverity string `json:"security-severity"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string        `json:"ruleId"`
	Level     string        `json:"level"`
	Message   sarifText     `json:"message"`
	Properties sarifProps   `json:"properties"`
}

type sarifProps struct {
	Passed bool `json:"passed"`
}

// severityToScore maps Jin's qualitative severity to a SARIF
// security-severity score (0.0–10.0).
func severityToScore(sev string) string {
	switch sev {
	case domain.SeverityCritical:
		return "9.8"
	case domain.SeverityHigh:
		return "7.5"
	case domain.SeverityMedium:
		return "5.0"
	case domain.SeverityLow:
		return "3.0"
	default:
		return "5.0"
	}
}

func sarifLevel(c domain.CheckResult) string {
	if c.Passed {
		return "note"
	}
	switch c.Severity {
	case domain.SeverityCritical, domain.SeverityHigh:
		return "error"
	case domain.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// renderSARIF converts a server-info scan (its security report) into a SARIF
// document and writes it as JSON.
func (a *App) renderSARIF(res *in.ServerInfoResult) error {
	doc := buildSARIF(res)
	return a.emitJSON(doc)
}

func buildSARIF(res *in.ServerInfoResult) sarifDoc {
	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "jin",
						Version: version.Version,
					},
				},
			},
		},
	}

	if res == nil || res.Security == nil {
		return doc
	}

	run := &doc.Runs[0]
	for _, c := range res.Security.Checks {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID:               c.Name,
			ShortDescription: sarifText{Text: c.Name},
			Properties:       sarifRuleProps{SecuritySeverity: severityToScore(c.Severity)},
		})
		run.Results = append(run.Results, sarifResult{
			RuleID:    c.Name,
			Level:     sarifLevel(c),
			Message:   sarifText{Text: c.Detail},
			Properties: sarifProps{Passed: c.Passed},
		})
	}
	return doc
}
