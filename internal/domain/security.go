package domain

// Severity levels for security checks.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// CheckResult is a single weighted security finding derived from a scan.
type CheckResult struct {
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
	Weight   int    `json:"weight"`
}

// SecurityReport aggregates the weighted checks into a 0-100 score and a
// letter grade.
type SecurityReport struct {
	Score  int           `json:"score"`
	Grade  string        `json:"grade"`
	Checks []CheckResult `json:"checks"`
}
