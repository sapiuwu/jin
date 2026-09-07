package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aliftech/jin/internal/version"
)

// releaseAPI is the GitHub REST endpoint for the latest published release.
const releaseAPI = "https://api.github.com/repos/aliftech/jin/releases/latest"

type githubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Name    string `json:"name"`
}

// runVersionCheck compares the running binary's version against the latest
// GitHub release and reports whether an update is available. It is best-
// effort: network failures simply fall back to reporting the local version.
func (a *App) runVersionCheck(p parsedArgs) int {
	fmt.Fprintf(a.out, "🔎 Jin version: %s\n", version.Version)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releaseAPI, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "jin/"+version.Version)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.errorf("could not reach update server: %v", err)
		return 0
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.errorf("update server returned status %d", resp.StatusCode)
		return 0
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		a.errorf("failed to read update response: %v", err)
		return 0
	}
	var rel githubRelease
	if err := json.Unmarshal(body, &rel); err != nil || rel.TagName == "" {
		a.errorf("could not parse update response")
		return 0
	}

	cmp := compareVersion(version.Version, strings.TrimPrefix(rel.TagName, "v"))
	switch {
	case cmp < 0:
		fmt.Fprintf(a.out, "%s Update available: %s → %s\n", a.yellow("⚠️"), version.Version, rel.TagName)
		fmt.Fprintf(a.out, "  Release notes: %s\n", rel.HTMLURL)
		fmt.Fprintf(a.out, "  Upgrade:  brew upgrade jin   |   docker pull wahyouka/jin:%s\n", rel.TagName)
	case cmp > 0:
		fmt.Fprintf(a.out, "%s You are running a newer build (%s) than the latest release (%s).\n", a.green("✓"), version.Version, rel.TagName)
	default:
		fmt.Fprintf(a.out, "%s You are on the latest version (%s).\n", a.green("✓"), version.Version)
	}
	return 0
}

// compareVersion compares two dot-separated semantic versions, returning -1,
// 0, or 1.
func compareVersion(a, b string) int {
	pa := splitVersion(a)
	pb := splitVersion(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var va, vb int
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va != vb {
			if va < vb {
				return -1
			}
			return 1
		}
	}
	return 0
}

func splitVersion(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			out = append(out, 0)
			continue
		}
		out = append(out, n)
	}
	return out
}
