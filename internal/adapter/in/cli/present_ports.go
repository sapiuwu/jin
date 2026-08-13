package cli

import (
	"fmt"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/in"
)

// portScanResponse is the JSON shape for a port scan result.
type portScanResponse struct {
	OpenPorts []domain.PortInfo `json:"open_ports"`
}

func (a *App) renderPorts(res *in.PortScanResult, wantJSON bool) error {
	if wantJSON {
		return a.emitJSON(portScanResponse{OpenPorts: filterOpen(res.Results)})
	}

	fmt.Fprintln(a.out, "🔍 Open ports:")
	openFound := false
	for _, p := range res.Results {
		if p.Status == "open" {
			fmt.Fprintf(a.out, "  %d/%s\n", p.Port, p.Service)
			openFound = true
		}
	}
	if !openFound {
		fmt.Fprintln(a.out, "  No open ports found.")
	}
	return nil
}

func filterOpen(ports []domain.PortInfo) []domain.PortInfo {
	var open []domain.PortInfo
	for _, p := range ports {
		if p.Status == "open" {
			open = append(open, p)
		}
	}
	return open
}
