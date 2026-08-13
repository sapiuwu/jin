package cli

import (
	"fmt"

	"github.com/aliftech/jin/internal/port/in"
)

type whoisReport struct {
	Info  *whoisInfo `json:"info,omitempty"`
	Error string     `json:"error,omitempty"`
}

type whoisInfo struct {
	Domain      string   `json:"domain"`
	Status      []string `json:"status,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	Registrar   string   `json:"registrar,omitempty"`
	CreatedDate string   `json:"created_date,omitempty"`
	UpdatedDate string   `json:"updated_date,omitempty"`
	ExpiresDate string   `json:"expires_date,omitempty"`
}

func (a *App) renderWhois(res *in.WhoisResult, wantJSON bool) error {
	if wantJSON {
		r := whoisReport{Error: res.Error}
		if res.Info != nil {
			r.Info = &whoisInfo{
				Domain:      res.Info.Domain,
				Status:      res.Info.Status,
				Nameservers: res.Info.Nameservers,
				Registrar:   res.Info.Registrar,
				CreatedDate: res.Info.CreatedDate,
				UpdatedDate: res.Info.UpdatedDate,
				ExpiresDate: res.Info.ExpiresDate,
			}
		}
		return a.emitJSON(r)
	}

	if res.Error != "" {
		fmt.Fprintf(a.out, "%s %s\n", a.red("✗"), res.Error)
		return nil
	}
	info := res.Info
	if info == nil {
		return nil
	}
	fmt.Fprintf(a.out, "📜 Registration data for %s:\n", info.Domain)
	if info.Registrar != "" {
		fmt.Fprintf(a.out, "  Registrar:   %s\n", info.Registrar)
	}
	if info.CreatedDate != "" {
		fmt.Fprintf(a.out, "  Created:     %s\n", info.CreatedDate)
	}
	if info.UpdatedDate != "" {
		fmt.Fprintf(a.out, "  Updated:     %s\n", info.UpdatedDate)
	}
	if info.ExpiresDate != "" {
		fmt.Fprintf(a.out, "  Expires:     %s\n", info.ExpiresDate)
	}
	if len(info.Status) > 0 {
		fmt.Fprintf(a.out, "  Status:      %v\n", info.Status)
	}
	if len(info.Nameservers) > 0 {
		fmt.Fprintf(a.out, "  Nameservers: %v\n", info.Nameservers)
	}
	return nil
}
