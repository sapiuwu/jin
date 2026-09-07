package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/out"
)

// RDAPWhoisProvider is an out.WhoisProvider adapter backed by RDAP
// (Registration Data Access Protocol). It uses the public redirector at
// rdap.org, which needs no API key and is fully passive.
type RDAPWhoisProvider struct {
	client *http.Client
}

// NewRDAPWhoisProvider builds the adapter, routed through an optional
// upstream proxy ("" for a direct connection).
func NewRDAPWhoisProvider(timeout time.Duration, proxy string) out.WhoisProvider {
	return &RDAPWhoisProvider{client: newHTTPClient(timeout, proxy)}
}

type rdapResponse struct {
	LDHName     string       `json:"ldhName"`
	Status      []string     `json:"status"`
	Nameservers []rdapNS     `json:"nameservers"`
	Events      []rdapEvent  `json:"events"`
	Entities    []rdapEntity `json:"entities"`
}

type rdapNS struct {
	LDHName string `json:"ldhName"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapEntity struct {
	Roles      []string `json:"roles"`
	VCardArray []any    `json:"vcardArray"`
}

// Lookup implements out.WhoisProvider.
func (p *RDAPWhoisProvider) Lookup(ctx context.Context, domainName string) (*domain.WhoisInfo, error) {
	host := strings.ToLower(strings.TrimSpace(domainName))
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if i := strings.Index(host, "/"); i != -1 {
		host = host[:i]
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://rdap.org/domain/"+host, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rdap returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var r rdapResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}

	info := &domain.WhoisInfo{
		Domain:      strings.ToLower(r.LDHName),
		Status:      r.Status,
		Registrar:   extractRegistrar(r.Entities),
		CreatedDate: eventDate(r.Events, "registration"),
		UpdatedDate: eventDate(r.Events, "last changed"),
		ExpiresDate: eventDate(r.Events, "expiration"),
	}
	for _, ns := range r.Nameservers {
		if ns.LDHName != "" {
			info.Nameservers = append(info.Nameservers, strings.ToLower(ns.LDHName))
		}
	}
	return info, nil
}

func eventDate(events []rdapEvent, action string) string {
	for _, e := range events {
		if strings.EqualFold(e.Action, action) {
			return e.Date
		}
	}
	return ""
}

// extractRegistrar walks the vcardArray (["vcard", [ [name,params,type,value], ... ]])
// of any entity with the "registrar" role and returns its organisation name.
func extractRegistrar(entities []rdapEntity) string {
	for _, e := range entities {
		isRegistrar := false
		for _, role := range e.Roles {
			if strings.EqualFold(role, "registrar") {
				isRegistrar = true
				break
			}
		}
		if !isRegistrar || len(e.VCardArray) < 2 {
			continue
		}
		items, ok := e.VCardArray[1].([]any)
		if !ok {
			continue
		}
		for _, item := range items {
			field, ok := item.([]any)
			if !ok || len(field) < 4 {
				continue
			}
			name, _ := field[0].(string)
			if strings.EqualFold(name, "org") {
				if v, ok := field[3].(string); ok {
					return v
				}
			}
		}
	}
	return ""
}
