package info

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aliftech/jin/internal/core"
	"github.com/aliftech/jin/internal/module/info/dto"
)

type CLIHandler struct {
	scanner core.ServerScanner
}

func NewCLIHandler(scanner core.ServerScanner) *CLIHandler {
	return &CLIHandler{scanner: scanner}
}

func (h *CLIHandler) HandleScan(url string, outputJSON bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	info, err := h.scanner.Scan(ctx, url)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if outputJSON {
		return h.printJSON(info)
	}
	return h.printHumanReadable(info)
}

func (h *CLIHandler) printJSON(info *core.ServerInfo) error {
	response := dto.FromDomain(info)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(response)
}

func (h *CLIHandler) printHumanReadable(info *core.ServerInfo) error {
	// Basic Info
	fmt.Printf("🌐 URL:          %s\n", info.URL)
	if info.RootDomain != "" && info.RootDomain != info.Domain {
		fmt.Printf("🗃️  Base Domain:  %s\n", info.RootDomain)
	}
	if info.CloudProvider != "" && info.CloudProvider != "Unknown" {
		fmt.Printf("☁️  Cloud:        %s\n", info.CloudProvider)
	}
	fmt.Printf("✅ Status:       %d\n", info.StatusCode)
	if info.Server != "" {
		fmt.Printf("🖥️  Server:      %s\n", info.Server)
	}
	if info.PoweredBy != "" {
		fmt.Printf("⚡ Powered By:   %s\n", info.PoweredBy)
	}
	fmt.Printf("📄 Content-Type: %s\n", info.ContentType)

	// TLS Info
	if info.TLSVersion != "" {
		fmt.Printf("🔒 TLS Version:  %s\n", info.TLSVersion)
		fmt.Printf("🔐 Cipher Suite: %s\n", info.TLSCipherSuite)
	}

	// Security Summary
	fmt.Println("\n🛡️  Security Insights:")
	hasIssues := false

	if info.HasCSP || info.HasCSPReportOnly {
		if len(info.CSPWarnings) > 0 {
			fmt.Println("  ⚠️ CSP Issues:")
			for _, w := range info.CSPWarnings {
				fmt.Printf("    • %s\n", w)
			}
			hasIssues = true
		} else {
			mode := "enforced"
			if info.HasCSPReportOnly && !info.HasCSP {
				mode = "report-only"
			}
			fmt.Printf("  ✅ CSP:          Policy %s\n", mode)
		}
	} else {
		fmt.Println("  ❌ CSP:          Not implemented")
		hasIssues = true
	}

	if len(info.CookieWarnings) > 0 {
		fmt.Println("  ⚠️ Cookie Issues:")
		for _, w := range info.CookieWarnings {
			fmt.Printf("    • %s\n", w)
		}
		hasIssues = true
	} else if info.HasHSTS {
		fmt.Println("  ✅ Cookies & HSTS: No obvious issues")
	}

	if !info.HasHSTS {
		fmt.Println("  ⚠️ HSTS:         Missing (no Strict-Transport-Security header)")
		hasIssues = true
	}

	if !info.HasXFrameOptions {
		fmt.Println("  ⚠️ X-Frame-Options: Missing (clickjacking protection not enforced)")
		hasIssues = true
	}

	if !hasIssues {
		fmt.Println("  ✅ No major security issues detected")
	}

	// Headers (collapsed if too many)
	fmt.Println("\n📋 Headers:")
	var headerKeys []string
	for k := range info.Headers {
		headerKeys = append(headerKeys, k)
	}
	// Optional: sort.Strings(headerKeys) for consistent output

	for _, key := range headerKeys {
		value := info.Headers[key]
		// Mask sensitive cookie values for readability (optional)
		if key == "Set-Cookie" {
			parts := strings.Split(value, ",")
			masked := make([]string, len(parts))
			for i, part := range parts {
				name := strings.SplitN(strings.TrimSpace(part), "=", 2)[0]
				masked[i] = name + "=<redacted>"
			}
			value = strings.Join(masked, ", ")
		}
		fmt.Printf("  %s: %s\n", key, value)
	}

	return nil
}
