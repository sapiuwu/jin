# Jin Roadmap

Planned improvements and fixes for upcoming releases. Items are ordered by
priority within each phase; each phase can ship as an independent release.

## Phase 1 — Correctness fixes (v2.5.0) — SHIPPED

Bugs that produce wrong results today.

### P1: IPv6 / `host:port` target parsing

- [x] Add a single centralized target parser, `internal/hostutil`
  (`Split`/`Host`/`DialAddress`/`RootDomain`), and route every parsing
  site through it (replaces the 5 manual "cut at first colon" sites):
  - `internal/adapter/in/cli/args.go` — `cleanHost` (deleted; did not strip
    `:port` or brackets at all)
  - `internal/application/service/full_scan_service.go` (manual stripping
    deleted; target passed straight to the port use case)
  - `internal/application/service/techstack_service.go` — `rootDomain`
    (deleted; now `hostutil.RootDomain`)
  - `internal/adapter/out/scanner/tls_inspector.go` — `tlsHost` (now a
    one-liner over `hostutil.Host`)
  - `internal/adapter/out/scanner/http_server_scanner.go` —
    `extractRootDomain` (deleted; now `hostutil.RootDomain`)
- [x] **Fix false "closed" ports**: `jin ports -t example.com:8080` used
  to dial `example.com:8080:443` (`tcp_port_scanner.go:69`) and report
  every port closed. The target is now parsed once in
  `PortScanService.Scan` and dialed via `net.JoinHostPort`
  (`hostutil.DialAddress`).
- [x] Make IPv6 literal targets (`2001:db8::1`, `[::1]:8080`) dialable in
  `tcp_port_scanner.go`.
- [x] Port-selection precedence (was undefined): explicit `-p` list >
  port embedded in the target (validated 1–65535) > configured defaults.
- [x] Add the first unit tests of the project — table-driven tests in
  `internal/hostutil/hostutil_test.go` (`Split`, `Host`, `DialAddress`,
  `RootDomain` covering `[::1]`, `[::1]:8080`, `2001:db8::1`,
  `example.com:8080`, `example.com`, `https://example.com/path`,
  credentials, trailing dot, IP literals) plus
  `internal/application/service/port_scan_service_test.go` (host
  extraction, port precedence, error propagation) using a fake
  `out.PortScanner`.

## Phase 2 — NVD/crt.sh rate limiting & caching (v2.6.0)

Silent false-negatives in `tech-stack --cve` when NVD throttles.

- [ ] Token-bucket rate limiter for NVD (5 req/30s unauthenticated,
  50 req/30s with API key); no new dependencies (ticker-based).
- [ ] `NVD_API_KEY` support: config field in `internal/config/config.go`
  + `JIN_NVD_API_KEY` env, sent via the `apiKey` header (not query param).
- [ ] Retry with exponential backoff on 403/429; honor `Retry-After`
  (max 2 retries) in `nvd_cve_checker.go`.
- [ ] Two-layer cache for `nvd_cve_checker.go` and
  `ct_subdomain_enumerator.go`:
  - in-memory dedupe within a run (same tech+version queried once)
  - on-disk `~/.jin/cache/` with TTL (NVD 24h, crt.sh 6h)
- [ ] **Surface throttling instead of swallowing it**:
  `techstack_service.go:163` (`if err == nil && len(cves) > 0`) currently
  hides rate-limit errors — emit a visible warning such as
  `"NVD rate-limited, CVE results may be incomplete"`.
- [ ] crt.sh resilience: retry/backoff on 503 and timeouts in
  `ct_subdomain_enumerator.go`.
- [ ] Config knobs: cache TTL / cache dir / rate-limit overrides in
  `internal/config/config.go` (flag > env > file > default).

## Phase 3 — Complete SARIF output (v2.7.0)

- [ ] **Fix invalid stdout**: banner + status lines are printed before the
  SARIF document (`app.go:95`, `app.go:210`), so `jin info ... --format sarif`
  piped to a file is not valid JSON (see the broken `o_sarif.json` artifact
  in the repo root). Suppress banner/status for SARIF, or require `-o`.
- [ ] Add missing SARIF 2.1.0 elements in `present_sarif.go`:
  - `results[].locations[].physicalLocation.artifactLocation.uri`
    (required by GitHub code scanning to attach alerts)
  - `partialFingerprints` (prevents duplicate alerts every run)
  - `automationDetails.id` (category per command/run)
  - `tool.driver.informationUri`
  - rule `fullDescription`, `help`, `helpUri`, `properties.tags`
  - `invocations[].executionSuccessful`
- [ ] Passed checks → SARIF `kind: "pass"` instead of `level: "note"`.
- [ ] Dedupe `rules[]` when two checks share the same `Name`
  (`present_sarif.go:118` appends blindly).
- [ ] Extend SARIF beyond `info`/`headers`/`scan`:
  - `tech-stack --cve` → rule `jin/CVE-<id>`, `security-severity` from CVSS,
    `helpUri` → NVD URL
  - `ports` → rule `jin/open-port`, one result per open port
- [ ] Replace the broken `o_sarif.json` repo artifact with a valid fixture
  and validate against the SARIF 2.1.0 schema.

## Backlog (unprioritized)

- [ ] IPv6-aware scanning: add `ARecords`/`AAAARecords` to `domain.DNSInfo`
  (currently NS/MX/TXT only) via `resolver.LookupIPAddr`; dual-stack port
  scan with per-IP results (`PortInfo.IP`); `--ipv4-only` / `--ipv6-only`
  flags.
- [ ] Test coverage + CI workflow (unit tests exist for `hostutil` and the
  port-scan use case since v2.5.0; `.github/` currently only has
  `FUNDING.yml` — no build/test automation).
- [ ] `.gitignore` for stray output artifacts (`o_*.txt`, `o_sarif.json`).
- [ ] Public-suffix-aware root-domain extraction (see note on
  `hostutil.RootDomain` — `example.co.uk` is truncated to `co.uk`).
- [ ] Paginate NVD queries (`resultsPerPage=20`, no `startIndex`).

## Release mapping

| Version | Contents |
| --- | --- |
| v2.5.0 | Phase 1: IPv6 / `host:port` parsing fixes + first unit tests — **released** |
| v2.6.0 | Phase 2: NVD/crt.sh rate limiting, caching, error transparency |
| v2.7.0 | Phase 3: Complete, valid SARIF output |

Bug fixes within a phase may be released as patch versions (e.g. v2.5.1)
without waiting for the next phase.
