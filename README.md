# Jin: Your Passive OSINT & Recon CLI Toolkit

[![Sponsor sapiuwu](https://img.shields.io/badge/Sponsor-sapiuwu-pink?logo=github)](https://github.com/sponsors/sapiuwu)

<img src="./public/jin-demo.gif">

**Version: 2.4.1**

Jin is an open-source command-line interface (CLI) toolkit for OSINT (Open-Source Intelligence) and reconnaissance. It gathers server, network, and technology-stack information about a target using passive, safe techniques — no active exploitation. This tool is intended for ethical and educational use only—please refrain from using it for harmful actions.

## Overview

Jin provides a suite of commands to assist with network reconnaissance, domain analysis, and vulnerability assessment. Built with Go, it is lightweight, portable, and containerizable with Docker, making it accessible for security researchers, students, and enthusiasts.

## Commands

- **info**: Full server reconnaissance — response headers, TLS version, and a weighted **security grade** (0–100, A+→F). Ideal for quick posture checks.
- **ports**: Scan for open ports using a TCP connect scan (custom port lists supported).
- **tech-stack**: Fingerprint the technology stack (CMS, server, frameworks, JS libraries, CDN) with confidence levels and evidence. Add `--subdomains` for passive subdomain + DNS discovery, and `--cve` to cross-reference detected versions against the NVD.
- **dns**: Resolve a domain's DNS records (nameservers, MX, TXT).
- **subdomains**: Enumerate subdomains passively via certificate transparency logs (crt.sh).
- **whois**: Registration data (RDAP) for a domain — registrar, creation/expiry, nameservers.
- **scan**: One combined report covering `info` + `ports` + `tech-stack` (accepts the same flags).
- **diff**: Compare two saved JSON reports and print what changed.
- **completions**: Emit a shell completion script (`bash`, `zsh`, or `fish`).

## Shared flags

| Flag | Description |
| --- | --- |
| `-t, --target <host>` | Target URL or host (most commands). |
| `-j, --json` | Output as JSON (for piping/automation). |
| `-o, --output <file>` | Write the JSON report to a file instead of stdout. |
| `-p, --ports <list>` | Custom ports for the `ports`/`scan` commands (comma-separated). |
| `-s, --subdomains` | Include subdomain + DNS discovery (`tech-stack`/`scan`). |
| `--cve` | Cross-reference detected versions against NVD advisories (`tech-stack`/`scan`). |
| `--min-grade <grade>` | CI gate: exit non-zero if the security grade is below this (e.g. `B`). |
| `--fail-on-low` | CI gate: exit non-zero if the security grade is below `C`. |

## Installation

### Homebrew (recommended)

```sh
brew tap sapiuwu/jin
brew install jin
```

### Prerequisites

- [Homebrew](https://brew.sh) (for the tap above)
- Go 1.25 or higher (to build from source)
- Docker (optional, for containerized usage)

### From Source

1. Clone the repository:

   ```
   git clone https://github.com/sapiuwu/jin.git
   ```

2. Navigate to the project directory:

   ```
   cd jin
   ```

3. Build the binary:

   ```
   go build -o jin ./cmd/
   ```

4. Run the CLI:
   ```
   ./jin
   ```

### Using Docker

1. Pull an image from Docker Hub (built per base image, e.g. `alpine-latest`, `debian-bookworm`, `ubuntu-24.04`):

   ```
    docker pull wahyouka/jin:v2.4.1-alpine-latest
   ```

2. **Interactive mode (REPL — recommended).** Running with no command
   enters the REPL: the prompt returns after each command so you can keep
   investigating. Always add `--rm` so the container is automatically removed
   when you quit (`exit`/`quit` or `Ctrl+C`) — this prevents leftover
   ("sampah") containers piling up:

   ```
   docker run -it --rm wahyouka/jin:v2.4.1-alpine-latest
   ```

   Inside the REPL you can type commands or a bare URL, e.g.:

   ```
   jin> https://example.com
   jin> ports -t example.com -p 80,443
   jin> dns -t example.com
   jin> exit
   ```

3. **One-shot command.** Pass the command directly; the program runs once
   and exits. Add `--rm` to clean up the container automatically:

   ```
   docker run -it --rm wahyouka/jin:v2.4.1-alpine-latest ports -t example.com
   docker run -it --rm wahyouka/jin:v2.4.1-alpine-latest dns -t example.com
   docker run -it --rm wahyouka/jin:v2.4.1-alpine-latest subdomains -t example.com
   ```

4. **Reuse a single container (no `--rm`).** `docker run` always creates a
   new container, so if you prefer one persistent container, give it a name
   and reconnect or run commands into it:

   ```
   docker run -it --name jin-session wahyouka/jin:v2.4.1-alpine-latest   # then quit
   docker start -ai jin-session                                          # reconnect to REPL
   docker exec -it jin-session ports -t example.com                      # run a command inside it
   docker rm -f jin-session                                              # remove when done
   ```

5. (Optional) Build the image locally:
   ```
   docker build -t <yourusername>/jin:latest .
   docker push <yourusername>/jin:latest
   ```

## Usage

### Interactive mode (recommended)

Running `jin` with no arguments starts an interactive session. Type any of the commands below (or a bare URL), press Enter to run it, and the prompt returns afterwards so you can keep investigating. Press `Ctrl+C` (or type `exit`/`quit`) to leave. Up/Down arrow keys recall history, and `Tab` completes command names.

```
jin
jin> https://example.com
jin> ports -t example.com -p 80,443
jin> tech-stack -t example.com --subdomains --cve
jin> dns -t example.com
jin> whois -t example.com
jin> scan -t example.com -o report.json
jin> exit
```

### One-shot commands

For scripts and Docker, commands can also be passed directly — the program runs once and exits:

```
jin <command> [options] <url> [options]
```

Or, using Docker:

```
docker run -it <yourusername>/jin:latest <command> [options] <url> [options]
```

## Contributing

We welcome contributions! To contribute:

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature-name`.
3. Commit changes: `git commit -m "Add feature-name"`.
4. Push to the branch: `git push origin feature-name`.
5. Submit a pull request.

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

The tools in this project are intended for ethical and educational purposes only. Use them responsibly and avoid actions that could harm others or violate privacy laws.

## About

Jin began as [sapiuwu/jin](https://github.com/sapiuwu/jin), a project focused on ethical port scanning and DDoS simulation for educational purposes. It has since been rewritten in Go and repurposed as a passive OSINT and recon toolkit for security research and education.
