# Jin: Your Passive OSINT & Recon CLI Toolkit

<img src="./public/jin-demo.gif">

**Version: 2.3.0**

Jin is an open-source command-line interface (CLI) toolkit for OSINT (Open-Source Intelligence) and reconnaissance. It gathers server, network, and technology-stack information about a target using passive, safe techniques — no active exploitation. This tool is intended for ethical and educational use only—please refrain from using it for harmful actions.

## Overview

Jin provides a suite of commands to assist with network reconnaissance, domain analysis, and vulnerability assessment. Built with Go, it is lightweight, portable, and containerizable with Docker, making it accessible for security researchers, students, and enthusiasts.

## Current Tools

- **info**: Full server reconnaissance — response headers, TLS version, and security checks for the given URL.
- **ports**: Scan for open ports using a TCP connect scan (custom port lists supported).
- **tech-stack**: Fingerprint the technology stack (CMS, server, frameworks, JS libraries, CDN), with optional subdomain and DNS discovery.

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
   docker pull wahyouka/jin:v2.3.0-alpine-latest
   ```

2. Run the CLI interactively:

   ```
   docker run -it --entrypoint jin wahyouka/jin:v2.3.0-alpine-latest
   ```

   Run a one-shot command:

   ```
   docker run -it wahyouka/jin:v2.3.0-alpine-latest ports -t example.com
   ```

3. (Optional) Build the image locally:
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
jin> tech-stack -t example.com --subdomains
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
