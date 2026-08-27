# Docker Build & Run

## Build locally

Build with the default base image (`alpine:latest`):

```bash
docker build -t jin .
```

Build from a different base image using the `BASE_IMAGE` build argument
(supported: `alpine:latest`, `alpine:3.20`, `debian:bookworm`,
`debian:bullseye`, `ubuntu:22.04`, `ubuntu:24.04`):

```bash
docker build --build-arg BASE_IMAGE=debian:bookworm -t jin:bookworm .
```

> The `Dockerfile` uses a single `ARG BASE_IMAGE` (default `alpine:latest`)
> and an `ENTRYPOINT ["jin"]` with an empty `CMD`, so `docker run -it jin`
> starts the interactive REPL by default. See `build.sh` for the matrix of
> base images published to Docker Hub.

## Run

```bash
# Interactive mode (REPL): the prompt returns after each command and the
# container is removed on quit (--rm) so containers don't pile up.
docker run -it --rm jin

# One-shot: add --rm so the container is cleaned up after it finishes.
docker run -it --rm jin help
docker run -it --rm jin https://example.com/
docker run -it --rm jin dns -t https://example.com/
docker run -it --rm jin subdomains -t https://example.com/
```

> Note: `docker run` always creates a new container. To reuse a single
> container, run it once with a name and reconnect or `exec` into it:
>
> ```bash
> docker run -it --name jin-session jin               # then quit
> docker start -ai jin-session                        # reconnect to the REPL
> docker exec -it jin-session ports -t example.com    # run a command in it
> docker rm -f jin-session                            # remove when done
> ```

## Tag & push to Docker Hub

```bash
# Local image -> Docker Hub (match the published version, e.g. v2.4.1)
docker tag jin wahyouka/jin:v2.4.1-alpine-latest

docker login
docker push wahyouka/jin:v2.4.1-alpine-latest
```

To publish every supported base image at once, use `build.sh` (it loops over
the base-image matrix and pushes each as `wahyouka/jin:v2.4.1-<base>-<tag>`).
