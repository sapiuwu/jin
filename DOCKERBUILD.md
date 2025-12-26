```bash
docker build -t <image-name>:<tag> .
docker build -t jin .
```

```bash
docker build -f Dockerfile.bookworm -t wahyouka/jin:v2.1.0-bookworm .
```

```bash
docker run -it jin help
docker run -it jin https://example.com/
docker run -it jin dns -t https://example.com/
docker run -it jin subdomains -t https://example.com/
```

```bash
docker tag jin:1.24.5-alpine wahyouka/jin:v1.0.0

docker login

docker push wahyouka/jin:v1.0.0
```
