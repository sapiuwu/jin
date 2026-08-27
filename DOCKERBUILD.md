```bash
docker build -t <image-name>:<tag> .
docker build -t jin .
```

```bash
docker build -f Dockerfile.bookworm -t wahyouka/jin:v2.1.0-bookworm .
```

```bash
# Mode interaktif (REPL): prompt kembali setelah tiap perintah, container
# otomatis dihapus saat keluar (--rm) sehingga tidak menumpuk container sampah.
docker run -it --rm jin

# One-shot: tambahkan --rm agar container ikut terhapus setelah selesai.
docker run -it --rm jin help
docker run -it --rm jin https://example.com/
docker run -it --rm jin dns -t https://example.com/
docker run -it --rm jin subdomains -t https://example.com/
```

> Catatan: `docker run` selalu membuat container baru. Untuk satu container
> yang bisa dipakai berulang, jalankan sekali dengan nama lalu `exec`:
>
> ```bash
> docker run -it --rm --name jin-session jin          # lalu quit
> # atau pakai exec untuk menjalankan perintah di container yang sudah ada:
> docker start -ai jin-session
> docker exec -it jin-session ports -t example.com
> ```

```bash
docker tag jin:1.24.5-alpine wahyouka/jin:v1.0.0

docker login

docker push wahyouka/jin:v1.0.0
```
