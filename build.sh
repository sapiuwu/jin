#!/bin/bash
# build.sh

IMAGES=(
  "debian:bullseye"
  "debian:bookworm"
  "ubuntu:22.04"
  "ubuntu:24.04"
  "alpine:latest"
  "alpine:3.20"
)

VERSION="wahyouka/jin:v2.1.0"

for img in "${IMAGES[@]}"; do
  tag=$(echo "$img" | tr ':' '-')
  echo "Building jin:$tag from $img..."
  docker build --build-arg BASE_IMAGE="$img" -t "${VERSION}-$tag" .
  docker push "${VERSION}-$tag"
done



echo "✅ All images built."