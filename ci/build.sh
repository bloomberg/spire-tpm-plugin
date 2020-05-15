#!/bin/bash -e

cd "$(dirname "$0")"

export "FIXUID=$(id -u)"
export "FIXGID=$(id -g)"

function cleanup() {
  docker-compose \
    -f docker/docker-compose.yaml \
    -p spire-tpm-plugin \
    stop
}

trap cleanup EXIT

docker-compose \
  -f docker/docker-compose.yaml \
  -p spire-tpm-plugin \
  up \
  --build \
  -d

docker exec \
  -t \
  -w "/home/docker/spire-tpm-plugin/" \
  spire-tpm-plugin-ci \
  fixuid \
  make
