#!/bin/bash -e

cd "$(dirname "$0")"

export "FIXUID=$(id -u)"
export "FIXGID=$(id -g)"

docker-compose \
  -f docker/docker-compose.yaml \
  -p spire-tpm-plugin \
  down \
  -v
