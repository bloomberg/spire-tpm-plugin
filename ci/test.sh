#!/bin/bash -e

cd "$(dirname "$0")"

export "FIXUID=$(id -u)"
export "FIXGID=$(id -g)"

option="$1"
if [ -z "$1" ]; then
  option="all"
fi

test_dirs=()
if [ "$option" = "plugin" ] || [ "$option" = "all" ]; then
  test_dirs+=("pkg/agent")
fi
if [ "$option" = "tools" ] || [ "$option" = "all" ]; then
  test_dirs+=("tools/get_tpm_pubhash")
fi

if [ "${#test_dirs[@]}" = "0" ]; then
  echo "usage: $0 all|plugin|tools" >&2
  exit 1
fi

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
  start

for i in "${test_dirs[@]}"; do
  echo "calling go test on dir: $i"
  docker exec \
    -t \
    -w "/home/docker/spire-tpm-plugin/$i" \
    spire-tpm-plugin-ci \
    go test
  echo ""
done
