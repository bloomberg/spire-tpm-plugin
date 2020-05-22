#!/bin/bash -e

cd "$(dirname "$0")/../"

display_usage() {
  echo -e "Usage:\n$0 [version]"
}

# check whether user had supplied -h or --help . If yes display usage
if [ $# = "--help" ] || [ $# = "-h" ]; then
  display_usage
  exit 0
fi

# check number of arguments
if [ $# -ne 1 ]; then
  display_usage
  exit 1
fi

binaries=("get_tpm_pubhash" "tpm_attestor_agent" "tpm_attestor_server")

rm -f spire-tpm-plugin-*.tar.gz
user="$(id -u):$(id -g)"
sudo chown root:root "${binaries[@]}"
tar -cvzf "spire-tpm-plugin-$1-linux-amd64.tar.gz" "${binaries[@]}"
sudo chown "$user" "${binaries[@]}"
