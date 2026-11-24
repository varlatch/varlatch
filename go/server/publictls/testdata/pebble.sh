#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Pebble, Let's Encrypt's test CA, and its mock DNS server for the public
# HTTPS tests (go/server/publictls, go/server/daemon; ADR-0059 step 6,
# slice 6.3a). Containers on the host's network, no outside network used:
# every name resolves to 127.0.0.1, and Pebble validates on 5002 (HTTP-01)
# and 5001 (TLS-ALPN-01), where the tests listen. Certificates last 45
# seconds, so renewals happen during a test.
#
#   go/server/publictls/testdata/pebble.sh start <dir>   # writes <dir>/pebble-api-root.pem, prints the env
#   go/server/publictls/testdata/pebble.sh stop
#
# Only this script's own containers are touched (removed by name).
set -euo pipefail

PEBBLE=ghcr.io/letsencrypt/pebble:2.8.0@sha256:d9080f68f6cb6af8d82134ab26de0aaaf312ac9cba42aecc6d3aede6cb63007b
CHALLTESTSRV=ghcr.io/letsencrypt/pebble-challtestsrv:2.8.0@sha256:c6ea5f6193517b3c7a02431b928234caf9db29a7a8abca4c0b337403468b650d
config="$(cd "$(dirname "$0")" && pwd)/pebble-config.json"

stop() {
  docker rm -fv varlatch-test-pebble varlatch-test-challtestsrv >/dev/null 2>&1 || true
}

case "${1:-}" in
start)
  dir=${2:?usage: pebble.sh start <dir>}
  stop
  # The mock DNS server only: its own challenge servers stay off, so that
  # 5001 and 5002 are the tests'.
  docker run -d --name varlatch-test-challtestsrv --network host "$CHALLTESTSRV" \
    -defaultIPv4 127.0.0.1 -defaultIPv6 "" -dns01 127.0.0.1:8053 -management 127.0.0.1:8055 \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" >/dev/null
  docker run -d --name varlatch-test-pebble --network host \
    -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 -e PEBBLE_AUTHZREUSE=0 \
    -v "$config:/pebble-config.json:ro" "$PEBBLE" -config /pebble-config.json -dnsserver 127.0.0.1:8053 >/dev/null
  mkdir -p "$dir"
  docker cp varlatch-test-pebble:/test/certs/pebble.minica.pem "$dir/pebble-api-root.pem" >/dev/null
  for _ in $(seq 1 60); do
    if curl -fsS --cacert "$dir/pebble-api-root.pem" https://localhost:14000/dir >/dev/null 2>&1; then
      echo "export VARLATCH_TEST_PEBBLE=https://localhost:14000/dir"
      echo "export VARLATCH_TEST_PEBBLE_ROOT=$dir/pebble-api-root.pem"
      exit 0
    fi
    sleep 0.5
  done
  docker logs varlatch-test-pebble >&2 || true
  echo "pebble.sh: Pebble did not answer" >&2
  exit 1
  ;;
stop) stop ;;
*) echo "usage: pebble.sh start <dir> | stop" >&2; exit 64 ;;
esac
