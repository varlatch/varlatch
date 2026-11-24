#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Pulls images CI starts containers from, trying again when the registry has
# a bad moment: `docker run` pulls once, so one 500 from a registry fails
# every job that starts the image.
#
#   scripts/ci-pull-image.sh <image>@sha256:<digest> [...]
#
# Each image is named by its digest (a tag beside it is allowed). One that is
# here already is not asked for. A pull is tried 5 times, 5, 15, 30 and 60
# seconds apart (under two minutes of waiting: a longer outage still fails).
# An answer another try cannot change (the image is not there, access is
# refused, no Docker daemon) fails at once; anything else (a 5xx, a rate
# limit, a lost connection) is tried again. Exit 64 is a usage error.
set -euo pipefail

if [ $# -eq 0 ]; then
  echo "usage: ci-pull-image.sh <image>@sha256:<digest> [...]" >&2
  exit 64
fi
for image in "$@"; do
  if ! [[ "$image" =~ ^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$ ]]; then
    echo "ci-pull-image: $image is not an image by its digest (<image>@sha256:<digest>)" >&2
    exit 64
  fi
done

# What another try cannot change. A 408 or a 429 can pass.
permanent='manifest unknown|manifest for .* not found|: not found$|repository does not exist|pull access denied|unauthorized|no matching manifest|invalid reference format'
permanent+='|(400 Bad Request|401 Unauthorized|403 Forbidden|404 Not Found|410 Gone)|Cannot connect to the Docker daemon|permission denied while trying to connect'

pull() {
  local image=$1 out try=1 wait
  if docker image inspect "$image" > /dev/null 2>&1; then
    echo "ci-pull-image: $image is here" >&2
    return 0
  fi
  for wait in 5 15 30 60 ''; do
    if out=$(docker pull --quiet "$image" 2>&1); then
      echo "ci-pull-image: $image pulled (try $try)" >&2
      return 0
    fi
    echo "ci-pull-image: try $try of 5 of $image failed: $out" >&2
    if grep -qiE "$permanent" <<< "$out"; then
      echo "ci-pull-image: another try cannot change that" >&2
      return 1
    fi
    [ -n "$wait" ] || break
    sleep "$wait"
    try=$((try + 1))
  done
  echo "ci-pull-image: $image could not be pulled" >&2
  return 1
}

for image in "$@"; do pull "$image"; done
