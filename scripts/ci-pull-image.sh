#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Has images CI starts containers from on this host, whatever mood their
# registry is in: `docker run` pulls once, so one 500 from a registry fails
# every job that starts the image.
#
#   scripts/ci-pull-image.sh <image>@sha256:<digest> [...]
#
# Each image is named by its digest (a tag beside it is allowed). For each,
# a line on stdout is what to start: the image as named, or, for one loaded
# from the cache, its ID (docker load keeps no name by digest). In turn:
#
# 1. One that is here already is not asked for.
# 2. With CI_IMAGE_CACHE (a directory), its <digest>.tar there, as docker
#    save wrote it, is loaded. What it loaded must be the pinned image: an
#    image's ID is the hash of its content, so it is looked for by the IDs
#    the pinned one can have and no other (ids, below). It must be whole too:
#    docker load takes a tar with a damaged layer, whose image then has its
#    ID and lacks the layer, so a container is made of it, which unpacks every
#    layer, checked, and removed again. Anything else is refused, and the
#    image is pulled.
# 3. It is pulled: 5 tries, 5, 15, 30 and 60 seconds apart (under two
#    minutes of waiting: a longer outage still fails). An answer another try
#    cannot change (the image is not there, access is refused, no Docker
#    daemon) fails at once; anything else (a 5xx, a rate limit, a lost
#    connection) is tried again. With CI_IMAGE_CACHE, it is saved there.
#
# Exit 64 is a usage error.
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

# The IDs image may have here: the pinned digest (Docker's containerd image
# store, the hosted runners' and a new installation's), and, recorded here,
# its linux/amd64 configuration's digest (the older store, overlay2's).
ids() {
  echo "${1##*@}"
  case "${1##*@}" in
    # cgr.dev/chainguard/minio. After a change of its digest:
    # docker save <image> | tar -xO manifest.json, its "Config".
    sha256:6a1d0b45c8669726bba580ced0bfa4cb9fdeed1ed636dfabd81d1577beb6937b)
      echo sha256:a1477d311e9fdbf40a1e6fcb62c391b1e826a9897decb27341d6310294abed8a ;;
  esac
}

# here prints what to start of an image that is on this host.
here() {
  if docker image inspect "$1" > /dev/null 2>&1; then
    echo "$1"
    return 0
  fi
  by_id "$1"
}

# whole is whether the loaded image is one a container can be made of.
whole() {
  local container
  container=$(docker create --pull never "$1" true 2>&1) || { echo "ci-pull-image: $container" >&2; return 1; }
  docker rm --force --volumes "$container" > /dev/null 2>&1 || true
}

by_id() {
  local id
  for id in $(ids "$1"); do
    if [ "$(docker image inspect --format '{{.Id}}' "$id" 2> /dev/null)" = "$id" ]; then
      echo "$id"
      return 0
    fi
  done
  return 1
}

cached() { echo "${CI_IMAGE_CACHE:+$CI_IMAGE_CACHE/${1##*@sha256:}.tar}"; }

# What another try cannot change. A 408 or a 429 can pass.
permanent='manifest unknown|manifest for .* not found|: not found$|repository does not exist|pull access denied|unauthorized|no matching manifest|invalid reference format'
permanent+='|(400 Bad Request|401 Unauthorized|403 Forbidden|404 Not Found|410 Gone)|Cannot connect to the Docker daemon|permission denied while trying to connect'

get() {
  local image=$1 tar out id try=1 wait
  if here "$image"; then
    echo "ci-pull-image: $image is here" >&2
    return 0
  fi
  tar=$(cached "$image")
  if [ -n "$tar" ] && [ -f "$tar" ]; then
    if ! out=$(docker load --quiet --input "$tar" 2>&1); then
      echo "ci-pull-image: $image could not be loaded from the cache: $out" >&2
    elif id=$(by_id "$image") && whole "$id"; then
      echo "ci-pull-image: $image loaded from the cache" >&2
      echo "$id"
      return 0
    else
      echo "::warning::ci-pull-image: refused: what the cache holds is not $image ($out); pulling it" >&2
      # A name is the tar's own word: the image's is not left on another,
      # nor its ID on a part of it.
      docker image rm --force "$image" ${id:+"$id"} > /dev/null 2>&1 || true
    fi
  fi
  for wait in 5 15 30 60 ''; do
    if out=$(docker pull --quiet "$image" 2>&1); then
      echo "ci-pull-image: $image pulled (try $try)" >&2
      echo "$image"
      [ -z "$tar" ] || save "$image" "$tar"
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

# save writes the cache's tar, whole or not at all. The cache is a help: one
# that cannot be written fails nothing.
save() {
  if mkdir -p "$(dirname "$2")" && docker save --output "$2.part" "$1" >&2 && mv "$2.part" "$2"; then
    echo "ci-pull-image: $1 saved for the cache" >&2
  else
    rm -f "$2.part"
    echo "ci-pull-image: $1 could not be saved for the cache" >&2
  fi
}

for image in "$@"; do get "$image"; done
