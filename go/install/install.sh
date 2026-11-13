#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Installs Varlatch (ADR-0059 Decision 8).
#
#   curl -fsSLo install.sh https://varlatch.com/install.sh && sh install.sh
#       the varlatch CLI, for the current user, in ~/.local/bin
#   sh install.sh --server [-- <varlatch setup flags>]
#       a server, as root: varlatch and varlatchd in /usr/local/bin and the
#       varlatchd systemd unit, then varlatch setup
#
# Options: --version <version> (default: the release this script came
# with), --dir <directory> (the CLI's directory), --help. Tests also set
# VARLATCH_INSTALL_BASE_URL (another HTTPS address for the release files)
# and VARLATCH_INSTALL_ROOT (a directory standing in for / in --server).
#
# What this trusts: HTTPS to github.com for the release files, which are
# checked against the release's SHA256SUMS; then, before anything is put in
# place, the downloaded varlatch checks that SHA256SUMS is signed by the
# release workflow of varlatch/varlatch for this version (Sigstore). If any
# check fails, nothing is installed. For the strongest route, download the
# files and check them with cosign first:
# https://docs.varlatch.com/operations/verify-release/
#
# Every line that runs is inside the braces below. A shell runs none of it
# until it has read the closing brace, so a copy of this file cut off in
# transfer runs nothing at all.

{
set -eu

# The release stamps its version here; a copy that was not stamped needs
# --version.
VARLATCH_RELEASE='@VARLATCH_VERSION@'
REPOSITORY='varlatch/varlatch'

say() { printf '%s\n' "$*"; }
stop() { printf 'varlatch install: %s\n' "$*" >&2; exit 1; }

usage() {
  say 'usage: sh install.sh [--version <version>] [--dir <directory>]'
  say '       sh install.sh --server [--version <version>] [-- <varlatch setup flags>]'
}

# curl without ~/.curlrc (-q), HTTPS only, also after redirects (GitHub
# serves release files from another host), failing on any HTTP error.
fetch() {
  curl -q -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 2 -o "$2" "$1" \
    || stop "could not download $1"
}

# The SHA-256 tool, chosen once (main checks one exists).
sha256() {
  case "$hasher" in
    sha256sum) sha256sum "$1" | cut -d' ' -f1 ;;
    shasum) shasum -a 256 "$1" | cut -d' ' -f1 ;;
    *) openssl dgst -sha256 -r "$1" | cut -d' ' -f1 ;;
  esac
}

# expected <name>: the one SHA-256 SHA256SUMS lists for exactly that file
# (fails otherwise).
expected() {
  awk -v name="$1" '
    length($1) == 64 && $1 ~ /^[0-9a-f]+$/ && ($2 == name || $2 == "*" name) { hash = $1; n++ }
    END { if (n == 1) print hash; else exit 1 }
  ' "$tmp/SHA256SUMS"
}

# download <name>: fetches a release file into the private directory and
# checks it against SHA256SUMS. A file cut off in transfer fails here.
download() {
  want=$(expected "$1") || stop "SHA256SUMS does not list $1 exactly once; nothing was installed"
  fetch "$base/$1" "$tmp/$1"
  [ "$(sha256 "$tmp/$1")" = "$want" ] || stop "$1 does not match SHA256SUMS; nothing was installed"
}

# verify <--file path=name>...: the downloaded CLI checks the signature on
# SHA256SUMS, and the files against it.
verify() {
  "$tmp/$cli" verify-release --version "$version" --sums "$tmp/SHA256SUMS" \
    --bundle "$tmp/SHA256SUMS.sigstore.json" "$@" \
    || stop "the release signature does not verify; nothing was installed"
}

# place <file> <target> <mode>: moves a checked file into place atomically,
# through a temporary name in the target's own directory.
place() {
  into=$(dirname "$2")
  mkdir -p "$into"
  cp "$1" "$into/.varlatch-install.$$.tmp"
  chmod "$3" "$into/.varlatch-install.$$.tmp"
  mv -f "$into/.varlatch-install.$$.tmp" "$2"
}

# same <file> <target>: the target exists and has exactly this content.
same() {
  [ -f "$2" ] && [ "$(sha256 "$1")" = "$(sha256 "$2")" ]
}

# A Homebrew copy is Homebrew's to update.
homebrew() {
  [ -e "$1" ] || return 0
  if grep -q 'installed with Homebrew' "$1" 2>/dev/null; then
    stop "varlatch is installed with Homebrew at $1; update it with: brew upgrade varlatch"
  fi
  case "$(readlink "$1" 2>/dev/null || true)" in
    */Cellar/*) stop "varlatch is installed with Homebrew at $1; update it with: brew upgrade varlatch" ;;
  esac
}

main() {
  version=$VARLATCH_RELEASE
  server=no
  dir=${HOME:-}/.local/bin
  while [ $# -gt 0 ]; do
    case "$1" in
      --version) [ $# -ge 2 ] || stop "--version needs a value"; version=$2; shift 2 ;;
      --dir) [ $# -ge 2 ] || stop "--dir needs a value"; dir=$2; shift 2 ;;
      --server) server=yes; shift ;;
      --help|-h) usage; exit 0 ;;
      --) shift; break ;;
      *) usage >&2; stop "unknown option: $1" ;;
    esac
  done
  [ "$server" = yes ] || [ $# -eq 0 ] || stop "setup flags after -- are for --server"
  case "$version" in
    @*) stop "this copy of install.sh is not from a release; pass --version <version>" ;;
  esac
  # A plain release version: nothing in it can change where files come from.
  case "$version" in
    ''|*[!0-9A-Za-z.-]*|.*|*..*|-*) stop "not a release version: $version" ;;
  esac
  case "$version" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) stop "not a release version: $version" ;;
  esac

  case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) stop "no varlatch for $(uname -s); on Windows use install.ps1" ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) stop "no varlatch for $(uname -m) processors" ;;
  esac

  root=${VARLATCH_INSTALL_ROOT:-}
  if [ "$server" = yes ]; then
    [ "$os" = linux ] || stop "a server needs Linux (with systemd)"
    [ "$(id -u)" = 0 ] || stop "a server install needs root: sudo sh install.sh --server"
    dir=$root/usr/local/bin
  else
    [ -n "$dir" ] || stop "set HOME or pass --dir"
  fi
  command -v curl >/dev/null 2>&1 || stop "needs curl"
  if command -v sha256sum >/dev/null 2>&1; then hasher=sha256sum
  elif command -v shasum >/dev/null 2>&1; then hasher=shasum
  elif command -v openssl >/dev/null 2>&1; then hasher=openssl
  else stop "needs sha256sum, shasum or openssl to check the downloads"
  fi

  base=${VARLATCH_INSTALL_BASE_URL:-https://github.com/$REPOSITORY/releases/download/v$version}
  cli=varlatch-$version-$os-$arch
  daemon=varlatchd-$version-linux-$arch

  # Private (mktemp -d is mode 0700), and removed whatever happens.
  tmp=$(mktemp -d) || stop "could not make a temporary directory"
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 1' HUP INT TERM

  fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS"
  fetch "$base/SHA256SUMS.sigstore.json" "$tmp/SHA256SUMS.sigstore.json"
  download "$cli"
  chmod 700 "$tmp/$cli"
  if [ "$server" = yes ]; then
    download "$daemon"
    download varlatchd.service
    chmod 700 "$tmp/$daemon"
  fi

  # The downloaded CLI must run here, be this version, and verify the
  # release signature before anything is put in place.
  reported=$("$tmp/$cli" --version 2>/dev/null) || stop "the downloaded varlatch does not run on this machine; nothing was installed"
  case "$reported" in
    "varlatch $version"|"varlatch $version "*) ;;
    *) stop "the downloaded varlatch reports '$reported', not $version; nothing was installed" ;;
  esac
  if [ "$server" = yes ]; then
    verify --file "$tmp/$cli=$cli" --file "$tmp/$daemon=$daemon" --file "$tmp/varlatchd.service=varlatchd.service"
  else
    verify --file "$tmp/$cli=$cli"
  fi

  if [ "$server" = yes ]; then
    install_server "$@"
  else
    install_cli
  fi
}

install_cli() {
  target=$dir/varlatch
  homebrew "$target"
  saved_ifs=$IFS
  IFS=:
  set -f
  for entry in $PATH; do
    [ -n "$entry" ] && homebrew "$entry/varlatch"
  done
  set +f
  IFS=$saved_ifs

  if same "$tmp/$cli" "$target"; then
    say "varlatch $version is already installed at $target."
  else
    place "$tmp/$cli" "$target" 755
    say "Installed varlatch $version at $target."
  fi
  case ":$PATH:" in
    *":$dir:"*)
      first=$(command -v varlatch 2>/dev/null || true)
      if [ -n "$first" ] && [ "$first" != "$target" ]; then
        say "Another varlatch comes first on your PATH: $first. Remove it, or put $dir before it."
      fi ;;
    *) say "$dir is not on your PATH. Add it, for example: echo 'export PATH=\"$dir:\$PATH\"' >> ~/.profile" ;;
  esac
  say "Next: varlatch login --server <your Varlatch address>"
}

install_server() {
  unit=$root/etc/systemd/system/varlatchd.service
  changed=no
  for pair in "$cli:$dir/varlatch:755" "$daemon:$dir/varlatchd:755" "varlatchd.service:$unit:644"; do
    name=${pair%%:*}
    rest=${pair#*:}
    target=${rest%:*}
    mode=${rest##*:}
    if ! same "$tmp/$name" "$target"; then
      place "$tmp/$name" "$target" "$mode"
      changed=yes
    fi
  done
  if [ "$changed" = yes ]; then
    say "Installed varlatch and varlatchd $version in $dir, and the varlatchd unit."
    [ -n "$root" ] || systemctl daemon-reload || stop "systemctl daemon-reload failed"
  else
    say "varlatch and varlatchd $version are already installed."
  fi
  # Setup asks its questions on the terminal, even when this script was
  # started with its input redirected.
  if [ -n "$root" ]; then
    say "Next: varlatch setup"
  elif ( : </dev/tty ) 2>/dev/null; then
    exec "$dir/varlatch" setup "$@" </dev/tty
  else
    exec "$dir/varlatch" setup "$@"
  fi
}

main "$@"
exit
}
