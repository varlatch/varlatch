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
# with), --dir <directory> (the CLI's directory), --help. The release
# files always come from github.com: the downloaded varlatch checks its own
# signature, which only means something when the download itself is
# trusted, so no option or variable changes where they come from.
#
# An installation that serves this script (varlatchd's serve_cli; ADR-0058
# Decision 3) stamps its own address in ORIGIN below: the CLI then comes
# from it, and is checked the same way. Installing from an installation
# trusts it, and whoever controls its host or its address, to run code on
# this machine.
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
# The serving installation's address, stamped when it serves this script;
# empty in a release, which installs from github.com.
ORIGIN=''

say() { printf '%s\n' "$*"; }
stop() { printf 'varlatch install: %s\n' "$*" >&2; exit 1; }

usage() {
  say 'usage: sh install.sh [--version <version>] [--dir <directory>]'
  say '       sh install.sh --server [--version <version>] [-- <varlatch setup flags>]'
}

# curl without ~/.curlrc (-q), HTTPS only, also after redirects (GitHub
# serves release files from another host), failing on any HTTP error. From
# an installation: its own scheme (https, or http on this machine), and no
# redirect is followed.
fetch() {
  if [ -n "$ORIGIN" ]; then
    if [ "$scheme" = http ]; then
      status=$(curl -q -sS --proto '=http' -w '%{http_code}' -o "$2" "$1") || stop "could not download $1"
    else
      status=$(curl -q -sS --proto '=https' --tlsv1.2 -w '%{http_code}' -o "$2" "$1") || stop "could not download $1"
    fi
    [ "$status" = 200 ] || stop "could not download $1 (HTTP $status; a redirect is never followed from an installation)"
    return
  fi
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

# typescript <file>: the file is the TypeScript CLI's single-file build
# (varlatch-cli-<version>.cjs), whose first lines carry its banner.
typescript() {
  [ -f "$1" ] && dd if="$1" bs=512 count=1 2>/dev/null | LC_ALL=C grep -q 'Varlatch CLI\. Copyright'
}

# compose: this host has a Compose installation (decision 11): its install
# marker or its Compose file in /srv/varlatch (compose_dir), the directory
# the operations guides use. Its host commands stay the TypeScript CLI's,
# as varlatch-ts.
compose() {
  [ -f "$compose_dir/varlatch-install.json" ] || [ -f "$compose_dir/docker-compose.yml" ]
}

# put_cli <file> <target>: puts the checked varlatch at target. A
# TypeScript CLI there is kept until the new varlatch runs from target
# (decision 11): then it is removed, both sharing one store of sign-ins
# and settings until then, or, on a host with a Compose installation, kept
# beside it as varlatch-ts. If the new one does not run, the TypeScript
# CLI is put back.
put_cli() {
  if ! typescript "$2"; then
    place "$1" "$2" 755
    return
  fi
  into=$(dirname "$2")
  if compose && [ -e "$into/varlatch-ts" ] && ! typescript "$into/varlatch-ts"; then
    stop "$into/varlatch-ts exists and is not the TypeScript CLI; move it away, then run this again (nothing was installed)"
  fi
  old=$into/.varlatch-install.$$.typescript
  cp -p "$2" "$old" || stop "could not keep a copy of the TypeScript CLI at $2; nothing was installed"
  place "$1" "$2" 755
  if ! "$2" --version >/dev/null 2>&1; then
    mv -f "$old" "$2"
    stop "the new varlatch does not run at $2; the TypeScript CLI was put back"
  fi
  if compose; then
    mv -f "$old" "$into/varlatch-ts"
    say "Kept the TypeScript CLI as $into/varlatch-ts: the Compose installation in $compose_dir needs it for its host commands (setup, upgrade, doctor, admin, move) until varlatch migrate moves it."
  else
    rm -f "$old"
    say "Replaced the TypeScript CLI at $2. Your sign-ins and settings carry over: both CLIs use the same store."
  fi
}

# A Homebrew copy is Homebrew's to update. Homebrew is told by where the
# file is, as varlatch self-update tells it (selfupdate.Locate): the path,
# or any link on its way to the file, in a Cellar or under Homebrew's
# prefixes. And the TypeScript CLI's formula installed a script wrapper,
# which says so. Never by the message in a binary: every Go varlatch
# carries self-update's refusal text.
homebrew() {
  [ -e "$1" ] || [ -L "$1" ] || return 0
  hops=0 p=$1
  while :; do
    case "$p" in
      */Cellar/* | */cellar/* | /opt/homebrew/* | /home/linuxbrew/.linuxbrew/*)
        stop "varlatch is installed with Homebrew at $1; update it with: brew upgrade varlatch" ;;
    esac
    [ -L "$p" ] && [ "$hops" -lt 40 ] || break
    link=$(readlink "$p" 2>/dev/null) || break
    case "$link" in
      /*) p=$link ;;
      *) p=$(dirname "$p")/$link ;;
    esac
    hops=$((hops + 1))
  done
  if [ "$(head -c 2 "$1" 2>/dev/null)" = '#!' ] && grep -q 'installed with Homebrew' "$1" 2>/dev/null; then
    stop "varlatch is installed with Homebrew at $1; update it with: brew upgrade varlatch"
  fi
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
  [ -z "$ORIGIN" ] || [ "$server" = no ] || stop "a server installs from github.com: use the release's install.sh (https://github.com/$REPOSITORY/releases)"
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

  # The tests run a copy of this script with a directory here instead of /.
  root=''
  compose_dir=$root/srv/varlatch
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

  base=https://github.com/$REPOSITORY/releases/download/v$version
  scheme=https
  if [ -n "$ORIGIN" ]; then
    case "$ORIGIN" in
      *[!A-Za-z0-9.:/\[\]-]*) stop "$ORIGIN is not an address to install from" ;;
      https://?*) ;;
      http://localhost|http://localhost:[0-9]*|http://127.0.0.1|http://127.0.0.1:[0-9]*|'http://[::1]'|'http://[::1]:'[0-9]*) scheme=http ;;
      *) stop "$ORIGIN is neither https: nor http: on this machine" ;;
    esac
    base=$ORIGIN/cli/v$version
  fi
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
    put_cli "$tmp/$cli" "$target"
    say "Installed varlatch $version at $target."
  fi
  case ":$PATH:" in
    *":$dir:"*)
      first=$(command -v varlatch 2>/dev/null || true)
      if [ -n "$first" ] && [ "$first" != "$target" ]; then
        if typescript "$first" && compose; then
          say "The TypeScript CLI comes first on your PATH: $first. The Compose installation in $compose_dir needs it for its host commands: rename it to varlatch-ts, for example: sudo mv $first $(dirname "$first")/varlatch-ts"
        else
          say "Another varlatch comes first on your PATH: $first. Remove it, or put $dir before it."
        fi
      fi ;;
    *) say "$dir is not on your PATH. Add it, for example: echo 'export PATH=\"$dir:\$PATH\"' >> ~/.profile" ;;
  esac
  if [ -n "$ORIGIN" ]; then
    say "Next: varlatch login --server $ORIGIN"
  else
    say "Next: varlatch login --server <your Varlatch address>"
  fi
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
      if [ "$name" = "$cli" ]; then
        put_cli "$tmp/$name" "$target"
      else
        place "$tmp/$name" "$target" "$mode"
      fi
      changed=yes
    fi
  done
  if [ "$changed" = yes ]; then
    say "Installed varlatch and varlatchd $version in $dir, and the varlatchd unit."
    [ -n "$root" ] || systemctl daemon-reload || stop "systemctl daemon-reload failed"
  else
    say "varlatch and varlatchd $version are already installed."
  fi
  if [ -n "$root" ]; then
    say "Next: varlatch setup"
    return
  fi
  # exec replaces this shell, so its EXIT trap would not run: the private
  # directory goes first. Setup asks its questions on the terminal, even
  # when this script was started with its input redirected.
  rm -rf "$tmp"
  trap - EXIT
  if ( : </dev/tty ) 2>/dev/null; then
    exec "$dir/varlatch" setup "$@" </dev/tty
  else
    exec "$dir/varlatch" setup "$@"
  fi
}

main "$@"
exit
}
