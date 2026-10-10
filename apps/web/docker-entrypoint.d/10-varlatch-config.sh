#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Runtime configuration for prebuilt images: release images are shared across
# installations, so the browser-facing Convex origin cannot be baked at build
# time. nginx runs every /docker-entrypoint.d/*.sh before serving.
#
# Also writes the dashboard's Content-Security-Policy (ADR-0046, rollout step
# 4): scripts and styles from this origin only, nothing inline, no framing,
# and connections only to this origin, the browser-facing Convex origin and,
# when set, the tailnet browser endpoint (VARLATCH_TAILNET_ENDPOINT, an exact
# https origin).
set -eu

HTML_DIR="${VARLATCH_HTML_DIR:-/usr/share/nginx/html}"
CSP_FILE="${VARLATCH_CSP_FILE:-/etc/nginx/varlatch/csp.conf}"

fail() {
  echo "varlatch-web: $*" >&2
  exit 1
}

# URLs end up inside a JavaScript string and an nginx header: refuse
# anything that could leave either (quotes, backslashes, semicolons, $,
# backticks, whitespace, more than one line).
plain_url() {
  [ "$(printf '%s' "$1" | wc -l)" -eq 0 ] && printf '%s\n' "$1" | grep -Eq '^https?://[^[:space:]"'\''\\;$`]+$'
}
if [ -n "${CONVEX_URL:-}" ] && ! plain_url "$CONVEX_URL"; then
  fail "CONVEX_URL must be a plain http(s) URL, got: ${CONVEX_URL}"
fi
endpoint="${VARLATCH_TAILNET_ENDPOINT:-}"
if [ -n "$endpoint" ] && ! { [ "$(printf '%s' "$endpoint" | wc -l)" -eq 0 ] && printf '%s\n' "$endpoint" | grep -Eq '^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$'; }; then
  fail "VARLATCH_TAILNET_ENDPOINT must be exactly an https origin such as https://varlatch.example.ts.net:8688, got: ${endpoint}"
fi

if [ -n "${CONVEX_URL:-}" ]; then
  printf 'window.__VARLATCH__ = { convexUrl: "%s" };\n' "$CONVEX_URL" \
    > "$HTML_DIR/varlatch-config.js"
fi

# Convex: the origin the dashboard uses (app.tsx falls back to a local dev
# backend when none is configured), over HTTP(S) and its WebSocket.
convex="${CONVEX_URL:-http://localhost:3210}"
convex_origin=$(printf '%s' "$convex" | sed -E 's#^(https?://[^/]+).*#\1#')
case "$convex_origin" in
  https://*) convex_ws="wss://${convex_origin#https://}" ;;
  *) convex_ws="ws://${convex_origin#http://}" ;;
esac

connect="'self' $convex_origin $convex_ws${endpoint:+ $endpoint}"
policy="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; font-src 'self' data:; connect-src $connect; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"

mkdir -p "$(dirname "$CSP_FILE")"
printf 'add_header Content-Security-Policy "%s" always;\n' "$policy" > "$CSP_FILE"
