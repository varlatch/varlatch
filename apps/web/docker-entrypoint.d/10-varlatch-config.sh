#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Runtime configuration for prebuilt images: release images are shared across
# installations, so the browser-facing Convex origin cannot be baked at build
# time. nginx runs every /docker-entrypoint.d/*.sh before serving.
set -eu
if [ -n "${CONVEX_URL:-}" ]; then
  printf 'window.__VARLATCH__ = { convexUrl: "%s" };\n' "$CONVEX_URL" \
    > /usr/share/nginx/html/varlatch-config.js
fi
