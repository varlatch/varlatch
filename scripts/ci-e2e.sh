#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Clean-room end-to-end: the conformance runner against a fresh stack built
# from this checkout, with the CLI built from it (scripts/conformance/README.md).
# It starts the canonical Compose stack as a disposable project, reconciles
# Convex, bootstraps a passkey, seeds data, runs every suite in a fixed order,
# reports each check by its ID, and removes the project on exit. Used by CI
# and runnable locally after `pnpm build` (wrap in `newgrp docker` if your
# session lacks the group). Extra arguments go to the runner, for example
# `--report report.json` or `--suite values`.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
exec node "$REPO_ROOT/scripts/conformance/run.mjs" --target ts-source --cli source "$@"
