#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Playwright's Chromium for the browser suites in CI.
#
# `playwright install --with-deps chromium` also runs apt: on GitHub's
# Ubuntu runner image that only adds fonts (CJK, Thai, Unicode fallbacks)
# no suite looks at, yet an apt mirror at 87 kB/s made it take 5 minutes.
# So this installs the browsers alone (from Playwright's CDN, seconds), starts
# each one Playwright may use, and installs the system dependencies only when
# one does not start, as on a runner image that lacks its libraries.
set -euo pipefail

playwright() {
  pnpm --filter @varlatch/varlatchd exec playwright "$@"
}

playwright install chromium

# Headless launches use the headless shell; the "chromium" channel is the
# full browser.
probe='
const { chromium } = require("playwright");
(async () => {
  for (const options of [{}, { channel: "chromium" }]) {
    const browser = await chromium.launch(options);
    await browser.close();
  }
})().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
'
if pnpm --filter @varlatch/varlatchd exec node -e "$probe"; then
  echo "Chromium starts with the runner image's libraries; no apt packages needed."
else
  echo "Chromium does not start yet; installing its system dependencies."
  playwright install-deps chromium
  pnpm --filter @varlatch/varlatchd exec node -e "$probe"
fi
