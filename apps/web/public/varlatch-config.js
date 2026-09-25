// SPDX-License-Identifier: AGPL-3.0-or-later
// Runtime configuration. This default (no overrides) is what dev servers and
// source builds serve; the container entrypoint overwrites it from CONVEX_URL
// so one prebuilt release image works for every installation.
window.__VARLATCH__ = {};
