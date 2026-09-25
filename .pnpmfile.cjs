// SPDX-License-Identifier: Apache-2.0
// better-auth declares optional peers for integrations Varlatch does not use:
// vitest for its test utilities, react and react-dom for `better-auth/react`
// (the dashboard uses `better-auth/client`). pnpm resolves optional peers
// that exist anywhere in the workspace, and `pnpm deploy --prod` then copied
// vitest, vite, rollup, react, and their native binaries into the production
// varlatchd image. Dropping these peers keeps each image to what it runs.
const UNUSED_PEERS = ["vitest", "react", "react-dom"];

module.exports = {
  hooks: {
    readPackage(pkg) {
      if (pkg.name === "better-auth" || pkg.name?.startsWith("@better-auth/")) {
        for (const peer of UNUSED_PEERS) {
          delete pkg.peerDependencies?.[peer];
          delete pkg.peerDependenciesMeta?.[peer];
        }
      }
      return pkg;
    },
  },
};
