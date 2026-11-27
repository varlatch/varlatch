// SPDX-License-Identifier: Apache-2.0
/**
 * Sections that moved to another page. Links into the old place keep
 * working: released CLIs, dashboards and other sites point at them, and a
 * fragment never reaches the server, so a small script on the old page
 * sends the reader on. The old page also keeps an anchor per moved
 * section, in a "Moved sections" list, for GitHub and readers without
 * scripts. check-links.mjs fails the build when a target does not exist,
 * or when the old page lost one of those anchors.
 */
export const MOVED = {
  "/getting-started/": {
    "what-you-need": "/self-hosting/#what-you-need",
    "get-the-cli": "/reference/install-the-cli/",
    "nodejs-version": "/reference/install-the-cli/#nodejs-version",
    "on-windows": "/reference/install-the-cli/#on-windows",
    "run-an-installation": "/self-hosting/",
    "try-it-on-your-own-machine": "/self-hosting/#try-it-on-your-own-machine",
    "set-up-a-project": "/set-up-a-project/",
    "move-an-existing-env-file-in": "/set-up-a-project/#move-an-existing-env-file-in",
    "or-start-from-a-contract": "/set-up-a-project/#or-start-from-a-contract",
    "run-your-application": "/set-up-a-project/#run-your-application",
    "invite-your-team": "/reference/members/#invite-your-team",
    "join-a-project": "/join-a-team/",
    "your-passkeys": "/reference/passkeys-and-sessions/#your-passkeys",
    "connect-ci-and-other-machines": "/reference/ci-and-machines/",
    "with-coding-agents": "/set-up-a-project/#with-coding-agents",
    "delete-a-project-or-an-organization": "/reference/uninstall/#delete-a-project-or-an-organization",
    "what-varlatch-puts-on-your-machine": "/reference/uninstall/#what-varlatch-puts-on-your-machine",
    "where-to-go-next": "/getting-started/#reference",
  },
  // The Compose guide was at /self-hosting/ up to 0.23.0, and day-2 operations
  // later moved to /self-hosting/operate/. Dashboards link to the upgrade sections.
  "/self-hosting/": {
    "first-install": "/self-hosting/#install",
    "with-varlatch-setup-recommended": "/self-hosting/#install",
    "existing-installations-varlatch-adopt": "/self-hosting/compose/#existing-installations-varlatch-adopt",
    "by-hand": "/self-hosting/compose/#by-hand",
    "where-to-keep-the-backup": "/self-hosting/operate/#the-root-kek-is-your-responsibility",
    "the-root-kek-is-your-responsibility": "/self-hosting/operate/#the-root-kek-is-your-responsibility",
    "passphrase-wrapped-escrow-recommended": "/self-hosting/operate/#a-passphrase-protected-copy",
    "shamir-secret-sharing-multi-custodian": "/self-hosting/operate/#shares-for-several-people",
    "break-glass-recovery": "/self-hosting/operate/#break-glass-recovery",
    "backup": "/operations/backup/",
    "upgrade-backup-gated-forward-only": "/operations/upgrade/",
    "outbound-destinations-after-upgrading-to-0220": "/self-hosting/compose/#outbound-destinations-after-upgrading-to-0220",
    "newer-releases-in-the-dashboard": "/operations/upgrade/#newer-releases-in-the-dashboard",
    "health-check-read-only": "/self-hosting/operate/#health-check",
    "health-check": "/self-hosting/operate/#health-check",
    "optional-tailscale-integration": "/self-hosting/configuration/#tailscale",
    "september-2026-upgrade-compatibility": "/self-hosting/compose/#september-2026-upgrade-compatibility",
    "client-addresses-behind-proxies": "/self-hosting/configuration/#trusted_proxies",
  },
};

/** The inline script every page carries: on an old page with a moved fragment, go to the new place. */
export function movedAnchorsScript(moved = MOVED) {
  // Own properties only: a fragment such as #constructor or #__proto__ must not reach Object.prototype.
  return `(()=>{const all=${JSON.stringify(moved)};if(!Object.hasOwn(all,location.pathname))return;const m=all[location.pathname];let id;try{id=decodeURIComponent(location.hash.slice(1))}catch{return}if(Object.hasOwn(m,id))location.replace(m[id]);})();`;
}
