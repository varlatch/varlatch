// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The Security page's checklist (ADR-0054 Decision 11): a few things worth
 * doing, each with one line on why and its page on docs.varlatch.com (the
 * site renders docs/ at the same paths, in lower case). The CLI's
 * `varlatch security status` lists the same items.
 */

export const DOCS = "https://docs.varlatch.com";

/** The docs section about this page. */
export const SECURITY_PAGE_DOCS = `${DOCS}/reference/security-controls/#the-security-page`;

export interface ChecklistItem {
  id: string;
  title: string;
  why: string;
  url: string;
}

export const CHECKLIST: readonly ChecklistItem[] = [
  {
    id: "report-mode",
    title: "Try each control in report mode",
    why: "Report refuses nothing; its counts show what enforce would stop before you decide.",
    url: `${DOCS}/reference/security-controls/`,
  },
  {
    id: "trusted-passkeys",
    title: "Give every admin a trusted passkey",
    why: "Only a trusted passkey can approve turning a control down or off.",
    url: `${DOCS}/reference/passkeys-and-sessions/#your-passkeys`,
  },
  {
    id: "find-files",
    title: "Find copies of secrets on disk",
    why: "varlatch scan --find-files lists .env and key files that a stolen laptop would give away.",
    url: `${DOCS}/reference/secret-scanning/#finding-copies-of-secrets`,
  },
  {
    id: "backup-object-lock",
    title: "Keep backups where the host cannot erase them",
    why: "With Object Lock on the bucket, a compromised host cannot delete or overwrite archives.",
    url: `${DOCS}/operations/backup/#scoping-destination-credentials-per-provider`,
  },
  {
    id: "threat-model",
    title: "Read the threat model",
    why: "What Varlatch protects against, and what it leaves to whoever runs the host.",
    url: `${DOCS}/threat-model/`,
  },
];
