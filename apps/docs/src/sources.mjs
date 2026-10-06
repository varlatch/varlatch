// SPDX-License-Identifier: Apache-2.0
/**
 * Which repository files become pages, and at which route. The repository
 * stays the one source: these files are written for GitHub, with a `# Title`
 * first line and relative links between them, and the site is built from
 * them unchanged (scripts/sync-content.mjs copies them in, and
 * repo-links.mjs points their links at the site).
 *
 * Every Markdown file under docs/ is a page at its path without `docs/` and
 * `.md`, in lower case. The files outside docs/ are listed here.
 */
import { readdirSync } from "node:fs";
import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

export const REPOSITORY = "https://github.com/varlatch/varlatch";

/** The ref that links to files which are not pages point at. */
export const sourceRef = process.env.DOCS_SOURCE_REF || "main";

const EXTRA = [
  { source: "infra/compose/README.md", route: "self-hosting", title: "Install and operate" },
  { source: "CONTEXT.md", route: "concepts", title: "Concepts" },
  { source: "CHANGELOG.md", route: "changelog" },
];

function markdownUnder(dir) {
  return readdirSync(join(repoRoot, dir), { recursive: true, withFileTypes: true })
    .filter(entry => entry.isFile() && entry.name.endsWith(".md"))
    .map(entry => posix.join(posix.relative(repoRoot, entry.parentPath).split("\\").join("/"), entry.name))
    .sort();
}

/** @returns {{ source: string, route: string, title?: string }[]} */
export function pages() {
  const docs = markdownUnder("docs").map(source => ({
    source,
    route: source.slice("docs/".length, -".md".length).toLowerCase(),
  }));
  return [...docs, ...EXTRA];
}

/** The site path of a page's route. */
export function pathOf(route) {
  return `/${route}/`;
}
