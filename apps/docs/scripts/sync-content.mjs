#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Copies the repository's documentation into the site's content collection
 * (src/content/docs/, ignored by Git except for the hand-written home page).
 * Each file's `# Title` line becomes the page title, and the page's "Edit
 * page" link points at the file on GitHub. Links are rewritten when the page
 * renders (src/repo-links.mjs), not here.
 *
 *   sync-content.mjs    run before `astro dev` and `astro build`
 */
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { pages, REPOSITORY, repoRoot } from "../src/sources.mjs";

const contentDir = resolve(dirname(fileURLToPath(import.meta.url)), "../src/content/docs");
const KEEP = new Set(["index.mdx"]);

/** Splits a page into its title and the Markdown after the title line. */
export function splitTitle(source, text) {
  const match = text.match(/^# (.+)\n+/);
  if (!match) throw new Error(`${source}: the first line must be a "# Title" heading`);
  return { title: match[1].trim(), body: text.slice(match[0].length) };
}

/**
 * Drops HTML comments that start a line outside code blocks: notes for
 * maintainers (`<!-- TODO(owner): ... -->`), which GitHub does not show
 * either, stay out of the site's HTML.
 */
export function dropComments(body) {
  const kept = [];
  let fence = null;
  let comment = false;
  for (const line of body.split("\n")) {
    if (comment) {
      if (line.includes("-->")) comment = false;
      continue;
    }
    const marker = line.match(/^\s*(`{3,}|~{3,})/)?.[1];
    if (fence === null && marker) fence = marker;
    else if (fence !== null && marker?.startsWith(fence)) fence = null;
    if (fence === null && line.startsWith("<!--")) {
      comment = !line.includes("-->");
      continue;
    }
    kept.push(line);
  }
  return kept.join("\n").replace(/\n{3,}/g, "\n\n");
}

/** A page as the content collection reads it. */
export function toPage({ source, title: override }, text) {
  const { title, body: raw } = splitTitle(source, text);
  const body = dropComments(raw);
  const frontmatter = {
    title: override ?? title.replace(/`/g, ""),
    editUrl: `${REPOSITORY}/edit/main/${source}`,
  };
  const yaml = Object.entries(frontmatter)
    .map(([key, value]) => `${key}: ${JSON.stringify(value)}`)
    .join("\n");
  return `---\n${yaml}\n---\n\n${body}`;
}

function sync() {
  for (const entry of readdirSync(contentDir)) {
    if (!KEEP.has(entry)) rmSync(join(contentDir, entry), { recursive: true, force: true });
  }
  const list = pages();
  for (const page of list) {
    const target = join(contentDir, `${page.route}.md`);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, toPage(page, readFileSync(join(repoRoot, page.source), "utf8")));
  }
  console.log(`Synced ${list.length} pages into ${contentDir}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) sync();
