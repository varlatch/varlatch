// SPDX-License-Identifier: Apache-2.0
/**
 * Points the relative links of a synced page at the site. The repository's
 * Markdown links file to file (`../operations/backup.md#restore`), which is
 * right on GitHub; on the site, a link to another page goes to that page's
 * route, and a link to any other file in the repository goes to the file on
 * GitHub. A link to a file that does not exist fails the build.
 */
import { existsSync, statSync } from "node:fs";
import { dirname, join, posix, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { pages, pathOf, REPOSITORY, repoRoot, sourceRef } from "./sources.mjs";

const contentDir = resolve(dirname(fileURLToPath(import.meta.url)), "content/docs");

/**
 * The site URL for `url`, linked from the repository file `from`, or
 * undefined when the link is not relative (another site, an anchor on the
 * same page, a mail address).
 */
export function rewrite(url, from, routes, exists = path => existsSync(join(repoRoot, path))) {
  // Files that ship outside the repository (the deployment guide is in every
  // release's bundle) link to pages on GitHub; on the site, those are pages.
  const onGithub = url.match(/^https:\/\/github\.com\/varlatch\/varlatch\/blob\/[^/]+\/([^#?]+)(#.*)?$/);
  if (onGithub && routes.has(onGithub[1])) return pathOf(routes.get(onGithub[1])) + (onGithub[2] ?? "");
  if (/^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith("#") || url.startsWith("/")) return undefined;
  const hashAt = url.indexOf("#");
  const path = hashAt === -1 ? url : url.slice(0, hashAt);
  const hash = hashAt === -1 ? "" : url.slice(hashAt);
  const target = posix.normalize(posix.join(posix.dirname(from), decodeURIComponent(path))).replace(/\/$/, "");
  if (target.startsWith("../")) throw new Error(`${from}: "${url}" points outside the repository`);
  const route = routes.get(target);
  if (route !== undefined) return pathOf(route) + hash;
  if (!exists(target)) throw new Error(`${from}: "${url}" points at ${target}, which does not exist`);
  const kind = statSync(join(repoRoot, target)).isDirectory() ? "tree" : "blob";
  return `${REPOSITORY}/${kind}/${sourceRef}/${target}${hash}`;
}

/**
 * The Sätteri plugin (Astro's Markdown processor) that applies `rewrite` to
 * every link and link definition of a synced page; hand-written pages are
 * left alone.
 */
export function repoLinks({ fileURL }) {
  if (!fileURL) return null;
  const list = pages();
  const route = relative(contentDir, fileURLToPath(fileURL)).replace(/\.mdx?$/, "").split("\\").join("/");
  const from = list.find(page => page.route === route)?.source;
  if (from === undefined) return null;
  const routes = new Map(list.map(page => [page.source, page.route]));
  const update = (node, ctx) => {
    const url = rewrite(node.url, from, routes);
    if (url !== undefined) ctx.setProperty(node, "url", url);
  };
  return { name: "varlatch-repo-links", link: update, definition: update };
}
