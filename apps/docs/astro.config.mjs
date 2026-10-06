// SPDX-License-Identifier: Apache-2.0
// docs.varlatch.com: the repository's documentation as a static site
// (Starlight). The pages are copied in from docs/ and the files listed in
// src/sources.mjs before every build; edit them there, not here.
import { satteri } from "@astrojs/markdown-satteri";
import starlight from "@astrojs/starlight";
import { defineConfig } from "astro/config";
import { repoLinks } from "./src/repo-links.mjs";

export default defineConfig({
  site: "https://docs.varlatch.com",
  trailingSlash: "always",
  markdown: { processor: satteri({ mdastPlugins: [repoLinks] }) },
  integrations: [
    starlight({
      title: "Varlatch",
      description: "Run a Varlatch installation, and use it from your machines, CI, and coding agents.",
      logo: {
        light: "./src/assets/varlatch-mark-on-light.png",
        dark: "./src/assets/varlatch-mark-on-dark.png",
        alt: "",
      },
      favicon: "/brand/favicon-32.png",
      head: [{ tag: "link", attrs: { rel: "apple-touch-icon", href: "/brand/apple-touch-icon.png" } }],
      social: [{ icon: "github", label: "GitHub", href: "https://github.com/varlatch/varlatch" }],
      customCss: ["@fontsource-variable/inter", "@fontsource-variable/jetbrains-mono", "./src/styles/theme.css"],
      sidebar: [
        { label: "Start here", items: ["getting-started", "concepts"] },
        {
          label: "Self-hosting",
          items: [
            "self-hosting/requirements",
            "self-hosting",
            "self-hosting/configuration",
            { label: "Backup and recovery", slug: "operations/backup" },
            { label: "First off-host backup (B2)", slug: "operations/backup-b2" },
            { label: "Moving to another address", slug: "operations/move-installation" },
            { label: "Verifying a release", slug: "operations/verify-release" },
          ],
        },
        {
          label: "Contracts",
          items: [
            { label: "The .env.schema file", slug: "reference/env-schema" },
            { label: "Contract semantics", slug: "reference/contract-semantics" },
            { label: "Importing a .env file", slug: "reference/import" },
            { label: "Type generation", slug: "reference/type-generation" },
            { label: "Strict startup", slug: "reference/strict-startup" },
          ],
        },
        {
          label: "Coding agents",
          items: [
            { label: "Skill and agent files", slug: "reference/coding-agents" },
            { label: "Assisted mode", slug: "reference/assisted-mode" },
            { label: "Agent-safe runs", slug: "reference/agent-safe-runs" },
            { label: "MCP server", slug: "reference/mcp" },
            { label: "Output redaction", slug: "reference/output-redaction" },
            { label: "Secret scanning", slug: "reference/secret-scanning" },
          ],
        },
        { label: "CLI", items: [{ label: "Scripting the CLI", slug: "reference/scripting" }] },
        { label: "Security", items: [{ label: "Threat model", slug: "threat-model" }] },
        { label: "Changelog", link: "/changelog/" },
      ],
    }),
  ],
});
