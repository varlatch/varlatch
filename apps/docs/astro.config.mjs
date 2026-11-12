// SPDX-License-Identifier: Apache-2.0
// docs.varlatch.com: the repository's documentation as a static site
// (Starlight). The pages are copied in from docs/ and the files listed in
// src/sources.mjs before every build; edit them there, not here.
import { satteri } from "@astrojs/markdown-satteri";
import starlight from "@astrojs/starlight";
import { defineConfig } from "astro/config";
import { movedAnchorsScript } from "./src/moved-anchors.mjs";
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
      head: [
        { tag: "link", attrs: { rel: "apple-touch-icon", href: "/brand/apple-touch-icon.png" } },
        { tag: "script", content: movedAnchorsScript() },
      ],
      social: [{ icon: "github", label: "GitHub", href: "https://github.com/varlatch/varlatch" }],
      components: { SocialIcons: "./src/components/SocialIcons.astro" },
      customCss: ["@fontsource-variable/inter", "@fontsource-variable/jetbrains-mono", "./src/styles/theme.css"],
      sidebar: [
        {
          label: "Start here",
          items: ["getting-started", "join-a-team", "set-up-a-project", "run-an-installation", "set-up-with-an-agent", "concepts"],
        },
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
        {
          label: "Using Varlatch",
          items: [
            { label: "Install the CLI", slug: "reference/install-the-cli" },
            { label: "Members and access", slug: "reference/members" },
            { label: "Passkeys and sessions", slug: "reference/passkeys-and-sessions" },
            { label: "CI and other machines", slug: "reference/ci-and-machines" },
            { label: "Scripting the CLI", slug: "reference/scripting" },
            { label: "Removing Varlatch", slug: "reference/uninstall" },
          ],
        },
        {
          label: "Security",
          items: [
            { label: "Security controls", slug: "reference/security-controls" },
            { label: "Incident freeze", slug: "reference/incident-freeze" },
            { label: "Outbound policy", slug: "reference/outbound-policy" },
            { label: "Threat model", slug: "threat-model" },
          ],
        },
        { label: "Changelog", link: "/changelog/" },
      ],
    }),
  ],
});
