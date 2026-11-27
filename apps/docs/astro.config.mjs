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
          items: [
            { label: "How Varlatch works", slug: "overview" },
            { label: "Choose your path", slug: "getting-started" },
            { label: "Join a team", slug: "join-a-team" },
            { label: "Connect a project", slug: "set-up-a-project" },
            { label: "Set up with a coding agent", slug: "set-up-with-an-agent" },
          ],
        },
        {
          label: "Self-hosting",
          items: [
            { label: "Install Varlatch", slug: "self-hosting" },
            { label: "Docker and Coolify", slug: "self-hosting/docker-and-coolify" },
            { label: "Operate and recover", slug: "self-hosting/operate" },
            { label: "Host requirements", slug: "self-hosting/requirements" },
            { label: "Configuration", slug: "self-hosting/configuration" },
            { label: "Self-hosted tailnet (Headscale)", slug: "self-hosting/self-hosted-tailnet-control" },
            { label: "Backup and recovery", slug: "operations/backup" },
            { label: "Off-host backup with B2", slug: "operations/backup-b2" },
            { label: "Upgrading", slug: "operations/upgrade" },
            { label: "Moving to another address", slug: "operations/move-installation" },
            { label: "Verifying a release", slug: "operations/verify-release" },
          ],
        },
        {
          label: "Using Varlatch",
          items: [
            { label: "Install the CLI", slug: "reference/install-the-cli" },
            { label: "Members and access", slug: "reference/members" },
            { label: "Passkeys and sessions", slug: "reference/passkeys-and-sessions" },
            { label: "CI and other machines", slug: "reference/ci-and-machines" },
            { label: "One-time codes", slug: "reference/one-time-codes" },
            { label: "Pages, applications and pipes", slug: "reference/typed-destinations" },
            { label: "Entry links", slug: "reference/entry-links" },
            {
              label: "OAuth connections",
              items: [
                { label: "OAuth connections", slug: "reference/oauth-connections" },
                { label: "Google", slug: "reference/oauth-google" },
                { label: "Microsoft", slug: "reference/oauth-microsoft" },
                { label: "Another provider", slug: "reference/oauth-generic" },
              ],
            },
            { label: "Integrations (GitHub, Coolify, Convex)", slug: "reference/integrations" },
            { label: "Checking sync drift", slug: "reference/sync-check" },
            { label: "Scripting the CLI", slug: "reference/scripting" },
            { label: "Removing Varlatch", slug: "reference/uninstall" },
          ],
        },
        {
          label: "Contracts",
          items: [
            { label: "The .env.schema file", slug: "reference/env-schema" },
            { label: "Importing a .env file", slug: "reference/import" },
            { label: "Type generation", slug: "reference/type-generation" },
            { label: "Strict startup", slug: "reference/strict-startup" },
            { label: "Contract semantics", slug: "reference/contract-semantics" },
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
          label: "Security",
          items: [
            { label: "Security controls", slug: "reference/security-controls" },
            { label: "Incident freeze", slug: "reference/incident-freeze" },
            { label: "Audit export", slug: "reference/audit-export" },
            { label: "Outbound policy", slug: "reference/outbound-policy" },
            { label: "Threat model", slug: "threat-model" },
          ],
        },
        {
          label: "Reference & legacy",
          collapsed: true,
          items: [
            { label: "Glossary", slug: "concepts" },
            { label: "Migrating from 0.23.x to 0.50", slug: "operations/migrate-to-0.50" },
            { label: "Docker Compose (0.23.x legacy)", slug: "self-hosting/compose" },
            { label: "Changelog", link: "/changelog/" },
          ],
        },
      ],
    }),
  ],
});
