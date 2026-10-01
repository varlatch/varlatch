// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
// @ts-expect-error: a plain ES module script without type declarations
import { collectSkillFiles, renderModule } from "../scripts/embed-skill.mjs";
import { agentsBlock } from "../src/agents/install.js";
import { GUIDE_TOPICS, GuideTopicError, guide, skillFiles } from "../src/agents/skill.js";
import { SKILL_FILES } from "../src/agents/skillFiles.generated.js";
import { commandHelp } from "../src/usage.js";

/**
 * The agent skill (ADR-0043 Decision 7): the embedded copy matches the
 * source, the frontmatter uses only the Agent Skills specification's
 * fields, every command a coding agent is told to run starts with
 * `varlatch --assisted` and names only options the CLI has, and the text
 * names no coding agent or agent-specific tool. Each lint has a control:
 * the same skill with the rule broken must be reported.
 */

const SPEC_FIELDS = ["name", "description", "license", "compatibility", "metadata", "allowed-tools"];

function frontmatter(content: string): Record<string, unknown> {
  const match = /^---\n([\s\S]*?)\n---\n/.exec(content);
  if (!match) throw new Error("no frontmatter");
  return parseYaml(match[1] as string) as Record<string, unknown>;
}

interface Command {
  file: string;
  text: string;
  /** In a ```sh block or an inline span: a command the coding agent runs. A ```text block holds the human's. */
  agent: boolean;
  inline: boolean;
}

/** Every Varlatch command line in the skill's Markdown: fenced blocks by language, and inline code spans. */
function commands(files: Record<string, string>): Command[] {
  const out: Command[] = [];
  for (const [file, content] of Object.entries(files)) {
    const fence = /^```(\w*)\n([\s\S]*?)^```$/gm;
    let prose = content;
    for (const m of content.matchAll(fence)) {
      prose = prose.replace(m[0], "");
      for (const line of (m[2] as string).split("\n")) {
        // A command after a pipe is a command too: `... | varlatch --assisted values set X --stdin`.
        const at = line.search(/(^|\|\s*)varlatch\b/);
        if (at < 0) continue;
        out.push({ file, text: line.slice(line.indexOf("varlatch", at)).trim(), agent: m[1] !== "text", inline: false });
      }
    }
    for (const m of prose.matchAll(/`(varlatch\b[^`]*)`/g)) out.push({ file, text: m[1] as string, agent: true, inline: true });
  }
  return out;
}

/** Commands a coding agent runs that do not start with `varlatch --assisted`. */
function missingAssisted(files: Record<string, string>): string[] {
  return commands(files)
    .filter((c) => c.agent && !c.text.startsWith("varlatch --assisted"))
    // An inline span that only names a command (`varlatch request`) is prose, not a command to run.
    .filter((c) => !(c.inline && c.text.split(/\s+/).length <= 2))
    .map((c) => `${c.file}: ${c.text}`);
}

/** Commands whose command word or options the CLI's usage does not have. */
function unknownOptions(files: Record<string, string>): string[] {
  const problems: string[] = [];
  for (const c of commands(files)) {
    const words = c.text.split(/\s+/).slice(1);
    if (words[0] === "--assisted") words.shift();
    const command = words[0];
    if (!command || command.startsWith("<")) continue;
    const help = commandHelp(command);
    if (help === null) {
      problems.push(`${c.file}: ${c.text}: no command ${command}`);
      continue;
    }
    const own = words.includes("--") ? words.slice(0, words.indexOf("--")) : words;
    for (const word of own) {
      if (!/^--?[a-z]/i.test(word)) continue;
      const option = word.split("=")[0] as string;
      const escaped = option.replace(/[-]/g, "\\-");
      if (!new RegExp(`(^|[\\s\\[(|])${escaped}(?=[\\s\\]|)<=]|$)`, "m").test(help)) problems.push(`${c.file}: ${c.text}: ${command} has no ${option}`);
    }
  }
  return problems;
}

const AGENT_SPECIFIC = /\b(claude|codex|cursor|copilot|gemini|subagents?|sub-agents?|slash commands?|run_in_background|todowrite|(bash|read|edit|write|shell) tool)\b/i;

function agentSpecific(files: Record<string, string>): string[] {
  return Object.entries(files).flatMap(([file, content]) =>
    content
      .split("\n")
      .filter((line) => AGENT_SPECIFIC.test(line))
      .map((line) => `${file}: ${line.trim()}`),
  );
}

function emDashes(files: Record<string, string>): string[] {
  return Object.entries(files).flatMap(([file, content]) => (/[–—]/.test(content) ? [file] : []));
}

describe("the embedded skill", () => {
  it("matches its source: pnpm --filter @varlatch/cli embed-skill regenerates it", () => {
    const generated = readFileSync(fileURLToPath(new URL("../src/agents/skillFiles.generated.ts", import.meta.url)), "utf8");
    expect(generated, "stale: run pnpm --filter @varlatch/cli embed-skill").toBe(renderModule(collectSkillFiles()));
    // Control: an edited source no longer matches.
    const edited = { ...collectSkillFiles(), "SKILL.md": `${collectSkillFiles()["SKILL.md"]}\nedited\n` };
    expect(renderModule(edited)).not.toBe(generated);
  });

  it("has only the Agent Skills specification's frontmatter fields, within its limits", () => {
    const meta = frontmatter(SKILL_FILES["SKILL.md"] as string);
    expect(Object.keys(meta).filter((key) => !SPEC_FIELDS.includes(key))).toEqual([]);
    expect(meta.name).toBe("varlatch");
    expect(meta.name).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*$/);
    expect(typeof meta.description).toBe("string");
    expect((meta.description as string).length).toBeGreaterThan(0);
    expect((meta.description as string).length).toBeLessThanOrEqual(1024);
    expect(meta.metadata).toEqual({ generator: "varlatch {{VERSION}}" });
  });

  it("names the CLI version that generated it, in fields the specification allows", () => {
    const files = skillFiles("9.8.7");
    const skill = files.get("SKILL.md") as string;
    expect(skill).not.toContain("{{VERSION}}");
    expect(frontmatter(skill).metadata).toEqual({ generator: "varlatch 9.8.7" });
    for (const [path, content] of files) {
      if (path !== "SKILL.md") expect(content.split("\n")[0], path).toMatch(/^<!-- Generated by varlatch 9\.8\.7: .*-->$/);
    }
    expect([...files.keys()].sort()).toEqual(Object.keys(SKILL_FILES).sort());
  });

  it("links every reference, and every reference is a guide topic", () => {
    const references = Object.keys(SKILL_FILES).filter((path) => path !== "SKILL.md");
    expect(references.length).toBeGreaterThan(0);
    for (const path of references) expect(SKILL_FILES["SKILL.md"], path).toContain(`\`${path}\``);
    expect(Object.values(GUIDE_TOPICS).sort()).toEqual(references.sort());
  });

  it("starts every command a coding agent runs with varlatch --assisted", () => {
    expect(commands(SKILL_FILES).filter((c) => c.agent).length).toBeGreaterThan(20);
    expect(missingAssisted(SKILL_FILES)).toEqual([]);
    expect(missingAssisted({ "AGENTS.md": agentsBlock() })).toEqual([]);
  });

  it("control: the same skill with --assisted dropped is reported, in blocks and inline", () => {
    const stripped = Object.fromEntries(Object.entries(SKILL_FILES).map(([p, c]) => [p, c.replaceAll("varlatch --assisted ", "varlatch ")]));
    const found = missingAssisted(stripped);
    expect(found).toContain("SKILL.md: varlatch run -- npm test");
    expect(found).toContain("SKILL.md: varlatch import <file> --dry-run");
    expect(found).toContain("references/run.md: varlatch values set API_KEY --stdin");
    expect(missingAssisted({ "AGENTS.md": agentsBlock().replaceAll("varlatch --assisted ", "varlatch ") }).length).toBeGreaterThan(0);
  });

  it("uses only commands and options the CLI has, in the agent's commands and the human's", () => {
    expect(commands(SKILL_FILES).filter((c) => !c.agent).length).toBeGreaterThan(3);
    expect(unknownOptions(SKILL_FILES)).toEqual([]);
    expect(unknownOptions({ "AGENTS.md": agentsBlock() })).toEqual([]);
  });

  it("control: an option or command the CLI does not have is reported", () => {
    const broken = {
      ...SKILL_FILES,
      "SKILL.md": (SKILL_FILES["SKILL.md"] as string)
        .replace("varlatch --assisted run -- npm test", "varlatch --assisted run --unmasked -- npm test")
        .replace("varlatch --assisted context --json", "varlatch --assisted contexts --json"),
    };
    expect(unknownOptions(broken).sort()).toEqual([
      "SKILL.md: varlatch --assisted contexts --json: no command contexts",
      "SKILL.md: varlatch --assisted run --unmasked -- npm test: run has no --unmasked",
    ]);
  });

  it("names no coding agent or agent-specific tool, and has no em dashes", () => {
    expect(agentSpecific(SKILL_FILES)).toEqual([]);
    expect(agentSpecific({ "AGENTS.md": agentsBlock() })).toEqual([]);
    expect(emDashes(SKILL_FILES)).toEqual([]);
    expect(emDashes({ "AGENTS.md": agentsBlock() })).toEqual([]);
    // Controls: the same lints on text that breaks them.
    expect(agentSpecific({ "x.md": "Use the Bash tool, or ask a subagent." })).toHaveLength(1);
    expect(emDashes({ "x.md": "one — two" })).toEqual(["x.md"]);
  });
});

describe("varlatch agents guide", () => {
  it("prints the skill without its frontmatter, then the topics", () => {
    const text = guide(undefined);
    expect(text.startsWith("# Varlatch\n")).toBe(true);
    expect(text).not.toContain("{{VERSION}}");
    expect(text).not.toMatch(/^---$/m);
    expect(text.trimEnd().split("\n").at(-1)).toBe(`Topics: ${Object.keys(GUIDE_TOPICS).join(", ")} (varlatch --assisted agents guide <topic>)`);
  });

  it("prints one reference per topic, and refuses a topic it does not have", () => {
    for (const [topic, path] of Object.entries(GUIDE_TOPICS)) expect(guide(topic)).toBe(SKILL_FILES[path]);
    expect(() => guide("nosuch")).toThrow(GuideTopicError);
  });
});
