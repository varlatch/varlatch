// SPDX-License-Identifier: Apache-2.0
import { createInterface, type Interface } from "node:readline";

/**
 * Questions on a terminal (ADR-0058 Decision 2): a choice from a list, a
 * yes/no, and a line of text. One readline interface for a whole guided
 * run; tests pass their own input and output streams. Never for a secret
 * value: secretInput.ts's hidden prompt is the only way to type one.
 */
export interface Prompter {
  /** The index of the chosen option; `preselected` answers an empty line. */
  select(question: string, options: string[], preselected?: number): Promise<number>;
  confirm(question: string, defaultYes: boolean): Promise<boolean>;
  text(question: string, defaultValue?: string): Promise<string>;
  /** A line of output between questions. */
  say(line: string): void;
  /** Stops reading the input while a child process uses the terminal; resume() reads again. */
  pause(): void;
  resume(): void;
  close(): void;
}

export function terminalPrompter(input: NodeJS.ReadableStream = process.stdin, output: NodeJS.WritableStream = process.stdout): Prompter {
  const rl: Interface = createInterface({ input, output, terminal: false });
  // Lines typed ahead of a question wait here instead of being dropped.
  const lines: string[] = [];
  const waiting: ((line: string | null) => void)[] = [];
  let ended = false;
  rl.on("line", (line) => {
    const next = waiting.shift();
    if (next) next(line);
    else lines.push(line);
  });
  rl.on("close", () => {
    ended = true;
    for (const next of waiting.splice(0)) next(null);
  });
  const ask = async (question: string): Promise<string> => {
    output.write(question);
    const line = lines.length > 0 ? (lines.shift() as string) : ended ? null : await new Promise<string | null>((resolve) => waiting.push(resolve));
    if (line === null) throw new Error("the input ended before an answer");
    return line.trim();
  };
  return {
    async select(question, options, preselected = 0) {
      for (;;) {
        output.write(`${question}\n`);
        options.forEach((option, i) => output.write(`  [${i + 1}] ${option}${i === preselected ? "  (Enter)" : ""}\n`));
        const answer = await ask("Choice: ");
        if (answer === "") return preselected;
        const n = Number(answer);
        if (Number.isInteger(n) && n >= 1 && n <= options.length) return n - 1;
        output.write(`Answer with a number from 1 to ${options.length}.\n`);
      }
    },
    async confirm(question, defaultYes) {
      for (;;) {
        const answer = (await ask(`${question} ${defaultYes ? "[Y/n]" : "[y/N]"} `)).toLowerCase();
        if (answer === "") return defaultYes;
        if (answer === "y" || answer === "yes") return true;
        if (answer === "n" || answer === "no") return false;
        output.write("Answer y or n.\n");
      }
    },
    async text(question, defaultValue) {
      const answer = await ask(defaultValue ? `${question} [${defaultValue}]: ` : `${question}: `);
      return answer === "" ? (defaultValue ?? "") : answer;
    },
    say(line) {
      output.write(`${line}\n`);
    },
    pause() {
      rl.pause();
    },
    resume() {
      rl.resume();
    },
    close() {
      rl.close();
    },
  };
}
