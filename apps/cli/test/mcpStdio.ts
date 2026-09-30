// SPDX-License-Identifier: Apache-2.0
import { spawn, type ChildProcess } from "node:child_process";

/**
 * A minimal MCP client over stdio for tests: newline-delimited JSON-RPC,
 * initialize then requests. It keeps the CLI free of a client dependency and
 * speaks the protocol as any MCP host does.
 */
export class McpStdio {
  private nextId = 1;
  private buffer = "";
  private readonly pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  stderr = "";
  serverInfo: { name: string; version: string } | null = null;

  private constructor(private readonly child: ChildProcess) {
    child.stdout!.setEncoding("utf8");
    child.stdout!.on("data", (chunk: string) => {
      this.buffer += chunk;
      let newline: number;
      while ((newline = this.buffer.indexOf("\n")) >= 0) {
        const line = this.buffer.slice(0, newline).trim();
        this.buffer = this.buffer.slice(newline + 1);
        if (!line) continue;
        const message = JSON.parse(line) as { id?: number; result?: unknown; error?: { message: string } };
        const waiter = message.id !== undefined ? this.pending.get(message.id) : undefined;
        if (!waiter) continue;
        this.pending.delete(message.id!);
        if (message.error) waiter.reject(new Error(message.error.message));
        else waiter.resolve(message.result);
      }
    });
    child.stderr!.on("data", (d: Buffer) => (this.stderr += d.toString()));
    child.on("exit", (code) => {
      for (const waiter of this.pending.values()) waiter.reject(new Error(`the server exited (${code}): ${this.stderr}`));
      this.pending.clear();
    });
  }

  static async start(command: string, args: string[], env: NodeJS.ProcessEnv, cwd: string): Promise<McpStdio> {
    const client = new McpStdio(spawn(command, args, { env, cwd, stdio: ["pipe", "pipe", "pipe"] }));
    const init = (await client.request("initialize", {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "mcp-e2e", version: "0" },
    })) as { serverInfo: { name: string; version: string } };
    client.serverInfo = init.serverInfo;
    client.child.stdin!.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    return client;
  }

  request(method: string, params?: unknown): Promise<unknown> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.child.stdin!.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, ...(params !== undefined ? { params } : {}) })}\n`);
    });
  }

  async listTools(): Promise<string[]> {
    const result = (await this.request("tools/list")) as { tools: { name: string }[] };
    return result.tools.map((t) => t.name).sort();
  }

  /** A tool's result, or the protocol error (an unknown tool) as `{ protocolError }`. */
  async callTool(name: string, args: Record<string, unknown>): Promise<{ isError?: boolean; text: string; protocolError?: string }> {
    try {
      const result = (await this.request("tools/call", { name, arguments: args })) as { isError?: boolean; content: { text: string }[] };
      return { isError: result.isError, text: result.content[0]?.text ?? "" };
    } catch (err) {
      return { isError: true, text: "", protocolError: (err as Error).message };
    }
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      if (this.child.exitCode !== null) return resolve();
      this.child.once("exit", () => resolve());
      this.child.stdin!.end();
      this.child.kill();
    });
  }
}
