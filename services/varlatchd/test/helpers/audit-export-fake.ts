// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The audit export parity fixtures' destination (go-audit-export-fixture
 * and go-audit-export-worker-fixture): a local S3 server with Object Lock
 * (FakeS3; s3fake in Go, the same behaviour by access key and bucket)
 * under one fixed endpoint, http://s3.fixture.test, which the outbound
 * policy allows and connects to it.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { BucketDestination, StorageClient, StorageCredentials } from "@varlatch/backup/s3";
import { OutboundPolicy, type OutboundPurpose, type Resolver } from "../../src/net/outbound.js";

/** The destination's fixed endpoint, and the allow list and resolver that open it. */
export const ENDPOINT = "http://s3.fixture.test";
export const ALLOW = "s3.fixture.test,127.0.0.1/32:*";
const RESOLVE: Record<string, { address: string; family: 4 | 6 }[]> = { "s3.fixture.test": [{ address: "10.9.9.9", family: 4 }] };
const resolve: Resolver = async (name) => {
  const a = RESOLVE[name];
  if (!a) throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${name}`), { code: "ENOTFOUND" });
  return a;
};

// The fake's keys and buckets (go/server/auditexport/s3fake).
export const KEY_GOOD = "AKIAFIXTUREGOOD";
export const KEY_NO_READ = "AKIAFIXTURENOREAD";
export const BUCKET = "export-bucket";

/** What the server keeps of an upload. */
export interface FakeObject {
  body: Buffer;
  sha256: string;
  contentType: string;
  mode: string;
  until: string;
}

/**
 * A local S3 server with Object Lock, path style: the requests the probe
 * and the worker make, answered by access key and bucket as s3fake answers
 * them. It records each request, keeps what it is given, can be taken down
 * (every request answers 503) and can hold an object nobody uploaded.
 */
export class FakeS3 {
  readonly objects = new Map<string, FakeObject>();
  readonly requests: string[] = [];
  /** The names (bucket/key) of the uploads it kept, in order. */
  readonly uploads: string[] = [];
  down = false;
  private server: Server | null = null;
  url = "";

  async start(): Promise<void> {
    this.server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => this.serve(req, res, Buffer.concat(chunks)));
    });
    await new Promise<void>((r) => this.server!.listen(0, "127.0.0.1", r));
    this.url = `http://127.0.0.1:${(this.server!.address() as AddressInfo).port}`;
  }

  async stop(): Promise<void> {
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
  }

  /** Keep an object under bucket/key as if it had been uploaded. */
  plant(bucket: string, key: string, o: Partial<FakeObject> & { body: Buffer }): void {
    this.objects.set(`${bucket}/${key}`, { sha256: "", contentType: "", mode: "", until: "", ...o });
  }

  private fail(req: IncomingMessage, res: ServerResponse, status: number, code: string): number {
    if (req.method === "HEAD") {
      res.writeHead(status).end();
      return status;
    }
    res.writeHead(status, { "content-type": "application/xml" });
    res.end(`<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>${code}</Code><Message>${code}</Message></Error>`);
    return status;
  }

  private serve(req: IncomingMessage, res: ServerResponse, body: Buffer): void {
    const url = new URL(req.url ?? "/", "http://fake");
    const [bucket = "", ...rest] = url.pathname.slice(1).split("/");
    const key = decodeURIComponent(rest.join("/"));
    const access = /Credential=([^/]+)\//.exec(req.headers.authorization ?? "")?.[1] ?? "";
    const retention = url.searchParams.has("retention");
    const status = this.answer(req, res, bucket, key, access, retention, body);
    this.requests.push(`${req.method}${retention ? " retention" : ""} ${access} ${status}`);
  }

  private answer(req: IncomingMessage, res: ServerResponse, bucket: string, key: string, access: string, retention: boolean, body: Buffer): number {
    if (this.down) return this.fail(req, res, 503, "ServiceUnavailable");
    if (![KEY_GOOD, KEY_NO_READ, "AKIAFIXTURENORETENTION"].includes(access)) return this.fail(req, res, 403, "InvalidAccessKeyId");
    if (!["export-bucket", "overwrite-bucket", "nometa-bucket", "nolock-bucket", "weak-bucket"].includes(bucket)) return this.fail(req, res, 404, "NoSuchBucket");
    const name = `${bucket}/${key}`;
    const h = (n: string) => (req.headers[n] as string | undefined) ?? "";
    if (req.method === "PUT") {
      if (this.objects.has(name) && h("if-none-match") === "*" && bucket !== "overwrite-bucket") return this.fail(req, res, 412, "PreconditionFailed");
      const o: FakeObject = { body, sha256: h("x-amz-meta-sha256"), contentType: h("content-type"), mode: h("x-amz-object-lock-mode"), until: h("x-amz-object-lock-retain-until-date") };
      if (bucket === "nometa-bucket") o.sha256 = "";
      if (bucket === "nolock-bucket") [o.mode, o.until] = ["", ""];
      if (bucket === "weak-bucket" && o.mode) o.mode = "GOVERNANCE";
      this.objects.set(name, o);
      this.uploads.push(name);
      res.writeHead(200, { etag: '"fixture"' }).end();
      return 200;
    }
    if (req.method === "HEAD") {
      if (access === KEY_NO_READ) return this.fail(req, res, 403, "AccessDenied");
      const o = this.objects.get(name);
      if (!o) return this.fail(req, res, 404, "NotFound");
      res.writeHead(200, { ...(o.sha256 ? { "x-amz-meta-sha256": o.sha256 } : {}), "content-length": "0", "last-modified": new Date(0).toUTCString() }).end();
      return 200;
    }
    if (req.method === "GET" && retention) {
      if (access === KEY_NO_READ || access === "AKIAFIXTURENORETENTION") return this.fail(req, res, 403, "AccessDenied");
      const o = this.objects.get(name);
      if (!o) return this.fail(req, res, 404, "NoSuchKey");
      if (!o.mode) return this.fail(req, res, 404, "NoSuchObjectLockConfiguration");
      res.writeHead(200, { "content-type": "application/xml" });
      res.end(`<?xml version="1.0" encoding="UTF-8"?>\n<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>${o.mode}</Mode><RetainUntilDate>${o.until}</RetainUntilDate></Retention>`);
      return 200;
    }
    return this.fail(req, res, 405, "MethodNotAllowed");
  }
}

/** The outbound policy with the fixed endpoint connected to the fake. */
export class FixturePolicy extends OutboundPolicy {
  constructor(private readonly fake: FakeS3) {
    super(ALLOW, { resolve, log: () => {} });
  }
  override storageClient(purpose: OutboundPurpose, destination: BucketDestination, credentials: StorageCredentials, requestTimeoutMs: number): StorageClient {
    const endpoint = destination.endpoint === ENDPOINT ? this.fake.url : destination.endpoint;
    return super.storageClient(purpose, { ...destination, endpoint }, credentials, requestTimeoutMs);
  }
}
