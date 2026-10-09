// SPDX-License-Identifier: AGPL-3.0-or-later
import { constants } from "node:crypto";
import https from "node:https";
import type { AddressInfo } from "node:net";
import type { TLSSocket } from "node:tls";
import { serve, type ServerType } from "@hono/node-server";
import { getConnInfo } from "@hono/node-server/conninfo";
import type { Context } from "hono";
import type { NodeCertificate } from "./cert.js";
import { resolveWhois, type WhoisResult } from "./whois.js";

/**
 * The tailnet listeners' device check (ADR-0014 §7): the accepted socket's
 * own peer address and port, through LocalAPI WhoIs, and nothing the
 * request says. Shared by the plain listener and the browser endpoint.
 */
export function tailnetResolver(config: {
  socketPath: string;
  expectedTailnet: string;
  selfNodeId: () => Promise<string | null>;
}): (c: Context) => Promise<WhoisResult> {
  return async (c) => {
    const info = getConnInfo(c);
    const addr = info.remote.address;
    const port = info.remote.port;
    if (!addr || port === undefined) return { ok: false, reason: "unrecognized" };
    return resolveWhois(config, addr, port);
  };
}

/**
 * The browser endpoint binds loopback only: in the userspace sidecar,
 * tailscaled forwards tailnet connections to 127.0.0.1, and Compose peers
 * cannot reach it there (ADR-0046 spike S2).
 */
export const TAILNET_HTTPS_BIND = "127.0.0.1";

/**
 * Serve the browser endpoint over TLS with the node's certificate (ADR-0046
 * Decision 1). Only the node's own name is served: a handshake for another
 * name, without a name (SNI), or while no valid certificate is loaded is
 * refused. TLS terminates here, in the process that reads the socket peer,
 * so the device check sees exactly what the plain listener sees.
 *
 * Sessions are never resumed. Node runs SNICallback when OpenSSL picks a
 * certificate, which a resumed handshake skips, so a resumed session would
 * skip the name and validity checks too. Every connection makes a full
 * handshake, and one that somehow resumed, or completed without a valid
 * certificate loaded, is closed before a request is read.
 */
export function serveTailnetHttps(
  opts: {
    fetch: Parameters<typeof serve>[0]["fetch"];
    host: string;
    port: number;
    certificate: NodeCertificate;
    bind?: string;
  },
  onListening?: (info: AddressInfo) => void,
): ServerType {
  const server = serve(
    {
      fetch: opts.fetch,
      port: opts.port,
      hostname: opts.bind ?? TAILNET_HTTPS_BIND,
      createServer: https.createServer,
      serverOptions: {
        minVersion: "TLSv1.2",
        // No stateless tickets (TLS 1.2), and TLS 1.3 tickets become
        // stateful, which nothing stores: no session can be resumed.
        secureOptions: constants.SSL_OP_NO_TICKET,
        SNICallback: (servername, cb) => {
          if (servername.toLowerCase() !== opts.host) return cb(new Error("unknown server name"));
          const context = opts.certificate.context();
          if (!context) return cb(new Error("no valid certificate"));
          cb(null, context);
        },
      },
    },
    onListening,
  );
  // Before the HTTP parser sees any byte of this connection.
  server.prependListener("secureConnection", (socket: TLSSocket) => {
    if (socket.isSessionReused() || !opts.certificate.context()) socket.destroy();
  });
  return server;
}
