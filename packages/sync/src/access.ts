// SPDX-License-Identifier: Apache-2.0
import { AdapterError } from "./types.js";

/**
 * The outcome of a read-only access check (ADR-0031, amendment 2026-10-09):
 * whether a credential reaches a base identity, or one destination on it,
 * before anything is saved or pushed.
 *
 * - `credential-rejected`: the platform does not accept the credential.
 * - `permission-missing`: it accepts the credential, but not for this.
 * - `not-found`: the owner, repository, environment, application or
 *   deployment does not exist, or the credential cannot see it.
 * - `unreachable`: no usable answer (network, timeout, rate limit, 5xx);
 *   trying again later may work.
 * - `failed`: any other refusal.
 */
export type AccessCheckStatus =
  | "ok"
  | "credential-rejected"
  | "permission-missing"
  | "not-found"
  | "unreachable"
  | "failed";

/** What an outcome is about: the credential and base identity, or the destination. */
export type AccessCheckWhere = "connection" | "destination";

export interface AccessCheck {
  status: AccessCheckStatus;
  where: AccessCheckWhere;
  /**
   * One sentence for the person who fixes it, written by Varlatch: never
   * platform response text, a value, or credential material.
   */
  message: string;
  /** The platform's HTTP status, when it answered. */
  httpStatus?: number;
}

/** Node's fetch reports the transport problem on the cause of its TypeError. */
function transportProblem(err: unknown): "timeout" | "redirect" | "dns" | "refused" | "tls" | null {
  if (!(err instanceof AdapterError)) return null;
  if (err.message === "TimeoutError") return "timeout";
  const cause = (err.cause as { cause?: { code?: unknown; message?: unknown } } | undefined)?.cause;
  const code = typeof cause?.code === "string" ? cause.code : "";
  if (typeof cause?.message === "string" && /redirect/i.test(cause.message)) return "redirect";
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") return "dns";
  if (code === "ECONNREFUSED") return "refused";
  if (/CERT|SELF_SIGNED|SIGNATURE|TLS|SSL/.test(code)) return "tls";
  return null;
}

/** The request never got an answer: DNS, TLS, a refused redirect, a timeout. */
export function unreachable(host: string, err: unknown, where: AccessCheckWhere): AccessCheck {
  const problem = transportProblem(err);
  const messages = {
    timeout: `${host} did not answer in time. Try again in a moment.`,
    redirect: `${host} answered with a redirect, which Varlatch does not follow. Enter the address it leads to, or let Varlatch past a sign-in page in front of it.`,
    dns: `No address was found for ${host}. Check the spelling, and that this server can resolve it.`,
    refused: `${host} refused the connection. Check the address and port.`,
    tls: `This server does not trust the certificate of ${host}: it is self-signed, expired, or made for another name.`,
  };
  return {
    status: "unreachable",
    where,
    message: problem
      ? messages[problem]
      : `Varlatch could not reach ${host}. Check the address, and that this server can reach it.`,
  };
}

/** An answer the adapter has no specific reading for. */
export function unexpected(platform: string, status: number, where: AccessCheckWhere): AccessCheck {
  if (status === 429) {
    return {
      status: "unreachable",
      where,
      httpStatus: status,
      message: `${platform} is limiting requests right now. Try again in a few minutes.`,
    };
  }
  if (status >= 500) {
    return {
      status: "unreachable",
      where,
      httpStatus: status,
      message: `${platform} answered with a server error (HTTP ${status}). Try again later.`,
    };
  }
  return { status: "failed", where, httpStatus: status, message: `${platform} refused the request (HTTP ${status}).` };
}

/**
 * An answer at a user-supplied base address that is not the platform's API
 * (a 410 from another site, a 405 from a proxy): the address is wrong more
 * often than the platform is.
 */
export function foreign(platform: string, kind: string, host: string, status: number): AccessCheck {
  if (status === 429 || status >= 500) return unexpected(platform, status, "connection");
  return {
    status: "failed",
    where: "connection",
    httpStatus: status,
    message: `${host} does not answer like a ${platform} ${kind} (HTTP ${status}). Check the address.`,
  };
}
