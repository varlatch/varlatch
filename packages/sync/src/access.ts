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

/** The request never got an answer: DNS, TLS, a refused redirect, a timeout. */
export function unreachable(host: string, err: unknown, where: AccessCheckWhere): AccessCheck {
  if (err instanceof AdapterError && err.message === "TimeoutError") {
    return { status: "unreachable", where, message: `${host} did not answer in time. Try again in a moment.` };
  }
  return {
    status: "unreachable",
    where,
    message: `Varlatch could not reach ${host}. Check the address, and that this server can reach it.`,
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
