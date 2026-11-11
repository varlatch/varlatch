// SPDX-License-Identifier: AGPL-3.0-or-later
import { setOutboundResolverForTests } from "../../src/net/outbound.js";

/**
 * The outbound policy's one resolver injection point (ADR-0057 Decision 9),
 * set for every test file: no test depends on the machine's DNS. localhost
 * is loopback, as on any host; every other name resolves to one public
 * address. Tests about resolution build a policy with a resolver of their own.
 */
export const TEST_PUBLIC_ADDRESS = "93.184.215.14";

setOutboundResolverForTests(async (name) => {
  if (name === "localhost") return [{ address: "127.0.0.1", family: 4 }, { address: "::1", family: 6 }];
  return [{ address: TEST_PUBLIC_ADDRESS, family: 4 }];
});
