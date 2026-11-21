// SPDX-License-Identifier: Apache-2.0

/**
 * What a fixture that did not start was doing at the last probe: its exit
 * when seen; still running only when the process is (checked, not assumed
 * from an exit not yet seen), and then for how long it did not answer;
 * else gone, its exit not seen.
 */
export function fixtureStatus(exit, running, waitedMs) {
  if (exit) return exit;
  if (running) return `still running after ${waitedMs / 1000} s, its last probe not answered`;
  return "no longer running, its exit not seen";
}
