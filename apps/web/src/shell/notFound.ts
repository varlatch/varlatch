// SPDX-License-Identifier: AGPL-3.0-or-later
import type { UIMatch } from "react-router-dom";

/** The catch-all routes' handle: the shell knows an address without a page by it. */
export const NOT_FOUND = { notFound: true } as const;

/** Whether the matched address has no page. */
export const isNotFound = (matches: Pick<UIMatch, "handle">[]): boolean => matches.some((m) => m.handle === NOT_FOUND);
