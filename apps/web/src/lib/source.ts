// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Where the source of this dashboard and its server lives. The AGPL asks
 * anyone who runs a modified version for others to offer those users its
 * source (section 13). If you change Varlatch and run it for other people,
 * point this at your modified source.
 */
export const SOURCE_REPOSITORY = "https://github.com/varlatch/varlatch";

const RELEASE = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;

/** The source of the release the server reports, or the repository when it reports none. */
export function sourceUrl(serverVersion: string | undefined): string {
  return serverVersion && RELEASE.test(serverVersion) ? `${SOURCE_REPOSITORY}/tree/v${serverVersion}` : SOURCE_REPOSITORY;
}
