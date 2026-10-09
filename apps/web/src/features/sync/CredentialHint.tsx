// SPDX-License-Identifier: AGPL-3.0-or-later
import type { SyncPlatform } from "@varlatch/protocol";
import { platformMeta, setupGuideUrl } from "./platform-meta";

/** The platform's credential advice, with a link to its setup guide. */
export function CredentialHint({ platform }: { platform: SyncPlatform }) {
  return (
    <>
      {platformMeta(platform).credentialHelp}{" "}
      <a className="link" href={setupGuideUrl(platform)} target="_blank" rel="noreferrer">
        Setup guide
      </a>
    </>
  );
}
