// SPDX-License-Identifier: AGPL-3.0-or-later
import { Badge } from "../../components/ui";
import { WITHOUT_TLS, placeLabel, withoutTLS } from "./places";

/** Where a Capability's values may go; a page without TLS with a warning. */
export function Destinations({ destinations, nameOf }: { destinations: string[]; nameOf: (identityId: string) => string }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5 font-mono text-[12.5px] text-muted">
      → {destinations.map((d) => placeLabel(d, nameOf)).join(", ")}
      {destinations.some(withoutTLS) && (
        <Badge tone="warn" className="font-sans" title={WITHOUT_TLS} aria-label={WITHOUT_TLS} data-testid="destination-without-tls">
          http: not encrypted
        </Badge>
      )}
    </span>
  );
}
