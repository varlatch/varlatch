// SPDX-License-Identifier: AGPL-3.0-or-later
import type { DestinationListing, DestinationOption } from "@varlatch/protocol";
import { Button, Callout, Mono, Spinner, cn } from "../../components/ui";
import { AccessCheckNotice } from "./AccessCheckNotice";

/**
 * The destinations a connection's credential can see, under the field that
 * takes one. Picking fills the field; typing still works, for a destination
 * the credential cannot see or that does not exist yet. Either way the
 * Review step checks the destination before anything is created.
 */
export function DestinationPicker({
  noun,
  seenBy = "credential",
  value,
  valueOf,
  listing,
  onPick,
  onRetry,
}: {
  noun: { one: string; many: string };
  /**
   * Whose view the list is: a credential's (what a token can see), or a
   * GitHub App installation's (exactly the repositories it includes).
   */
  seenBy?: "credential" | "installation";
  /** What the field holds now. */
  value: string;
  /** What the field takes for an option (a repository name, an application UUID). */
  valueOf: (option: DestinationOption) => string;
  listing: { pending: boolean; settled: boolean; result: DestinationListing | undefined; error: unknown };
  onPick: (option: DestinationOption) => void;
  onRetry: () => void;
}) {
  const typeInstead = `Type the ${noun.one} instead; Review checks it.`;
  const app = seenBy === "installation";
  const seen = app ? "the App's installation includes" : "this credential can see";
  const retry = (
    <Button size="sm" variant="secondary" data-testid="destination-retry" onClick={onRetry}>
      Try again
    </Button>
  );

  if (listing.error) {
    return (
      <Callout tone="warn" title={`Could not load the ${noun.many}`} actions={retry} data-testid="destination-list" data-status="error">
        {listing.error instanceof Error ? listing.error.message : String(listing.error)} {typeInstead}
      </Callout>
    );
  }
  if (!listing.settled || !listing.result) {
    return (
      <p className="flex items-center gap-2 text-[13px] text-muted" data-testid="destination-list" data-status="pending">
        <Spinner /> Loading the {noun.many} {seen}…
      </p>
    );
  }
  const { check, items, truncated } = listing.result;
  // A truncated listing is partial: Varlatch stopped reading (at 1,000
  // options, or after 30 GitHub pages), so more may exist than it shows.
  if (check.status !== "ok") {
    return (
      <div className="space-y-1.5" data-testid="destination-list" data-status="failed">
        <AccessCheckNotice pending={false} check={check} error={null} actions={retry} />
        <p className="text-xs text-muted">{typeInstead}</p>
      </div>
    );
  }
  if (items.length === 0) {
    // On the platform, one may have been created since: Try again lists anew.
    // Archived repositories are left out, so an App's empty list does not
    // mean its installation includes none.
    return (
      <div className="flex items-center gap-3" data-testid="destination-list" data-status="empty" data-truncated={truncated}>
        <p className="min-w-0 flex-1 text-[13px] text-muted">
          {truncated
            ? `Varlatch stopped reading before it found any ${noun.many} here: the ${app ? "installation includes" : "credential sees"} more than Varlatch reads.`
            : app
              ? `No unarchived ${noun.many} are listed for the App's installation: add one to it on GitHub, or unarchive one there.`
              : `This credential sees no ${noun.many}.`}{" "}
          {typeInstead}
        </p>
        {retry}
      </div>
    );
  }

  const query = value.trim().toLowerCase();
  const picked = items.find((o) => valueOf(o).toLowerCase() === query);
  // Once one is picked, the whole list stays in view to pick another.
  const shown = picked || query === "" ? items : items.filter((o) => matches(o, query));
  return (
    <div className="space-y-1.5" data-testid="destination-list" data-status="ok">
      {shown.length > 0 ? (
        <div role="group" aria-label={`${noun.many} ${seen}`} className="max-h-56 overflow-y-auto rounded-xl border border-bd">
          {shown.map((option) => {
            const optionValue = valueOf(option);
            const selected = option === picked;
            return (
              <button
                key={optionValue}
                type="button"
                aria-pressed={selected}
                data-testid={`destination-option-${optionValue}`}
                onClick={() => onPick(option)}
                className={cn(
                  "flex w-full cursor-pointer items-center gap-3 border-b border-bd px-3 py-2 text-left last:border-b-0 hover:bg-hover",
                  selected && "bg-accent/[0.06]",
                )}
              >
                <Mono className="min-w-0 flex-1 truncate">{option.label}</Mono>
                {option.detail && <span className="shrink-0 truncate text-xs text-muted">{option.detail}</span>}
              </button>
            );
          })}
        </div>
      ) : (
        <p className="text-[13px] text-muted">
          No listed {noun.one} matches <Mono>{value.trim()}</Mono>. Varlatch uses it as typed; Review checks it.
        </p>
      )}
      <div className="flex items-center gap-3">
        <p className="min-w-0 flex-1 text-xs text-muted" data-testid="destination-list-count">
          {shown.length === items.length ? `${items.length}` : `${shown.length} of ${items.length}`} {noun.many} {seen}
          {truncated ? ", a partial list: Varlatch stopped reading early" : ""}. Not listed? Type it; Review checks it.
        </p>
        <Button size="sm" variant="ghost" data-testid="destination-retry" onClick={onRetry}>
          Reload list
        </Button>
      </div>
    </div>
  );
}

function matches(option: DestinationOption, query: string): boolean {
  return [option.label, option.detail ?? "", ...Object.values(option.destination)].some((text) => text.toLowerCase().includes(query));
}
