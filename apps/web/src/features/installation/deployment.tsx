// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { Segmented } from "../../components/ui";

/** How the operator runs varlatchd: as the systemd service `varlatch setup` makes, or in the container image. The dashboard cannot tell. */
export type Deployment = "host" | "container";

/** The container as the operator names it. */
export const CONTAINER = "<container>";

/** A command of the installation's host, as it is run there; `asks` is one that asks before it acts. */
export function hostCommand(deployment: Deployment, command: string, asks = false): string {
  return deployment === "host" ? `sudo ${command}` : `docker exec ${asks ? "-it " : ""}${CONTAINER} ${command}`;
}

/** What to do after changing varlatchd.conf. */
export function restartNote(deployment: Deployment): string {
  return deployment === "host" ? "then run sudo systemctl restart varlatchd" : "then restart its container";
}

/** The commands a page shows follow this choice. */
export function DeploymentChoice({ value, onChange }: { value: Deployment; onChange: (d: Deployment) => void }) {
  return (
    <div className="flex flex-wrap items-center gap-3 text-[13px]">
      <span className="text-muted">varlatchd runs</span>
      <Segmented
        size="sm"
        aria-label="How varlatchd runs"
        value={value}
        onChange={onChange}
        options={[
          { value: "host", label: "as a service", "data-testid": "deployment-host" },
          { value: "container", label: "in a container", "data-testid": "deployment-container" },
        ]}
      />
    </div>
  );
}
