// SPDX-License-Identifier: AGPL-3.0-or-later
import { Dialog } from "../components/Dialog";
import { Kbd } from "../components/ui";
import { modKey } from "../lib/hotkeys";

const GROUPS: { title: string; items: [keys: string[], label: string][] }[] = [
  {
    title: "Anywhere",
    items: [
      [["mod", "K"], "Search and run commands"],
      [["/"], "Filter the current list"],
      [["?"], "Show these shortcuts"],
      [["Esc"], "Close, clear or cancel"],
    ],
  },
  {
    title: "Go to",
    items: [
      [["G", "P"], "Projects"],
      [["G", "A"], "Access"],
      [["G", "C"], "Connections"],
      [["G", "L"], "Audit log"],
      [["G", "S"], "Settings"],
      [["G", "M"], "My account"],
    ],
  },
  {
    title: "Lists",
    items: [
      [["↑", "↓"], "Move the selection"],
      [["↵"], "Open the selected row"],
      [["mod", "↵"], "Open in a new tab"],
    ],
  },
  {
    title: "Values",
    items: [
      [["E"], "Edit the selected cell"],
      [["mod", "S"], "Review and save"],
      [["Esc"], "Revert the cell being edited"],
    ],
  },
];

export function ShortcutsDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const mod = modKey();
  return (
    <Dialog open={open} onClose={onClose} title="Keyboard shortcuts" size="md" data-testid="shortcuts-dialog">
      <div className="grid gap-x-8 gap-y-6 pb-4 sm:grid-cols-2">
        {GROUPS.map((g) => (
          <section key={g.title}>
            <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-subtle">{g.title}</h3>
            <ul className="space-y-1.5">
              {g.items.map(([keys, label]) => (
                <li key={label} className="flex items-center justify-between gap-3 text-[13px]">
                  <span className="text-fg/90">{label}</span>
                  <span className="flex items-center gap-1">
                    {keys.map((k, i) => (
                      <Kbd key={i}>{k === "mod" ? mod : k}</Kbd>
                    ))}
                  </span>
                </li>
              ))}
            </ul>
          </section>
        ))}
      </div>
    </Dialog>
  );
}
