# Dashboard UI conventions

The dashboard is built from the primitives in this folder. Feature folders
(`src/features/*`) compose them; they do not restyle them.

## Building blocks

| Need | Use |
| --- | --- |
| Page title, breadcrumbs, tabs | `PageHeader`, `Breadcrumbs`, `Tabs` (`PageHeader.tsx`) |
| Project or environment pages | render content only; `ProjectLayout` / `EnvironmentLayout` own the header and tabs, read data with `useProjectContext()` / `useEnvironmentContext()` |
| Buttons | `Button` (`primary` once per view, `secondary`, `ghost`, `danger`, `danger-solid`), `IconButton` (always labelled) |
| Text input | `Input`, `Textarea`, `Field` (label + hint/error), `Select`, `Switch`, `Checkbox`, `Segmented` |
| Lists you can search | `FilterInput` + `matchesFilter` + `Highlight` + `useListNavigation` (`/` focuses, Esc clears, ↑↓↵ moves and opens) |
| Status | `Status` / `StatusDot` (dot + text), `Badge`, `TierChip` / `TierDot` (tier dot always next to the tier name) |
| Containers | `Card`, `SectionCard` (title row + body), `table.*` class helpers, `EmptyState`, `Callout` |
| Dialogs | `Dialog`; `useConfirm()` for confirmations (with `consequences` and, for rare destructive actions, `typeToConfirm`); `usePrompt()` for a single text value. Never `window.alert/confirm/prompt`. |
| Feedback | `useToast()`: `success`, `error` (stays until dismissed), `undo` |
| Side content | `Drawer` (modal slide-over), `SidePanel` + `PanelSection` (inline, beside a list) |
| Commands and copying | `CodeBlock`, `InlineCommand`, `CopyButton` |
| Times | `timeAgo`, `timeUntil`, `countdown`, `dayLabel`, `useNow` (`lib/time.ts`) |
| Shortcuts | `useHotkeys` (`lib/hotkeys.ts`); bare keys never fire while typing or while a dialog is open |

## Rules

- Keyboard first: anything you can click in a list you can reach with
  `/`, ↑↓ and ↵. Show shortcuts with `Kbd`.
- Filtering is instant and local when the data is already loaded; when it
  queries the server, say so (never pretend a local filter covers history).
- Monospace (`Mono`, `font-mono`) for item names, slugs, values, IDs and
  commands. Proportional type for everything else.
- One mint `primary` action per view. Destructive actions are `danger` and go
  through `useConfirm`; type-to-confirm only for rare destructive operations
  (deleting a production environment, retiring a machine). Production saves
  use a checkbox acknowledgement.
- Secrets: masked by default, revealed only through the audited disclosure
  call, never cached by React Query, never placed in URLs or storage.
- Never show internal IDs where a name exists. Placeholder emails
  (`*.invalid`) are hidden with `displayEmail()`.
- No em dashes in user-facing text. No ADR numbers in user-facing text.
- Both themes: use the color tokens (`bg-raised`, `text-muted`, `border-bd`,
  `text-accent`, `text-deny`, `bg-tier-*` …), never raw hex values.
