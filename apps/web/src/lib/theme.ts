// SPDX-License-Identifier: AGPL-3.0-or-later
/** Theme persistence shared by the shell footer toggle and Settings →
    Appearance. Dark is the default (design R1); OS preference seeds it. */

export type Theme = "dark" | "light";

export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("varlatch-theme", theme);
  // Same-document listeners (the storage event only fires cross-document).
  window.dispatchEvent(new CustomEvent<Theme>("varlatch:theme", { detail: theme }));
}

export function initialTheme(): Theme {
  const saved = localStorage.getItem("varlatch-theme");
  if (saved === "light" || saved === "dark") return saved;
  return matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}
