// SPDX-License-Identifier: AGPL-3.0-or-later
/** Theme persistence shared by the shell, Settings and the account page.
    Dark is the default (design R1); "system" follows the OS preference. */

export type Theme = "dark" | "light";
export type ThemePreference = Theme | "system";

const KEY = "varlatch-theme";
const LIGHT_QUERY = "(prefers-color-scheme: light)";

export function themePreference(): ThemePreference {
  const saved = localStorage.getItem(KEY);
  return saved === "light" || saved === "dark" || saved === "system" ? saved : "system";
}

export function resolveTheme(preference: ThemePreference): Theme {
  if (preference !== "system") return preference;
  return matchMedia(LIGHT_QUERY).matches ? "light" : "dark";
}

export function initialTheme(): Theme {
  return resolveTheme(themePreference());
}

/** Shows `theme` and records it as an explicit choice. */
export function applyTheme(theme: Theme): void {
  localStorage.setItem(KEY, theme);
  show(theme);
}

/** Records a preference (including "system") and shows its resolved theme. */
export function chooseThemePreference(preference: ThemePreference): void {
  localStorage.setItem(KEY, preference);
  show(resolveTheme(preference));
}

/** Shows the stored preference without changing it; follows the OS in system mode. */
export function showPreferredTheme(): () => void {
  show(initialTheme());
  const mq = matchMedia(LIGHT_QUERY);
  const onChange = () => {
    if (themePreference() === "system") show(resolveTheme("system"));
  };
  mq.addEventListener("change", onChange);
  return () => mq.removeEventListener("change", onChange);
}

function show(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  // Same-document listeners (the storage event only fires cross-document).
  window.dispatchEvent(new CustomEvent<Theme>("varlatch:theme", { detail: theme }));
  window.dispatchEvent(new CustomEvent<ThemePreference>("varlatch:theme-preference", { detail: themePreference() }));
}
