// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { Plug } from "lucide-react";
import type { SyncPlatform } from "@varlatch/protocol";

/**
 * Monochrome brand marks (official Simple Icons path data, 24×24 viewBox),
 * rendered in `currentColor` so they inherit the token palette in both themes.
 */

type LogoProps = {
  size?: number | undefined;
  className?: string | undefined;
  title?: string | undefined;
};

function mark(title: string, d: string) {
  return function BrandLogo({ size = 16, className, title: t }: LogoProps) {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="currentColor"
        role="img"
        aria-label={t ?? title}
        className={className}
      >
        <path d={d} />
      </svg>
    );
  };
}

export const GitHubLogo = mark(
  "GitHub",
  "M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12",
);

export const CoolifyLogo = mark(
  "Coolify",
  "M4.364 4.364V0h17.454v4.364zm0 13.09H0V4.365h4.364zm0 0h17.454v4.364H4.364ZM6.545 6.546v-1.7H22.3V2.182H24v4.363zm0 0v10.4h-1.7v-10.4ZM3.882 17.936v1.7h-1.7v-1.7ZM24 24H6.545v-1.7H22.3v-2.664H24Z",
);

export const ConvexLogo = mark(
  "Convex",
  "M15.09 18.916c3.488-.387 6.776-2.246 8.586-5.348-.857 7.673-9.247 12.522-16.095 9.545a3.47 3.47 0 0 1-1.547-1.314c-1.539-2.417-2.044-5.492-1.318-8.282 2.077 3.584 6.3 5.78 10.374 5.399m-10.501-7.65c-1.414 3.266-1.475 7.092.258 10.24-6.1-4.59-6.033-14.41-.074-18.953a3.44 3.44 0 0 1 1.893-.707c2.825-.15 5.695.942 7.708 2.977-4.09.04-8.073 2.66-9.785 6.442m11.757-5.437C14.283 2.951 11.053.992 7.515.933c6.84-3.105 15.253 1.929 16.17 9.37a3.6 3.6 0 0 1-.334 2.02c-1.278 2.594-3.647 4.607-6.416 5.352 2.029-3.763 1.778-8.36-.589-11.847",
);

const PLATFORM_LOGOS: Record<SyncPlatform, React.ComponentType<LogoProps>> = {
  "github-actions": GitHubLogo,
  coolify: CoolifyLogo,
  convex: ConvexLogo,
};

/** Logo for a sync platform; unknown adapters fall back to a generic plug. */
export function PlatformLogo({
  platform,
  size = 16,
  className,
}: {
  platform: SyncPlatform | (string & {});
  size?: number | undefined;
  className?: string | undefined;
}) {
  const Logo = PLATFORM_LOGOS[platform as SyncPlatform];
  if (!Logo) return <Plug size={size} className={className} aria-hidden="true" />;
  return <Logo size={size} className={className} />;
}
