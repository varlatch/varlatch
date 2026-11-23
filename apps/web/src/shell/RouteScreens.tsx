// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useRef } from "react";
import { isRouteErrorResponse, Link, useLocation, useParams, useRouteError } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Compass, RefreshCw, TriangleAlert } from "lucide-react";
import { useSession } from "../lib/session";
import { Button, EmptyState } from "../components/ui";
import { keys } from "../features/projects/hooks";
import { CenteredCard } from "./CenteredCard";
import { BrandMark } from "./BrandMark";

/*
 * What the router shows when there is no page, or a page cannot be shown:
 * the app's own screens, never the router's. Neither shows what the address
 * or the error says: an error's text is for the browser's console.
 */

/**
 * The screen's heading, inside an EmptyState's title paragraph: it names the
 * document and takes the focus, so a screen reader says where it is and the
 * keyboard starts here, on every address that leads to it.
 */
function Heading({ children }: { children: string }) {
  const ref = useRef<HTMLSpanElement>(null);
  const { key } = useLocation();
  useEffect(() => {
    const before = document.title;
    document.title = `${children} · Varlatch`;
    return () => {
      document.title = before;
    };
  }, [children]);
  useEffect(() => {
    ref.current?.focus();
  }, [key]);
  return (
    <span ref={ref} role="heading" aria-level={1} tabIndex={-1} className="outline-none" data-testid="route-heading">
      {children}
    </span>
  );
}

function HomeLink({ to = "/", label = "Go to the start page" }: { to?: string; label?: string }) {
  return (
    <Link
      to={to}
      data-testid="route-home"
      className="inline-flex h-9 items-center gap-2 rounded-lg border border-bd bg-raised px-3.5 text-sm font-medium text-fg hover:bg-hover"
    >
      <ArrowLeft size={15} aria-hidden="true" />
      {label}
    </Link>
  );
}

/**
 * The way back: the Projects of the address's Organization once it is known
 * to be one of the caller's, else the start page (the last or first
 * Organization), never back into one that does not exist or is not theirs.
 */
function BackLink() {
  const { org } = useParams();
  const { api } = useSession();
  const orgs = useQuery({ queryKey: keys.orgs(), queryFn: () => api.listOrganizations() });
  const theirs = org !== undefined && (orgs.data?.items.some((o) => o.slug === org) ?? false);
  return theirs ? <HomeLink to={`/o/${org}/projects`} label="Go to Projects" /> : <HomeLink />;
}

/** No page at this address. Inside the shell, its navigation stays. */
export function NotFoundPage() {
  return (
    <EmptyState
      data-testid="not-found"
      className="py-24"
      icon={<Compass size={20} />}
      title={<Heading>Page not found</Heading>}
      description="There is no page at this address. It may have moved, or the link may be incomplete."
      actions={<BackLink />}
    />
  );
}

function ErrorMessage({ home }: { home: React.ReactNode }) {
  return (
    <EmptyState
      data-testid="page-error"
      role="alert"
      className="py-24"
      icon={<TriangleAlert size={20} />}
      title={<Heading>This page could not be shown</Heading>}
      description="Something went wrong in the dashboard. Reload to try again; nothing you saved is affected."
      actions={
        <>
          <Button variant="primary" icon={<RefreshCw size={15} />} data-testid="page-reload" onClick={() => window.location.reload()}>
            Reload
          </Button>
          {home}
        </>
      }
    />
  );
}

/** A page that could not be shown (it failed while loading or rendering), inside the shell. */
export function PageError() {
  const error = useRouteError();
  if (isRouteErrorResponse(error) && error.status === 404) return <NotFoundPage />;
  return <ErrorMessage home={<BackLink />} />;
}

/**
 * The same, where the shell itself is not there: the pages outside it, or
 * the shell's own failure. It asks the server nothing, so what failed there
 * cannot fail here.
 */
export function ScreenError() {
  return (
    <CenteredCard testId="screen-error">
      <div className="rounded-2xl border border-bd bg-raised px-4 py-2 shadow-pop">
        <div className="flex justify-center pt-6">
          <BrandMark size={36} />
        </div>
        <ErrorMessage home={<HomeLink />} />
      </div>
    </CenteredCard>
  );
}
