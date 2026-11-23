// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { isRouteErrorResponse, Link, useParams, useRouteError } from "react-router-dom";
import { ArrowLeft, Compass, RefreshCw, TriangleAlert } from "lucide-react";
import { Button, EmptyState } from "../components/ui";
import { CenteredCard } from "./CenteredCard";
import { BrandMark } from "./BrandMark";

/*
 * What the router shows when there is no page, or a page cannot be shown:
 * the app's own screens, never the router's. Neither shows what the address
 * or the error says: an error's text is for the browser's console.
 */

/** Where "back" leads: the address's Organization, else the start page (the last or first Organization). */
function useHome(): { to: string; label: string } {
  const { org } = useParams();
  return org ? { to: `/o/${org}/projects`, label: "Go to Projects" } : { to: "/", label: "Go to the start page" };
}

function HomeLink() {
  const home = useHome();
  return (
    <Link
      to={home.to}
      data-testid="route-home"
      className="inline-flex h-9 items-center gap-2 rounded-lg border border-bd bg-raised px-3.5 text-sm font-medium text-fg hover:bg-hover"
    >
      <ArrowLeft size={15} aria-hidden="true" />
      {home.label}
    </Link>
  );
}

/** The page's heading, inside an EmptyState's title paragraph. */
const Heading = ({ children }: { children: React.ReactNode }) => (
  <span role="heading" aria-level={1}>
    {children}
  </span>
);

/** No page at this address. Inside the shell, its navigation stays. */
export function NotFoundPage() {
  return (
    <EmptyState
      data-testid="not-found"
      className="py-24"
      icon={<Compass size={20} />}
      title={<Heading>Page not found</Heading>}
      description="There is no page at this address. It may have moved, or the link may be incomplete."
      actions={<HomeLink />}
    />
  );
}

/** A page that could not be shown (it failed while loading or rendering), inside the shell. */
export function PageError() {
  const error = useRouteError();
  if (isRouteErrorResponse(error) && error.status === 404) return <NotFoundPage />;
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
          <HomeLink />
        </>
      }
    />
  );
}

/** The same, where the shell itself is not there: the pages outside it, or the shell's own failure. */
export function ScreenError() {
  return (
    <CenteredCard testId="screen-error">
      <div className="rounded-2xl border border-bd bg-raised px-4 py-2 shadow-pop">
        <div className="flex justify-center pt-6">
          <BrandMark size={36} />
        </div>
        <PageError />
      </div>
    </CenteredCard>
  );
}
