// SPDX-License-Identifier: AGPL-3.0-or-later
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Destinations } from "../src/features/access/Destinations";

describe("a Capability's destinations in the list (ADR-0064)", () => {
  const shown = (...destinations: string[]) => renderToStaticMarkup(<Destinations destinations={destinations} nameOf={() => "desk-7"} />);
  it("names a page without TLS with a warning", () => {
    const html = shown("web:https://portal.example.com:443/login", "web:http://intra.example:80/login");
    expect(html).toContain("https://portal.example.com/login, http://intra.example/login");
    expect(html).toContain("http: not encrypted");
    expect(html).toContain("whoever is on the network");
  });
  it("says nothing of any other", () => {
    for (const d of ["web:https://portal.example.com:443/login", "api.example.com:80", "web:80", "app:CRM Client@idn_abc2"]) expect(shown(d)).not.toContain("not encrypted");
  });
});
