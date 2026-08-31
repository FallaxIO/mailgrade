/**
 * The public surface, pinned. A rename here is a breaking change, and this
 * test is where that shows up before a release does.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import * as root from "../src/index.ts";
import * as dmarc from "../src/dmarc/index.ts";
import * as headers from "../src/headers/index.ts";
import * as spf from "../src/spf.ts";
import * as dkim from "../src/dkim.ts";
import * as domain from "../src/domain.ts";
import * as verify from "../src/verify/index.ts";
import * as nodeDns from "../src/node-dns.ts";

const names = (m: object) => Object.keys(m).toSorted();

describe("entry points", () => {
  it("exposes the headline call and the pieces it is made of", () => {
    expect(names(root)).toEqual([
      "DEFAULT_OPTIONS",
      "DEFAULT_RI",
      "DKIM_SELECTORS",
      "DMARC_TAGS",
      "IMPERSONATED_DOMAINS",
      "INVISIBLE",
      "aligns",
      "analyzeDkim",
      "analyzeDmarc",
      "analyzeHeaders",
      "analyzeSpf",
      "blankCheck",
      "buildDmarcRecord",
      "cleanAddresses",
      "coerceDomain",
      "decodeEncodedWords",
      "detectImpersonation",
      "dkimCheck",
      "dkimHost",
      "dmarcCheck",
      "dmarcGrade",
      "dmarcHost",
      "domainLabel",
      "domainOf",
      "domainVerdict",
      "editDistance",
      "externalDestinations",
      "gradeDomain",
      "hasMixedScript",
      "headerValue",
      "headerValues",
      "headerVerdict",
      "identifierDomain",
      "isDkimKey",
      "isDmarcRecord",
      "isDomainName",
      "isPrivateIp",
      "isSpfRecord",
      "mailProvider",
      "parseAddress",
      "parseAuthResults",
      "parseDmarcRecord",
      "parseHeaders",
      "parseReceived",
      "registrableDomain",
      "reportDomain",
      "recordTags",
      "reviewDmarc",
      "rolloutPlan",
      "spfCheck",
      "staticResolver",
      "stripComments",
      "toAuthResults",
      "txtChunks",
      "verifyDkim",
      "verifyDmarc",
      "verifyMessage",
      "verifySpf",
    ].toSorted());
  });

  it("lets a caller import one area without the rest", () => {
    expect(names(spf)).toEqual(["analyzeSpf", "isSpfRecord"]);
    expect(names(dkim)).toEqual([
      "DKIM_SELECTORS",
      "analyzeDkim",
      "dkimHost",
      "isDkimKey",
    ]);
    expect(names(domain)).toContain("registrableDomain");
    expect(names(dmarc)).toContain("buildDmarcRecord");
    expect(names(headers)).toContain("analyzeHeaders");
    expect(names(verify)).toEqual([
      "staticResolver",
      "toAuthResults",
      "verifyDkim",
      "verifyDmarc",
      "verifyMessage",
      "verifySpf",
    ]);
  });

  it("exposes the Node resolver only from its own entry point", () => {
    expect(names(nodeDns)).toEqual(["nodeResolver"]);
    for (const module of [root, spf, dkim, domain, dmarc, headers, verify]) {
      expect(names(module)).not.toContain("nodeResolver");
    }
  });

  it("keeps the network code out of every entry point but its own", () => {
    for (const module of [root, spf, dkim, domain, dmarc, headers, verify]) {
      expect(names(module)).not.toContain("checkDomain");
      expect(names(module)).not.toContain("resolveDomain");
      expect(names(module)).not.toContain("dohResolver");
    }
  });
});

describe("no runtime dependencies", () => {
  it("has none declared", () => {
    const pkg = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as Record<string, unknown>;
    expect(pkg["dependencies"]).toBeUndefined();
    expect(pkg["peerDependencies"]).toBeUndefined();
  });
});

const SRC = new URL("../src/", import.meta.url).pathname;

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory()
      ? sources(join(dir, entry.name))
      : entry.name.endsWith(".ts")
        ? [join(dir, entry.name)]
        : [],
  );
}

// The one file allowed to reach for a Node built-in, because importing it is
// the whole point of it. It is its own entry point, so no bundle for a Worker
// or a browser can reach `node:` through any other import.
const NODE_ENTRY = "node-dns.ts";

describe("runs anywhere", () => {
  // The tests are typechecked with node types in scope, so nothing at the type
  // level stops a `node:` import drifting into the library itself. This does.
  // Static or dynamic: both forms are caught, so the exception stays explicit.
  it("imports no Node built-in anywhere in src but the Node entry point", () => {
    const offenders = sources(SRC)
      .filter((file) => /["']node:/.test(readFileSync(file, "utf8")))
      .map((file) => file.slice(SRC.length));
    expect(offenders).toEqual([NODE_ENTRY]);
  });

  it("keeps the source free of characters an editor cannot show", () => {
    const offenders = sources(SRC).filter((file) =>
      // eslint-disable-next-line no-control-regex
      /[^\x00-\x7F]/.test(readFileSync(file, "utf8")),
    );
    expect(offenders).toEqual([]);
  });
});
