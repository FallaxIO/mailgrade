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
import * as doh from "../src/doh.ts";

const names = (m: object) => Object.keys(m).toSorted();

describe("entry points", () => {
  it("exposes the documented API, and only that", () => {
    expect(names(root)).toEqual([
      "DKIM_SELECTORS",
      "DnsError",
      "aligns",
      "analyzeDkim",
      "analyzeDmarc",
      "analyzeHeaders",
      "analyzeSpf",
      "buildDmarcRecord",
      "gradeDomain",
      "coerceDomain",
      "dkimHost",
      "dmarcHost",
      "dohResolver",
      "domainOf",
      "domainVerdict",
      "gradeRecords",
      "isDkimKey",
      "isDmarcRecord",
      "isSpfRecord",
      "mailProvider",
      "parseDmarcRecord",
      "registrableDomain",
      "resolveDomain",
      "reviewDmarc",
      "rolloutPlan",
      "staticResolver",
      "toAuthResults",
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
    expect(names(doh)).toEqual([
      "DEFAULT_ENDPOINT",
      "DnsError",
      "defaultResolver",
      "dohResolver",
      "gradeDomain",
      "resolveDomain",
    ]);
  });

  it("exposes the Node resolver only from its own entry point", () => {
    expect(names(nodeDns)).toEqual(["nodeResolver"]);
    for (const module of [root, spf, dkim, domain, dmarc, headers, verify, doh]) {
      expect(names(module)).not.toContain("nodeResolver");
    }
  });

  // The headline calls belong on the headline import: a reader reaching for
  // this library types `mailgrade`, not `mailgrade/doh`. What has to stay out
  // of the root is `node:`, which is a bundler problem rather than a taste
  // one, and that is pinned separately below.
  it("puts the headline calls on the root import", () => {
    expect(names(root)).toContain("gradeDomain");
    expect(names(root)).toContain("verifyMessage");
    expect(names(root)).toContain("analyzeHeaders");
  });

  // The root is curated by hand, so this is the test that notices when
  // somebody reaches for `export *` again and the surface doubles.
  it("keeps the helpers off the root and on their own entry point", () => {
    for (const name of [
      "blankCheck",
      "editDistance",
      "headerValue",
      "parseHeaders",
      "spfCheck",
      "stripComments",
      "txtChunks",
    ]) {
      expect(names(root)).not.toContain(name);
    }
    expect(names(headers)).toContain("blankCheck");
    expect(names(headers)).toContain("editDistance");
    expect(names(headers)).toContain("parseHeaders");
    expect(names(dmarc)).toContain("txtChunks");
  });

  it("keeps the network code out of the entry points that promise none", () => {
    for (const module of [spf, dkim, domain, dmarc, headers]) {
      expect(names(module)).not.toContain("gradeDomain");
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
