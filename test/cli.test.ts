/**
 * The CLI, run entirely in-process: `runCli` takes its I/O and its DNS as
 * arguments, so these tests never spawn anything and never leave the process.
 */

import { describe, expect, it } from "vitest";

import { parseArgs, renderGrade, runCli, type CliIo } from "../src/cli/run.ts";
import { gradeRecords } from "../src/grade.ts";
import { staticResolver } from "../src/verify/resolver.ts";

const LOCKED_ZONE = {
  "acme.com": {
    TXT: ["v=spf1 include:_spf.google.com -all"],
    MX: ["aspmx.l.google.com"],
  },
  "_dmarc.acme.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@acme.com"] },
  "google._domainkey.acme.com": { TXT: ["v=DKIM1; k=rsa; p=MIIB"] },
} as const;

function io(overrides: Partial<CliIo> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const handle: CliIo = {
    write: (t) => void out.push(t),
    writeError: (t) => void err.push(t),
    resolver: staticResolver(LOCKED_ZONE),
    ...overrides,
  };
  return { handle, stdout: () => out.join(""), stderr: () => err.join("") };
}

describe("parseArgs", () => {
  it("takes a domain and the flags in any order", () => {
    expect(parseArgs(["--strict", "acme.com", "--json"])).toEqual({
      kind: "grade",
      domain: "acme.com",
      json: true,
      strict: true,
      noColor: false,
      selectors: null,
      endpoint: null,
    });
  });

  it("accepts a pasted URL or address and grades its domain", () => {
    const parsed = parseArgs(["https://www.acme.com/careers"]);
    expect(parsed).toMatchObject({ kind: "grade", domain: "acme.com" });
    expect(parseArgs(["ceo@acme.com"])).toMatchObject({ domain: "acme.com" });
  });

  it("reads --selectors as a list, with none meaning skip the probe", () => {
    expect(parseArgs(["acme.com", "--selectors", "google,pm"])).toMatchObject({
      selectors: ["google", "pm"],
    });
    expect(parseArgs(["acme.com", "--selectors=none"])).toMatchObject({
      selectors: [],
    });
  });

  it("refuses what it cannot grade", () => {
    expect(parseArgs([])).toMatchObject({ kind: "error" });
    expect(parseArgs(["not a domain"])).toMatchObject({ kind: "error" });
    expect(parseArgs(["acme.com", "--wat"])).toMatchObject({ kind: "error" });
    expect(parseArgs(["a.com", "b.com"])).toMatchObject({ kind: "error" });
  });
});

describe("runCli", () => {
  it("grades over the injected resolver and prints the report", async () => {
    const { handle, stdout } = io();
    const code = await runCli(["acme.com", "--selectors", "google"], handle);

    expect(code).toBe(0);
    expect(stdout()).toContain("A+");
    expect(stdout()).toContain("protected");
    expect(stdout()).toContain("SPF ends in -all");
    expect(stdout()).toContain("Google Workspace");
  });

  it("prints the whole grade as JSON with --json", async () => {
    const { handle, stdout } = io();
    const code = await runCli(
      ["acme.com", "--json", "--selectors", "google"],
      handle,
    );

    expect(code).toBe(0);
    const grade = JSON.parse(stdout());
    expect(grade.letter).toBe("A+");
    expect(grade.verdict).toBe("protected");
    expect(grade.recommendations[0].id).toBe("keep-watching");
  });

  it("exits 1 under --strict when the domain is not protected", async () => {
    const { handle } = io({
      resolver: staticResolver({
        "acme.com": { TXT: ["v=spf1 -all"], MX: ["aspmx.l.google.com"] },
        "_dmarc.acme.com": { TXT: ["v=DMARC1; p=none"] },
      }),
    });
    expect(await runCli(["acme.com", "--selectors=none"], handle)).toBe(0);
    expect(
      await runCli(["acme.com", "--selectors=none", "--strict"], handle),
    ).toBe(1);
  });

  it("exits 2 when DNS cannot answer, and says why on stderr", async () => {
    const { handle, stderr } = io({
      resolver: () => Promise.reject(new Error("socket closed")),
    });
    expect(await runCli(["acme.com"], handle)).toBe(2);
    expect(stderr()).toContain("socket closed");
  });

  it("exits 2 on a usage error", async () => {
    const { handle, stderr } = io();
    expect(await runCli([], handle)).toBe(2);
    expect(stderr()).toContain("mailgrade:");
  });

  it("keeps ANSI out of the output unless colour is on", async () => {
    const plain = io();
    await runCli(["acme.com", "--selectors=none"], plain.handle);
    expect(plain.stdout()).not.toContain("\u001b[");

    const colored = io({ color: true });
    await runCli(["acme.com", "--selectors=none"], colored.handle);
    expect(colored.stdout()).toContain("\u001b[");

    const flagged = io({ color: true });
    await runCli(["acme.com", "--selectors=none", "--no-color"], flagged.handle);
    expect(flagged.stdout()).not.toContain("\u001b[");
  });
});

describe("renderGrade", () => {
  it("renders the README's terminal example, exactly as printed", () => {
    const grade = gradeRecords({
      domain: "acme.com",
      txt: ["v=spf1 include:_spf.google.com -all"],
      dmarc: ["v=DMARC1; p=none; rua=mailto:dmarc@acme.com"],
      dkimSelectors: ["google"],
      mx: ["aspmx.l.google.com"],
    });
    expect(renderGrade(grade, { columns: 78 })).toBe(
      [
        "",
        "  acme.com",
        "",
        "   D  spoofable",
        "  mail claiming to be this domain can reach inboxes",
        "",
        "  ✓ SPF    SPF ends in -all",
        "  ✓ DKIM   DKIM keys published (google)",
        "  ✗ DMARC  DMARC is monitoring only (p=none)",
        "  · MX     Google Workspace",
        "",
        "  → Graduate DMARC from p=none. Monitoring mode was designed as a",
        "    transition, not a destination: once the reports show your real senders",
        "    passing, move to p=quarantine, then p=reject.",
        "",
      ]
        .map((line) => `${line}\n`)
        .join(""),
    );
  });

  it("wraps recommendation prose to the terminal width", () => {
    const grade = gradeRecords({
      domain: "acme.com",
      txt: ["v=spf1 include:_spf.google.com ~all"],
      dmarc: ["v=DMARC1; p=none; rua=mailto:d@acme.com"],
      mx: ["aspmx.l.google.com"],
    });
    const narrow = renderGrade(grade, { columns: 50 });
    for (const line of narrow.split("\n")) {
      expect(line.length).toBeLessThanOrEqual(50);
    }
    expect(narrow).toContain("Graduate DMARC");
  });
});
