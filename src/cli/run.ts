/**
 * `npx mailgrade acme.com`: the grade, in a terminal.
 *
 * Everything here is pure rendering over `gradeDomain`; the bin wrapper in
 * `../cli.ts` is the only place that touches `process`. Exit codes are part
 * of the contract, because the second thing people do with this is put it in
 * CI: 0 means graded (and `--strict` satisfied), 1 means graded but below
 * `--strict`, 2 means the grade could not be produced at all.
 */

import pkg from "../../package.json" with { type: "json" };
import { coerceDomain } from "../domain.ts";
import { gradeDomain, type GradeDomainOptions } from "../doh.ts";
import type { DomainGrade, GradeLetter } from "../grade.ts";
import type { FetchLike } from "../doh-resolver.ts";
import type { Resolver } from "../verify/resolver.ts";

export type CliIo = {
  readonly write: (text: string) => void;
  readonly writeError: (text: string) => void;
  /** Terminal width, for wrapping. 80 when unknown. */
  readonly columns?: number | undefined;
  /** Whether to emit colour; `--no-color` wins over it. */
  readonly color?: boolean;
  /** Injectable for tests, so no test ever leaves the process. */
  readonly fetch?: FetchLike;
  readonly resolver?: Resolver;
};

const HELP = `
  Grade a domain's SPF, DKIM and DMARC, and say what to fix.

  Usage
    $ mailgrade <domain>

  Options
    --json             print the full grade as JSON
    --strict           exit 1 unless the verdict is "protected" (for CI)
    --selectors a,b    DKIM selectors to probe; "none" skips the probe
    --endpoint <url>   a DNS-over-HTTPS endpoint other than Cloudflare's
    --no-color         plain output
    -v, --version      print the version
    -h, --help         this text

  Exit codes
    0  graded
    1  graded, but --strict was set and the verdict is not "protected"
    2  no grade: bad arguments, or DNS could not be reached

  Examples
    $ mailgrade acme.com
    $ mailgrade acme.com --json | jq .letter
    $ mailgrade acme.com --strict   # fail the build when protection slips
`.replace(/^\n/, "");

type ParsedArgs =
  | { readonly kind: "help" }
  | { readonly kind: "version" }
  | { readonly kind: "error"; readonly message: string }
  | {
      readonly kind: "grade";
      readonly domain: string;
      readonly json: boolean;
      readonly strict: boolean;
      readonly noColor: boolean;
      readonly selectors: readonly string[] | null;
      readonly endpoint: string | null;
    };

export function parseArgs(argv: readonly string[]): ParsedArgs {
  let domain: string | null = null;
  let json = false;
  let strict = false;
  let noColor = false;
  let selectors: readonly string[] | null = null;
  let endpoint: string | null = null;

  const take = (i: number): string | null => {
    const arg = argv[i] as string;
    const eq = arg.indexOf("=");
    if (eq !== -1) return arg.slice(eq + 1);
    const next = argv[i + 1];
    return next === undefined || next.startsWith("-") ? null : next;
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    const name = arg.startsWith("--") ? (arg.split("=")[0] as string) : arg;

    if (name === "-h" || name === "--help") return { kind: "help" };
    if (name === "-v" || name === "--version") return { kind: "version" };
    if (name === "--json") json = true;
    else if (name === "--strict") strict = true;
    else if (name === "--no-color") noColor = true;
    else if (name === "--selectors" || name === "--endpoint") {
      const value = take(i);
      if (value === null) {
        return { kind: "error", message: `${name} needs a value` };
      }
      if (!arg.includes("=")) i++;
      if (name === "--endpoint") endpoint = value;
      else {
        selectors =
          value === "none" || value === ""
            ? []
            : value.split(",").map((s) => s.trim()).filter((s) => s !== "");
      }
    } else if (name.startsWith("-")) {
      return { kind: "error", message: `unknown option ${name}` };
    } else if (domain === null) {
      domain = arg;
    } else {
      return { kind: "error", message: "one domain at a time" };
    }
  }

  if (domain === null) {
    return { kind: "error", message: "which domain? try: mailgrade acme.com" };
  }
  const coerced = coerceDomain(domain);
  if (coerced === "" || !coerced.includes(".")) {
    return { kind: "error", message: `"${domain}" does not look like a domain` };
  }
  return { kind: "grade", domain: coerced, json, strict, noColor, selectors, endpoint };
}

/* ---------------------------------------------------------------- paint --- */

type Paint = (text: string, code: string) => string;

const CODES: Record<string, string> = {
  bold: "1", dim: "2", red: "31", green: "32", yellow: "33",
};

function painter(color: boolean): Paint {
  if (!color) return (text) => text;
  return (text, code) => `\u001b[${CODES[code] ?? "0"}m${text}\u001b[0m`;
}

const LETTER_CODE: Record<GradeLetter, string> = {
  "A+": "green", A: "green", B: "yellow", C: "yellow", D: "red", F: "red",
};

const TAGLINE = {
  spoofable: "mail claiming to be this domain can reach inboxes",
  partial: "spoofed mail is degraded, not refused",
  protected: "receivers are told to refuse mail that fails authentication",
} as const;

function wrap(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/).filter((w) => w !== "");
  const lines: string[] = [];
  let line = "";
  for (const word of words) {
    if (line !== "" && line.length + 1 + word.length > width) {
      lines.push(line);
      line = word;
    } else {
      line = line === "" ? word : `${line} ${word}`;
    }
  }
  if (line !== "") lines.push(line);
  return lines.join(`\n${indent}`);
}

export function renderGrade(
  grade: DomainGrade,
  options: { readonly columns?: number | undefined; readonly color?: boolean } = {},
): string {
  const paint = painter(options.color ?? false);
  const width = Math.min(options.columns ?? 80, 96) - 2;
  const out: string[] = [""];

  const letter = paint(paint(` ${grade.letter} `, "bold"), LETTER_CODE[grade.letter]);
  out.push(`  ${paint(grade.domain, "bold")}`);
  out.push("");
  out.push(`  ${letter} ${paint(grade.verdict, "bold")}`);
  out.push(`  ${paint(wrap(TAGLINE[grade.verdict], width - 2, "  "), "dim")}`);
  out.push("");

  const mark = (status: "pass" | "warn" | "fail") =>
    status === "pass"
      ? paint("\u2713", "green")
      : status === "warn"
        ? paint("!", "yellow")
        : paint("\u2717", "red");
  const row = (label: string, symbol: string, text: string) =>
    out.push(
      `  ${symbol} ${paint(label.padEnd(7), "dim")}${wrap(text, width - 11, " ".repeat(11))}`,
    );

  row("SPF", mark(grade.spf.status), grade.spf.headline);
  row("DKIM", mark(grade.dkim.status), grade.dkim.headline);
  row("DMARC", mark(grade.dmarc.status), grade.dmarc.headline);
  row(
    "MX",
    paint("\u00b7", "dim"),
    grade.mx.provider ??
      (grade.mx.hosts.length > 0
        ? grade.mx.hosts.join(", ")
        : "no MX records"),
  );

  for (const rec of grade.recommendations) {
    out.push("");
    out.push(`  ${paint("\u2192", "dim")} ${wrap(rec.text, width - 4, "    ")}`);
  }

  out.push("");
  return out.map((line) => `${line}\n`).join("");
}

/* ------------------------------------------------------------------ run --- */

export async function runCli(
  argv: readonly string[],
  io: CliIo,
): Promise<number> {
  const args = parseArgs(argv);

  if (args.kind === "help") {
    io.write(HELP);
    return 0;
  }
  if (args.kind === "version") {
    io.write(`${pkg.version}\n`);
    return 0;
  }
  if (args.kind === "error") {
    io.writeError(`mailgrade: ${args.message}\n`);
    return 2;
  }

  const options: GradeDomainOptions = {
    ...(args.selectors ? { selectors: args.selectors } : {}),
    ...(args.endpoint ? { endpoint: args.endpoint } : {}),
    ...(io.fetch ? { fetch: io.fetch } : {}),
    ...(io.resolver ? { resolver: io.resolver } : {}),
  };

  let grade: DomainGrade;
  try {
    grade = await gradeDomain(args.domain, options);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    io.writeError(`mailgrade: ${message}\n`);
    return 2;
  }

  if (args.json) {
    io.write(`${JSON.stringify(grade, null, 2)}\n`);
  } else {
    io.write(
      renderGrade(grade, {
        columns: io.columns,
        color: args.noColor ? false : (io.color ?? false),
      }),
    );
  }

  return args.strict && grade.verdict !== "protected" ? 1 : 0;
}
