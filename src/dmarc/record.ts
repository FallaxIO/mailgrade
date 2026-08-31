/**
 * Building a DMARC record from a set of choices, and reading an existing one
 * back into the same shape.
 *
 * No DNS in here, so the whole thing runs in a browser. Parsing is deliberately
 * forgiving about what receivers forgive (case, spacing, a trailing semicolon,
 * a missing mailto:) and loud about what they do not (a missing v=DMARC1, a
 * policy that is not one of the three words).
 */

import { domainOf, isDomainName } from "../domain.ts";

export type DmarcPolicy = "none" | "quarantine" | "reject";
export type SubdomainPolicy = DmarcPolicy | "inherit";
export type Alignment = "r" | "s";

export type DmarcOptions = {
  /**
   * The domain the record is published for. Only used for the host row and to
   * tell an in-house report address from a third party's.
   */
  readonly domain: string;
  readonly policy: DmarcPolicy;
  readonly subdomainPolicy: SubdomainPolicy;
  /** Percentage of failing mail the policy applies to, 0 to 100. */
  readonly pct: number;
  /** Aggregate report addresses, bare (no mailto: prefix). */
  readonly rua: readonly string[];
  /** Failure report addresses, bare. */
  readonly ruf: readonly string[];
  readonly adkim: Alignment;
  readonly aspf: Alignment;
  /** Aggregate report interval in seconds. */
  readonly ri: number;
  /** fo tag: 0, 1, d, s, or a colon-joined combination. */
  readonly fo: string;
};

/** The same fields, writable, for assembling one tag at a time. */
type DmarcDraft = {
  -readonly [K in keyof DmarcOptions]: K extends "rua" | "ruf"
    ? string[]
    : DmarcOptions[K];
};

export const DEFAULT_RI = 86400;

export const DEFAULT_OPTIONS: DmarcOptions = {
  domain: "",
  policy: "none",
  subdomainPolicy: "inherit",
  pct: 100,
  rua: [],
  ruf: [],
  adkim: "r",
  aspf: "r",
  ri: DEFAULT_RI,
  fo: "0",
};

export const DMARC_TAGS: readonly string[] = [
  "v", "p", "sp", "pct", "ri", "rua", "ruf", "adkim", "aspf", "fo",
];

/* ---------------------------------------------------------------- build --- */

export type TagNote = {
  readonly tag: string;
  readonly value: string;
  readonly title: string;
  readonly detail: string;
};

const POLICY_EFFECT: Record<DmarcPolicy, string> = {
  none: "deliver it anyway and tell me about it",
  quarantine: "put it in the spam folder",
  reject: "refuse it at the door, so it never becomes anyone's decision",
};

/**
 * The tags the record carries, in the order it carries them, each with a
 * sentence explaining what it does.
 *
 * Emitting a tag whose value is the DMARC default only makes the record longer
 * and gives a reader something extra to misread, so defaults are left out: pct
 * is 100, alignment is relaxed, ri is a day and fo is 0 whether or not anyone
 * writes it down. The exception is p, which has no default and is the record.
 */
export function recordTags(o: DmarcOptions): TagNote[] {
  const notes: TagNote[] = [
    {
      tag: "v",
      value: "DMARC1",
      title: "This is a DMARC record",
      detail:
        "Has to be the first tag, spelled exactly this way. A receiver that does not find it here stops reading and treats the domain as having no policy at all.",
    },
    {
      tag: "p",
      value: o.policy,
      title: "What receivers do with mail that fails",
      detail: `Mail claiming to be ${o.domain || "your domain"} that does not authenticate: ${POLICY_EFFECT[o.policy]}.`,
    },
  ];

  if (o.subdomainPolicy !== "inherit") {
    notes.push({
      tag: "sp",
      value: o.subdomainPolicy,
      title: "The same question for subdomains",
      detail: `Mail from anything under the domain, including subdomains nobody ever registered, gets ${POLICY_EFFECT[o.subdomainPolicy]}. Without this tag subdomains inherit p.`,
    });
  }

  const rua = cleanAddresses(o.rua);
  if (rua.length > 0) {
    notes.push({
      tag: "rua",
      value: rua.map(mailto).join(","),
      title: "Where the daily reports go",
      detail:
        "Every receiver that handles mail in your name sends a summary here: which servers sent it, how much authenticated, and how much did not. This is the tag that turns DMARC from a switch into a rollout you can watch.",
    });
  }

  const ruf = cleanAddresses(o.ruf);
  if (ruf.length > 0) {
    notes.push({
      tag: "ruf",
      value: ruf.map(mailto).join(","),
      title: "Where per-message failure reports go",
      detail:
        "A copy of the headers, sometimes the whole message, for individual mail that failed. Most large receivers never send these, and the ones that do are handing you other people's correspondence.",
    });
  }

  if (o.adkim === "s") {
    notes.push({
      tag: "adkim",
      value: "s",
      title: "Strict DKIM alignment",
      detail:
        "The signing domain has to match the From domain exactly. Relaxed, the default, accepts a signature from a subdomain, which is how most mail vendors sign.",
    });
  }

  if (o.aspf === "s") {
    notes.push({
      tag: "aspf",
      value: "s",
      title: "Strict SPF alignment",
      detail:
        "The envelope sender has to be on the From domain exactly. Relaxed, the default, accepts a bounce address on a subdomain, which is what most mail vendors use.",
    });
  }

  if (o.pct < 100) {
    notes.push({
      tag: "pct",
      value: String(o.pct),
      title: "How much of the failing mail this applies to",
      detail: `${o.pct}% of messages that fail get the policy; the other ${100 - o.pct}% are delivered as if the policy were none. A dial for turning enforcement up slowly, not a permanent setting.`,
    });
  }

  if (o.ri !== DEFAULT_RI) {
    notes.push({
      tag: "ri",
      value: String(o.ri),
      title: "How often you want aggregate reports",
      detail: `Requests a report every ${Math.round(o.ri / 3600)} hours. It is a request: most receivers send one report a day whatever you ask for.`,
    });
  }

  if (o.fo !== "0" && ruf.length > 0) {
    notes.push({
      tag: "fo",
      value: o.fo,
      title: "Which failures earn a failure report",
      detail:
        "0 reports only when everything fails, 1 when any check fails, d on a DKIM failure and s on an SPF failure. 1 is the useful one, and it only matters when ruf is set.",
    });
  }

  return notes;
}

export function buildDmarcRecord(o: DmarcOptions): string {
  return recordTags(o)
    .map((t) => `${t.tag}=${t.value}`)
    .join("; ");
}

function mailto(address: string): string {
  return `mailto:${address}`;
}

/** Trimmed, de-duplicated, empty entries dropped. Order is the caller's. */
export function cleanAddresses(list: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of list) {
    const value = raw.trim().replace(/^mailto:/i, "");
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

/**
 * An address with an optional !size suffix (rua=mailto:d@acme.com!10m), which
 * is part of the URI rather than of the address.
 */
function isReportAddress(value: string): boolean {
  const address = value.split("!")[0] ?? "";
  return /^[^\s@,]+@[^\s@,]+$/.test(address) && domainOf(address) !== null;
}

export function reportDomain(value: string): string | null {
  return domainOf(value.split("!")[0] ?? "");
}

/**
 * A TXT value longer than 255 bytes has to be published as several quoted
 * strings, which receivers concatenate. Most DNS panels do this silently; the
 * ones that do not reject the record with an unhelpful error.
 */
export function txtChunks(record: string): string[] {
  const chunks: string[] = [];
  for (let i = 0; i < record.length; i += 255) {
    chunks.push(record.slice(i, i + 255));
  }
  return chunks;
}

/* ---------------------------------------------------------------- parse --- */

export type DmarcErrorId =
  | "empty"
  | "not-a-tag"
  | "duplicate-tag"
  | "missing-version"
  | "bad-version"
  | "version-not-first"
  | "missing-policy"
  | "bad-policy"
  | "bad-subdomain-policy"
  | "bad-pct"
  | "bad-ri"
  | "missing-mailto"
  | "bad-report-address"
  | "bad-alignment"
  | "bad-fo";

export type DmarcError = {
  readonly id: DmarcErrorId;
  /** The tag the problem is on, when it is on one. */
  readonly tag: string | null;
  readonly message: string;
};

export type DmarcParse = {
  readonly options: DmarcOptions;
  /** Syntax problems that stop the record doing what its author meant. */
  readonly errors: readonly DmarcError[];
  /** Tags we do not know, kept so a caller can say what it dropped. */
  readonly unknown: readonly string[];
};

const POLICIES: ReadonlySet<string> = new Set(["none", "quarantine", "reject"]);

export function parseDmarcRecord(raw: string, domain = ""): DmarcParse {
  const errors: DmarcError[] = [];
  const unknown: string[] = [];
  const options: DmarcDraft = { ...DEFAULT_OPTIONS, rua: [], ruf: [], domain };

  const fail = (id: DmarcErrorId, tag: string | null, message: string) => {
    errors.push({ id, tag, message });
  };

  const record = raw.trim().replace(/^"|"$/g, "").replace(/"\s*"/g, "").trim();

  if (!record) {
    fail("empty", null, "Paste the record itself, not an empty line.");
    return { options, errors, unknown };
  }

  const parts = record
    .split(";")
    .map((p) => p.trim())
    .filter(Boolean);

  const tags = new Map<string, string>();
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq === -1) {
      fail("not-a-tag", null, `"${part}" is not a tag=value pair.`);
      continue;
    }
    const key = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    if (tags.has(key)) {
      fail(
        "duplicate-tag",
        key,
        `The ${key} tag appears twice. Receivers read the first one and ignore the rest.`,
      );
      continue;
    }
    tags.set(key, value);
  }

  const version = tags.get("v");
  if (!version) {
    fail(
      "missing-version",
      "v",
      "No v=DMARC1 tag. Receivers will not read this as a DMARC record.",
    );
  } else if (version.toLowerCase() !== "dmarc1") {
    fail(
      "bad-version",
      "v",
      `v is "${version}", and the only value receivers accept is DMARC1.`,
    );
  } else if (parts[0]?.split("=")[0]?.trim().toLowerCase() !== "v") {
    fail(
      "version-not-first",
      "v",
      "v=DMARC1 has to come first. A record that starts with any other tag is ignored.",
    );
  }

  const policy = tags.get("p")?.toLowerCase();
  if (!policy) {
    fail(
      "missing-policy",
      "p",
      "No p tag. Without a policy the record says nothing about what to do with mail that fails.",
    );
  } else if (!POLICIES.has(policy)) {
    fail(
      "bad-policy",
      "p",
      `p is "${policy}", and the only values are none, quarantine and reject.`,
    );
  } else {
    options.policy = policy as DmarcPolicy;
  }

  const sp = tags.get("sp")?.toLowerCase();
  if (sp !== undefined) {
    if (POLICIES.has(sp)) {
      options.subdomainPolicy = sp as SubdomainPolicy;
    } else {
      fail(
        "bad-subdomain-policy",
        "sp",
        `sp is "${sp}", and the only values are none, quarantine and reject.`,
      );
    }
  }

  const pct = tags.get("pct");
  if (pct !== undefined) {
    const n = Number(pct);
    if (!Number.isInteger(n) || n < 0 || n > 100) {
      fail(
        "bad-pct",
        "pct",
        `pct is "${pct}", and it has to be a whole number from 0 to 100.`,
      );
    } else {
      options.pct = n;
    }
  }

  const ri = tags.get("ri");
  if (ri !== undefined) {
    const n = Number(ri);
    if (!Number.isInteger(n) || n <= 0) {
      fail("bad-ri", "ri", `ri is "${ri}", and it has to be a number of seconds.`);
    } else {
      options.ri = n;
    }
  }

  for (const key of ["rua", "ruf"] as const) {
    const value = tags.get(key);
    if (value === undefined) continue;
    const addresses: string[] = [];
    for (const uri of value
      .split(",")
      .map((u) => u.trim())
      .filter(Boolean)) {
      if (!/^mailto:/i.test(uri)) {
        fail(
          "missing-mailto",
          key,
          `"${uri}" in ${key} has no mailto: prefix. Receivers skip destinations they cannot address.`,
        );
      }
      const address = uri.replace(/^mailto:/i, "");
      if (!isReportAddress(address)) {
        fail(
          "bad-report-address",
          key,
          `"${address}" in ${key} is not an address a report can be sent to.`,
        );
        continue;
      }
      addresses.push(address);
    }
    options[key] = addresses;
  }

  for (const key of ["adkim", "aspf"] as const) {
    const value = tags.get(key);
    if (value === undefined) continue;
    const v = value.toLowerCase();
    if (v !== "r" && v !== "s") {
      fail(
        "bad-alignment",
        key,
        `${key} is "${value}", and the only values are r (relaxed) and s (strict).`,
      );
      continue;
    }
    options[key] = v;
  }

  const fo = tags.get("fo");
  if (fo !== undefined) {
    const flags = fo.split(":").map((p) => p.trim().toLowerCase());
    if (flags.length > 0 && flags.every((p) => ["0", "1", "d", "s"].includes(p))) {
      options.fo = flags.join(":");
    } else {
      fail(
        "bad-fo",
        "fo",
        `fo is "${fo}", and the only values are 0, 1, d and s, joined with colons.`,
      );
    }
  }

  for (const key of tags.keys()) {
    if (!DMARC_TAGS.includes(key)) unknown.push(key);
  }

  return { options, errors, unknown };
}

/* --------------------------------------------------- external reporting --- */

export type ExternalDestination = {
  readonly domain: string;
  /** The record the destination domain publishes to accept your reports. */
  readonly host: string;
  readonly value: string;
};

/**
 * Report addresses outside the domain, with the authorization record each one
 * needs (RFC 7489 section 7.1). Without it receivers silently refuse to send,
 * which is the usual reason a shiny DMARC dashboard stays empty for a
 * fortnight.
 */
export function externalDestinations(o: DmarcOptions): ExternalDestination[] {
  const domain = o.domain.trim().toLowerCase();
  if (!isDomainName(domain)) return [];

  const seen = new Set<string>();
  const out: ExternalDestination[] = [];
  for (const address of [...cleanAddresses(o.rua), ...cleanAddresses(o.ruf)]) {
    const target = reportDomain(address);
    if (!target) continue;
    if (target === domain || target.endsWith(`.${domain}`)) continue;
    if (seen.has(target)) continue;
    seen.add(target);
    out.push({
      domain: target,
      host: `${domain}._report._dmarc.${target}`,
      value: "v=DMARC1",
    });
  }
  return out;
}
