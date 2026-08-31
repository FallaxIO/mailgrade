/**
 * Grading the DMARC record a domain actually publishes.
 *
 * DMARC is the tag that decides the outcome: SPF and DKIM only decide whether
 * the policy has anything to align against. So the grades here lean on what
 * receivers enforce, not on whether the record parses.
 */

import type { Status } from "../types.ts";
import type { DmarcPolicy } from "./record.ts";

export type DmarcFinding =
  | "dmarc-missing"
  | "dmarc-multiple"
  | "dmarc-no-policy"
  | "dmarc-monitor"
  | "dmarc-quarantine"
  | "dmarc-sampled"
  | "dmarc-weak-subdomain"
  | "dmarc-enforcing";

export type DmarcAnalysis = {
  readonly id: DmarcFinding;
  readonly status: Status;
  readonly record: string | null;
  readonly policy: DmarcPolicy | null;
  /** Host the record was found at; the org domain when a subdomain inherited it. */
  readonly source: string | null;
  readonly headline: string;
  readonly detail: string;
};

/** The DNS name a domain's DMARC record is published at. */
export function dmarcHost(domain: string): string {
  return `_dmarc.${domain || "yourdomain.com"}`;
}

/** True for a TXT string that declares itself a DMARC record. */
export function isDmarcRecord(txt: string): boolean {
  return /^v=dmarc1\b/i.test(txt.trim());
}

function dmarcTags(record: string): Map<string, string> {
  const tags = new Map<string, string>();
  for (const part of record.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    if (key && !tags.has(key)) tags.set(key, part.slice(eq + 1).trim());
  }
  return tags;
}

/**
 * Grade the TXT records found at `_dmarc.<domain>`.
 *
 * `source` is the host they were found at, which is the domain itself or the
 * organizational domain a subdomain inherited from. It only affects wording.
 */
export function analyzeDmarc(
  txtRecords: readonly string[],
  source: string | null = null,
): DmarcAnalysis {
  const records = txtRecords.map((r) => r.trim()).filter(isDmarcRecord);

  if (records.length === 0) {
    return {
      id: "dmarc-missing",
      status: "fail",
      record: null,
      policy: null,
      source: null,
      headline: "No DMARC record",
      detail:
        "Receivers find no instruction for mail that fails authentication, so a spoofed message is delivered like any other. SPF and DKIM results are computed and then ignored.",
    };
  }

  if (records.length > 1) {
    return {
      id: "dmarc-multiple",
      status: "fail",
      record: records.join("  |  "),
      policy: null,
      source,
      headline: "Multiple DMARC records",
      detail:
        "More than one DMARC record at the same name is a permanent error and receivers discard the policy entirely. Remove all but one.",
    };
  }

  const record = records[0] as string;
  const tags = dmarcTags(record);
  const policyTag = tags.get("p")?.toLowerCase();

  if (
    policyTag !== "none" &&
    policyTag !== "quarantine" &&
    policyTag !== "reject"
  ) {
    return {
      id: "dmarc-no-policy",
      status: "fail",
      record,
      policy: null,
      source,
      headline: "DMARC record has no valid policy",
      detail:
        "The record exists but its p= tag is missing or unreadable, so receivers fall back to treating the domain as having no policy at all.",
    };
  }

  // Receivers ignore an unparseable tag, so a malformed pct means 100, not 0.
  const rawPct = Number(tags.get("pct") ?? "100");
  const pct = Number.isFinite(rawPct)
    ? Math.min(100, Math.max(0, Math.trunc(rawPct)))
    : 100;
  const subPolicy = tags.get("sp")?.toLowerCase() ?? null;
  const reportingNote = tags.has("rua")
    ? ""
    : " There is also no rua= address, so nobody is reading the reports receivers would send.";

  if (policyTag === "none") {
    return {
      id: "dmarc-monitor",
      status: "fail",
      record,
      policy: "none",
      source,
      headline: "DMARC is monitoring only (p=none)",
      detail:
        "p=none asks receivers to report failures and deliver the mail anyway. It is the right first step while cleaning up legitimate senders, and no protection at all if it stays." +
        reportingNote,
    };
  }

  if (policyTag === "quarantine") {
    return {
      id: "dmarc-quarantine",
      status: "warn",
      record,
      policy: "quarantine",
      source,
      headline: "DMARC quarantines, but does not reject",
      detail:
        "Spoofed mail is sent to spam instead of being refused. Junk folders get opened, and one click from there is all a phish needs. Move to p=reject once the reports look clean." +
        reportingNote,
    };
  }

  if (pct < 100) {
    return {
      id: "dmarc-sampled",
      status: "warn",
      record,
      policy: "reject",
      source,
      headline: `DMARC rejects only ${pct}% of failing mail`,
      detail:
        `pct=${pct} means receivers apply the reject policy to a sample and let the rest of the failing mail through. Raise it to 100 (or drop the tag, which means the same) to close the gap.` +
        reportingNote,
    };
  }

  if (subPolicy === "none" || subPolicy === "quarantine") {
    return {
      id: "dmarc-weak-subdomain",
      status: "warn",
      record,
      policy: "reject",
      source,
      headline: "Subdomains are weaker than the domain",
      detail:
        `The domain itself rejects, but sp=${subPolicy} leaves subdomains at a weaker policy: mail from invented names like billing.${source ?? "your domain"} is exactly what that opens.` +
        reportingNote,
    };
  }

  return {
    id: "dmarc-enforcing",
    status: "pass",
    record,
    policy: "reject",
    source,
    headline: "DMARC enforces p=reject",
    detail:
      "Receivers are instructed to refuse mail that fails authentication for this domain, subdomains included." +
      reportingNote,
  };
}
