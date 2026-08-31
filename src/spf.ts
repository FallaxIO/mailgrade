/**
 * Grading an SPF record.
 *
 * The question is not "is this record valid" but "how far does mail claiming
 * to be this domain get". A syntactically perfect record ending in ?all is
 * valid and protects nothing, and the grade below says so.
 */

import type { Status } from "./types.ts";

export type SpfFinding =
  | "spf-missing"
  | "spf-multiple"
  | "spf-redirect"
  | "spf-no-all"
  | "spf-hardfail"
  | "spf-softfail"
  | "spf-neutral"
  | "spf-allow-all";

export type SpfQualifier = "+" | "-" | "~" | "?";

export type SpfAnalysis = {
  readonly id: SpfFinding;
  readonly status: Status;
  readonly record: string | null;
  /** Qualifier on the `all` mechanism, null when there is no record or no `all`. */
  readonly allQualifier: SpfQualifier | null;
  readonly headline: string;
  readonly detail: string;
};

/** True for a TXT string that declares itself an SPF record. */
export function isSpfRecord(txt: string): boolean {
  return /^v=spf1(\s|$)/i.test(txt.trim());
}

/**
 * Grade the TXT records published at a domain.
 *
 * Pass every TXT string at the apex, not just the SPF one: publishing two of
 * them is a permanent error that voids the policy, and that can only be seen
 * from the whole set.
 */
export function analyzeSpf(txtRecords: readonly string[]): SpfAnalysis {
  const records = txtRecords.map((r) => r.trim()).filter(isSpfRecord);

  if (records.length === 0) {
    return {
      id: "spf-missing",
      status: "fail",
      record: null,
      allQualifier: null,
      headline: "No SPF record",
      detail:
        "Receivers get no list of servers allowed to send for this domain, so any server anywhere can claim it and SPF has no opinion.",
    };
  }

  if (records.length > 1) {
    return {
      id: "spf-multiple",
      status: "fail",
      record: records.join("  |  "),
      allQualifier: null,
      headline: "Multiple SPF records",
      detail:
        "Publishing more than one v=spf1 record is a permanent error: receivers treat SPF as broken and evaluate none of them. Merge everything into a single record.",
    };
  }

  const record = records[0] as string;
  const terms = record.split(/\s+/).slice(1);
  const allTerm = terms.findLast((t) => /^[+\-~?]?all$/i.test(t));
  const hasRedirect = terms.some((t) => /^redirect=/i.test(t));

  if (!allTerm) {
    return hasRedirect
      ? {
          id: "spf-redirect",
          status: "warn",
          record,
          allQualifier: null,
          headline: "SPF delegates elsewhere",
          detail:
            "The record hands evaluation to another domain via redirect=. The policy is only as strong as the record it points at, which this check does not follow.",
        }
      : {
          id: "spf-no-all",
          status: "fail",
          record,
          allQualifier: null,
          headline: "SPF never says no",
          detail:
            "Without an all mechanism the default for unlisted senders is neutral, which receivers treat as no opinion. The record lists your senders but never says anyone else is unauthorised.",
        };
  }

  const allQualifier: SpfQualifier =
    allTerm.length === 4 ? (allTerm[0] as SpfQualifier) : "+";

  switch (allQualifier) {
    case "-":
      return {
        id: "spf-hardfail",
        status: "pass",
        record,
        allQualifier,
        headline: "SPF ends in -all",
        detail:
          "Unlisted senders hard-fail. Combined with an enforcing DMARC policy this is what gets a spoofed message refused outright.",
      };
    case "~":
      return {
        id: "spf-softfail",
        status: "warn",
        record,
        allQualifier,
        headline: "SPF ends in ~all (softfail)",
        detail:
          "Softfail only asks receivers to be suspicious, which in practice means the spam folder at worst. That is fine when DMARC enforcement does the rejecting; without it, softfail alone stops nothing.",
      };
    case "?":
      return {
        id: "spf-neutral",
        status: "fail",
        record,
        allQualifier,
        headline: "SPF ends in ?all (neutral)",
        detail:
          "Neutral explicitly tells receivers to treat unlisted senders as if no SPF existed. The record documents your senders without protecting anything.",
      };
    case "+":
      return {
        id: "spf-allow-all",
        status: "fail",
        record,
        allQualifier,
        headline: "SPF ends in +all",
        detail:
          "+all authorises every server on the internet to send as this domain, and a spoofed message will genuinely pass SPF. This is worse than no record at all.",
      };
  }
}
