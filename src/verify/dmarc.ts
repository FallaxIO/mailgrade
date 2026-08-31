/**
 * DMARC evaluation, RFC 7489: discover the policy the way a receiver does,
 * then decide whether any authenticated identity aligns with the From domain.
 *
 * This is the capstone check. SPF and DKIM authenticate identities nobody
 * reads; DMARC is the rule that one of them has to be the identity everybody
 * reads.
 */

import { aligns, registrableDomain, type SuffixOptions } from "../domain.ts";
import { dmarcHost, isDmarcRecord } from "../dmarc/analyze.ts";
import { parseDmarcRecord, type Alignment, type DmarcPolicy } from "../dmarc/record.ts";
import type { Resolver } from "./resolver.ts";
import type { DkimVerification } from "./dkim.ts";
import type { SpfVerification } from "./spf.ts";

export type DmarcVerification = {
  readonly result: "pass" | "fail" | "none" | "temperror";
  /** What the policy asks a receiver to do with this message. */
  readonly disposition: "none" | "quarantine" | "reject";
  readonly fromDomain: string;
  readonly record: string | null;
  /** The host the record was found at; the org domain when inherited. */
  readonly source: string | null;
  readonly policy: DmarcPolicy | null;
  readonly pct: number;
  readonly adkim: Alignment;
  readonly aspf: Alignment;
  readonly spfAligned: boolean;
  readonly dkimAligned: boolean;
};

export type DmarcParams = {
  /** The domain in the message's From header. */
  readonly fromDomain: string;
  /** The SPF outcome, with the domain it authenticated (MAIL FROM or HELO). */
  readonly spf?: Pick<SpfVerification, "result" | "domain"> | null;
  /** One outcome per DKIM signature. */
  readonly dkim?: readonly Pick<DkimVerification, "result" | "domain">[];
  readonly resolver: Resolver;
} & SuffixOptions;

function identityAligns(
  identity: string | null,
  fromDomain: string,
  mode: Alignment,
  options: SuffixOptions,
): boolean {
  if (!identity) return false;
  return mode === "s"
    ? identity.toLowerCase() === fromDomain
    : aligns(identity, fromDomain, options);
}

export async function verifyDmarc(params: DmarcParams): Promise<DmarcVerification> {
  const fromDomain = params.fromDomain.trim().toLowerCase();
  const org = registrableDomain(fromDomain, params);

  const blank: DmarcVerification = {
    result: "none",
    disposition: "none",
    fromDomain,
    record: null,
    source: null,
    policy: null,
    pct: 100,
    adkim: "r",
    aspf: "r",
    spfAligned: false,
    dkimAligned: false,
  };

  let record: string | null = null;
  let source: string | null = null;
  try {
    const atDomain = (await params.resolver(dmarcHost(fromDomain), "TXT")).filter(
      isDmarcRecord,
    );
    // Exactly one record is a policy; several are a void, per the RFC.
    if (atDomain.length === 1) {
      record = atDomain[0] as string;
      source = fromDomain;
    } else if (atDomain.length === 0 && org && org !== fromDomain) {
      const atOrg = (await params.resolver(dmarcHost(org), "TXT")).filter(
        isDmarcRecord,
      );
      if (atOrg.length === 1) {
        record = atOrg[0] as string;
        source = org;
      }
    }
  } catch {
    return { ...blank, result: "temperror" };
  }

  if (record === null) return blank;

  const parsed = parseDmarcRecord(record, fromDomain);
  const usable = !parsed.errors.some(
    (e) => e.id === "missing-policy" || e.id === "bad-policy" || e.id === "bad-version" || e.id === "missing-version",
  );
  if (!usable) return { ...blank, record, source };

  const { policy, subdomainPolicy, pct, adkim, aspf } = parsed.options;

  const spfAligned =
    params.spf?.result === "pass" &&
    identityAligns(params.spf.domain, fromDomain, aspf, params);
  const dkimAligned = (params.dkim ?? []).some(
    (sig) =>
      sig.result === "pass" && identityAligns(sig.domain, fromDomain, adkim, params),
  );

  const pass = spfAligned || dkimAligned;
  // The record found at the org domain governs the subdomain through sp= when
  // it has one; a record on the domain itself always applies as p=.
  const applied =
    source !== fromDomain && subdomainPolicy !== "inherit"
      ? subdomainPolicy
      : policy;

  return {
    result: pass ? "pass" : "fail",
    disposition: pass ? "none" : applied,
    fromDomain,
    record,
    source,
    policy,
    pct,
    adkim,
    aspf,
    spfAligned,
    dkimAligned,
  };
}
