/**
 * The headline call: everything a domain publishes, in one verdict.
 *
 * The grade answers "how far does mail claiming to be this domain get", which
 * is why DMARC policy decides the verdict and SPF and DKIM decide whether that
 * policy has anything to align against.
 */

import { analyzeDkim, DKIM_SELECTORS, type DkimAnalysis } from "./dkim.ts";
import { analyzeDmarc, type DmarcAnalysis } from "./dmarc/analyze.ts";
import { mailProvider } from "./mx.ts";
import { analyzeSpf, type SpfAnalysis } from "./spf.ts";
import type { Recommendation } from "./types.ts";

export type DomainVerdict = "spoofable" | "partial" | "protected";

/** Raw DNS answers, however the caller obtained them. */
export type DomainRecords = {
  readonly domain: string;
  /** Every TXT record at the apex, not only the SPF one. */
  readonly txt: readonly string[];
  /** TXT records at `_dmarc.<domain>`, or at the organizational domain. */
  readonly dmarc: readonly string[];
  /** The host the DMARC records came from, when it is not the domain itself. */
  readonly dmarcSource?: string | null;
  /** Selectors that answered with a usable key. */
  readonly dkimSelectors?: readonly string[];
  /** How many selectors were probed, for honest wording on a miss. */
  readonly dkimProbed?: number;
  readonly mx?: readonly string[];
};

export type DomainGrade = {
  readonly domain: string;
  readonly verdict: DomainVerdict;
  readonly spf: SpfAnalysis;
  readonly dmarc: DmarcAnalysis;
  readonly dkim: DkimAnalysis;
  readonly mx: { readonly hosts: readonly string[]; readonly provider: string | null };
  readonly recommendations: readonly Recommendation[];
};

/**
 * +all is the one SPF state that defeats an enforcing DMARC policy: the
 * spoofer's server is genuinely authorised, so their mail passes SPF with an
 * aligned domain and DMARC waves it through.
 */
export function domainVerdict(
  spf: SpfAnalysis,
  dmarc: DmarcAnalysis,
): DomainVerdict {
  if (spf.allQualifier === "+") return "spoofable";
  if (dmarc.status === "fail") return "spoofable";
  if (dmarc.status === "warn") return "partial";
  return "protected";
}

export function gradeDomain(records: DomainRecords): DomainGrade {
  const domain = records.domain.trim().toLowerCase();
  const mxHosts = records.mx ?? [];
  const spf = analyzeSpf(records.txt);
  const dmarc = analyzeDmarc(records.dmarc, records.dmarcSource ?? domain);
  const dkim = analyzeDkim(
    records.dkimSelectors ?? [],
    records.dkimProbed ?? DKIM_SELECTORS.length,
  );

  return {
    domain,
    verdict: domainVerdict(spf, dmarc),
    spf,
    dmarc,
    dkim,
    mx: { hosts: mxHosts, provider: mailProvider(mxHosts) },
    recommendations: recommend(domain, spf, dmarc, dkim, mxHosts),
  };
}

function recommend(
  domain: string,
  spf: SpfAnalysis,
  dmarc: DmarcAnalysis,
  dkim: DkimAnalysis,
  mxHosts: readonly string[],
): Recommendation[] {
  const recs: Recommendation[] = [];

  // No MX and either no SPF or a bare "v=spf1 -all" reads as a domain that
  // does not do mail, so advice about signing and providers would be noise.
  const sendsNothing =
    mxHosts.length === 0 &&
    (spf.record === null || /^v=spf1\s+-all$/i.test(spf.record.trim()));

  if (sendsNothing && (spf.record === null || dmarc.status !== "pass")) {
    recs.push({
      id: "lock-parked-domain",
      text: `If ${domain} never sends or receives mail, lock it anyway: publish "v=spf1 -all" and a DMARC record with p=reject. Parked domains are the easiest ones to spoof because nobody is watching them.`,
    });
  }

  if (spf.allQualifier === "+") {
    recs.push({
      id: "remove-plus-all",
      text: "Remove +all from the SPF record immediately. It authorises the whole internet by name and overrides everything else you set up.",
    });
  } else if (spf.record === null && !sendsNothing) {
    recs.push({
      id: "publish-spf",
      text: 'Publish an SPF record listing the services that send for you, ending in -all or ~all, for example "v=spf1 include:_spf.google.com ~all".',
    });
  } else if (spf.record !== null && spf.status === "fail") {
    recs.push({
      id: "fix-spf-all",
      text: "Fix the SPF record so it ends in -all (or at least ~all): a neutral or missing all mechanism leaves unlisted senders unjudged.",
    });
  }

  if (dkim.selectorsFound.length === 0 && !sendsNothing) {
    recs.push({
      id: "enable-dkim",
      text: "Turn on DKIM signing in your mail provider's admin console and publish the selector records it gives you. DMARC is far more reliable when DKIM, not just SPF, can align.",
    });
  }

  if (dmarc.record === null) {
    recs.push({
      id: "publish-dmarc",
      text: `Publish a DMARC record at _dmarc.${domain}. Start with "v=DMARC1; p=none; rua=mailto:dmarc@${domain}" to collect reports, then move to quarantine and on to reject once legitimate mail passes.`,
    });
  } else if (dmarc.policy === "none") {
    recs.push({
      id: "graduate-dmarc",
      text: "Graduate DMARC from p=none. Monitoring mode was designed as a transition, not a destination: once the reports show your real senders passing, move to p=quarantine, then p=reject.",
    });
  } else if (dmarc.status === "warn") {
    recs.push({
      id: "tighten-dmarc",
      text: "Tighten the DMARC record to a full p=reject with no pct sampling and no weaker sp subdomain policy.",
    });
  }

  if (recs.length === 0) {
    recs.push(
      sendsNothing
        ? {
            id: "nothing-to-add",
            text: "This domain is locked down for a domain that does not send mail. Nothing to add on the records side.",
          }
        : {
            id: "keep-watching",
            text: "Keep reading the DMARC aggregate reports: enforcement only stays safe while every legitimate sender keeps passing, and new SaaS tools that send mail as you appear all the time.",
          },
    );
  }

  return recs;
}
