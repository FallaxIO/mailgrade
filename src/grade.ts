/**
 * Grading, given records somebody else fetched.
 *
 * `gradeDomain` in `mailgrade/doh` is this composed with the lookups; this is
 * the half that is pure, so a caller who already holds the DNS answers (a
 * cache, a bulk job, a fixture) never pays for a second round trip.
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

export type GradeLetter = "A+" | "A" | "B" | "C" | "D" | "F";

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
  /** The verdict as a report card, from A+ down to F. */
  readonly letter: GradeLetter;
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

export function gradeRecords(records: DomainRecords): DomainGrade {
  const domain = records.domain.trim().toLowerCase();
  // RFC 7505: a null MX ("MX 0 .") is a deliberate "this domain takes no
  // mail", and arrives as "." or, root dot stripped, as "". Neither is a mail
  // host, and treating one as a mail host would tell a no-mail domain to turn
  // on DKIM.
  const mxHosts = (records.mx ?? []).filter((h) => h !== "" && h !== ".");
  const spf = analyzeSpf(records.txt);
  const dmarc = analyzeDmarc(records.dmarc, records.dmarcSource ?? domain);
  const dkim = analyzeDkim(
    records.dkimSelectors ?? [],
    records.dkimProbed ?? DKIM_SELECTORS.length,
  );
  const verdict = domainVerdict(spf, dmarc);
  const parked = looksParked(spf, mxHosts);

  return {
    domain,
    verdict,
    letter: letterFor(verdict, spf, dmarc, dkim, parked),
    spf,
    dmarc,
    dkim,
    mx: { hosts: mxHosts, provider: mailProvider(mxHosts) },
    recommendations: recommend(domain, spf, dmarc, dkim, parked),
  };
}

/**
 * No MX and either no SPF or a bare "v=spf1 -all" reads as a domain that
 * does not do mail, so advice about signing and providers would be noise,
 * and absent DKIM is not held against the grade.
 */
function looksParked(spf: SpfAnalysis, mxHosts: readonly string[]): boolean {
  return (
    mxHosts.length === 0 &&
    (spf.record === null || /^v=spf1\s+-all$/i.test(spf.record.trim()))
  );
}

/**
 * The verdict as a report card. The verdict sets the band and the details
 * move within it:
 *
 * - `F`: spoofable with nothing effective published, or an SPF `+all`,
 *   which actively authorises the spoof.
 * - `D`: spoofable, but something is in place (a monitoring-only DMARC, or
 *   decent SPF with no DMARC behind it).
 * - `C`: partial enforcement: quarantine, a sampled reject, or a weaker
 *   subdomain policy.
 * - `B`: enforcing, but SPF is broken or missing, or a sending domain shows
 *   no DKIM keys, so enforcement rests on fewer legs than it should.
 * - `A`: enforcing, with SPF and DKIM both standing behind it.
 * - `A+`: as `A`, with SPF ending in `-all` and aggregate reports flowing
 *   somewhere (`rua=`), so drift will be noticed.
 */
function letterFor(
  verdict: DomainVerdict,
  spf: SpfAnalysis,
  dmarc: DmarcAnalysis,
  dkim: DkimAnalysis,
  parked: boolean,
): GradeLetter {
  if (verdict === "partial") return "C";

  if (verdict === "spoofable") {
    if (spf.id === "spf-allow-all") return "F";
    if (dmarc.record === null && spf.status === "fail") return "F";
    return "D";
  }

  const spfBroken = spf.status === "fail";
  const unsignedSender = dkim.selectorsFound.length === 0 && !parked;
  if (spfBroken || unsignedSender) return "B";

  return spf.id === "spf-hardfail" && dmarc.reporting ? "A+" : "A";
}

function recommend(
  domain: string,
  spf: SpfAnalysis,
  dmarc: DmarcAnalysis,
  dkim: DkimAnalysis,
  sendsNothing: boolean,
): Recommendation[] {
  const recs: Recommendation[] = [];

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
