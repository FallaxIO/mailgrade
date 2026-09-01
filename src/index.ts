/**
 * The public API, named one at a time.
 *
 * This barrel is curated rather than a set of `export *`: the point of the
 * root import is that autocomplete on `mailgrade` shows the calls a reader
 * would recognise from the README, not the sixty helpers those calls are
 * built out of. Every internal remains reachable from the entry point for its
 * own area (`mailgrade/headers`, `mailgrade/dmarc`, `mailgrade/spf`, ...),
 * which is also where a rename is a smaller promise to keep.
 */

/* -------------------------------------------------------------- domain --- */

export { gradeDomain, resolveDomain } from "./doh.ts";
export type { GradeDomainOptions } from "./doh.ts";
export { gradeRecords, domainVerdict } from "./grade.ts";
export type {
  DomainGrade,
  DomainRecords,
  DomainVerdict,
  GradeLetter,
} from "./grade.ts";

/* ----------------------------------------------------------- messages --- */

export { verifyMessage, toAuthResults } from "./verify/index.ts";
export type {
  AuthResultsInput,
  MessageVerification,
  VerifyMessageOptions,
} from "./verify/index.ts";
export { verifySpf, verifyDkim, verifyDmarc } from "./verify/index.ts";
export type {
  DkimResult,
  DkimResultId,
  DkimVerification,
  DkimVerifyOptions,
  DmarcParams,
  DmarcVerification,
  SpfParams,
  SpfResult,
  SpfVerification,
} from "./verify/index.ts";

/* ------------------------------------------------------------ headers --- */

export { analyzeHeaders } from "./headers/index.ts";
export type {
  AuthSource,
  Flag,
  HeaderAnalysis,
  HeaderVerdict,
  Identity,
  MessageSummary,
  Route,
} from "./headers/index.ts";

/* -------------------------------------------------------- dmarc records --- */

export {
  buildDmarcRecord,
  parseDmarcRecord,
  reviewDmarc,
  rolloutPlan,
} from "./dmarc/index.ts";
export type {
  Alignment,
  DmarcError,
  DmarcErrorId,
  DmarcNote,
  DmarcOptions,
  DmarcParse,
  DmarcPolicy,
  RolloutStage,
  SubdomainPolicy,
} from "./dmarc/index.ts";

/* ------------------------------------------------------------- records --- */

export { analyzeSpf, isSpfRecord } from "./spf.ts";
export type { SpfAnalysis, SpfFinding, SpfQualifier } from "./spf.ts";
export { analyzeDkim, isDkimKey, dkimHost, DKIM_SELECTORS } from "./dkim.ts";
export type { DkimAnalysis, DkimFinding } from "./dkim.ts";
export { analyzeDmarc, isDmarcRecord, dmarcHost } from "./dmarc/index.ts";
export type { DmarcAnalysis, DmarcFinding } from "./dmarc/index.ts";
export { mailProvider } from "./mx.ts";

/* ----------------------------------------------------------------- dns --- */

export { dohResolver, DnsError } from "./doh.ts";
export { staticResolver } from "./verify/resolver.ts";
export type { DnsRecordType, Resolver } from "./verify/resolver.ts";
export type { DohResolverOptions, FetchLike } from "./doh-resolver.ts";

/* -------------------------------------------------------------- shared --- */

export { registrableDomain, aligns, domainOf, coerceDomain } from "./domain.ts";
export type { SuffixOptions } from "./domain.ts";
export type {
  AuthStatus,
  Identified,
  Note,
  Recommendation,
  Severity,
  Status,
} from "./types.ts";
