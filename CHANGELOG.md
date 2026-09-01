# mailgrade

## 2.0.0

### Major Changes

- [#3](https://github.com/FallaxIO/mailgrade/pull/3) [`bfdbdb6`](https://github.com/FallaxIO/mailgrade/commit/bfdbdb6056b0a076483710e078f8cdb23fcd1311) Thanks [@IgnaceMaes](https://github.com/IgnaceMaes)! - Rework the public interface around the calls people actually make, put a
  letter on the grade, and ship the grade as a CLI.
  
  **`npx mailgrade acme.com`.** The package now has a bin: the grade in a
  terminal (letter, verdict, per-mechanism headlines, and the fixes) with
  `--json` for scripts and `--strict` for CI, where a non-zero exit catches the
  day someone "temporarily" weakens the DMARC record. Zero dependencies, like
  everything else here.
  
  **A letter on the grade.** `DomainGrade` now carries `letter`, `"A+"` down to
  `"F"`. The verdict sets the band (enforcing, partial, nothing) and the details
  move within it; `+all` is an automatic `F`. The rubric lives in the spec
  corpus (`spec/grade.json`), so ports share it.
  
  **One import.** `gradeDomain`, `verifyMessage` and `analyzeHeaders` are now on
  `mailgrade` itself, so the common cases need no second import and no guessing
  at a subpath. Every existing entry point still resolves; `mailgrade/doh` and
  `mailgrade/verify` are now for narrowing a bundle, not for finding the API.
  
  **No setup.** `resolver` is optional everywhere it was required, defaulting to
  DNS over HTTPS. `verifyMessage(raw, { ip, sender })` works on its own, the way
  `checkDomain` already did. A Node service that wants the system resolver still
  passes `nodeResolver()` from `mailgrade/node-dns`.
  
  **Headers you can use.** `verifyMessage` takes `mta` and returns `authResults`
  and `headers`: a folded, CRLF-terminated `Received-SPF` and
  `Authentication-Results` block, ready to prepend to the message. The values
  embedded there arrive off the wire, so they are sanitised on the way in: a
  CRLF in a hostile MAIL FROM becomes a space, never a forged header field. The
  folder is quote-aware, so a legal `"a;b"@example.com` survives intact.
  
  `DmarcAnalysis` also gains `reporting`: whether the record carries a `rua=`
  tag, read with the same tag parsing as everything else.
  
  **Names that match the package.** The headline call is `gradeDomain`, not
  `checkDomain`: this library grades, and the README section has always been
  called "Grade a domain". The pure function that used to hold that name is now
  `gradeRecords`, which is what it always took; `gradeDomain(records)` named a
  domain and accepted `DomainRecords`. The trio now reads in order:
  `resolveDomain` -> `gradeRecords`, and `gradeDomain` for both at once.
  
  Breaking: the JSON conformance corpus is no longer published in the tarball,
  and the `mailgrade/spec/*` subpath is gone with it. The corpus stays in the
  repository, which is where a port reads it from.
  
  Breaking: the root barrel is now a curated list rather than `export *`, so
  roughly 25 internals no longer appear on `mailgrade`. Each is still exported
  from the entry point for its own area, so `blankCheck`, `editDistance`,
  `parseHeaders` and `stripComments` move to `mailgrade/headers`, `txtChunks`
  and `recordTags` to `mailgrade/dmarc`, and so on. `toAuthResults` keeps its
  signature and now accepts any object with the five fields it reads. The
  options type for `gradeDomain` and `resolveDomain` is now named
  `GradeDomainOptions` (was `DohOptions`).

## 1.0.0

### Major Changes

- [`e576838`](https://github.com/FallaxIO/mailgrade/commit/e576838dc1c305406f755bb4b8cb8aa3d58e2b02) Thanks [@IgnaceMaes](https://github.com/IgnaceMaes)! - First stable release.
  
  No API changes from 0.2.0; this marks the surface as settled and brings it
  under semver: the grading, verification, DMARC record and header-analysis
  entry points will not break without a major bump.
  
  Releases are now published from CI through npm trusted publishing, so every
  version carries a provenance attestation and no long-lived token exists.

## 0.2.0

### Minor Changes

- [`9c80dd2`](https://github.com/FallaxIO/mailgrade/commit/9c80dd2ff9abb7c037a70d770823999fdad7c02c) Thanks [@IgnaceMaes](https://github.com/IgnaceMaes)! - Fix relaxed DMARC alignment under registry-operated second-level domains, and
  let a caller supply the real Public Suffix List.
  
  The built-in suffix rules were a fixed list of 42 two-label pairs. A pair not
  on it (`gov.uk`, `ac.jp`, `org.cn`, `com.ec`) collapsed every host under it
  to the pair itself, so `dept.gov.uk` and `attacker.gov.uk` shared an
  organizational domain and relaxed alignment reported them as aligned. In
  `mailgrade/verify` that is a DMARC pass for a signature the From domain's
  owner never made.
  
  - The suffix rules now treat the registry's own labels (`co`, `com`, `gov`,
    `ac`, `org`, `ne`, `sch`, and so on) as part of the suffix under any
    country code, rather than only for enumerated pairs. The remaining
    approximation errs toward reading a host as more specific than it is,
    which under-reports alignment instead of over-reporting it.
  - `registrableDomain`, `domainLabel` and `aligns` take an optional
    `{ publicSuffixes }`, and `verifyDmarc` and `verifyMessage` accept and
    forward it. Supplying a list replaces the built-in rules entirely: the
    longest entry matching a host's tail is its public suffix. Pass the ICANN
    section of the real PSL where a wrong alignment decision has a cost.

- [`194029a`](https://github.com/FallaxIO/mailgrade/commit/194029ace58854252841baef8734b82b1f1d3372) - First release.
  
  Grade a domain's SPF, DMARC and DKIM configuration, build and review DMARC
  records, and analyse a pasted header block. Zero runtime dependencies, no
  network code outside the optional `mailgrade/doh` entry point, and a
  language-neutral conformance corpus in `spec/` so the rules can be ported.

- [`9c80dd2`](https://github.com/FallaxIO/mailgrade/commit/9c80dd2ff9abb7c037a70d770823999fdad7c02c) Thanks [@IgnaceMaes](https://github.com/IgnaceMaes)! - Add `mailgrade/node-dns`, a `Resolver` backed by `node:dns`.
  
  `nodeResolver()` resolves through the system resolver rather than a public
  DoH endpoint, which a service that does not want every lookup leaving the
  process (or that is grading domains in bulk against a rate-limited resolver)
  now gets without writing the adapter itself. It does the mapping the
  `Resolver` contract needs and that is easy to get wrong by hand: NXDOMAIN and
  ENODATA answer `[]` rather than throwing (a throw would be read as
  `temperror` where `fail` is correct), TXT chunks are rejoined, and MX answers
  are reduced to bare host names. `{ servers, timeout, tries }` build a
  dedicated `dns.Resolver`, never touching process-wide DNS configuration.
  
  `node:dns` is imported only by this entry point, and only on the first
  lookup, so `mailgrade`, `mailgrade/verify` and `mailgrade/doh` stay loadable
  in Workers and browsers.

- [`9c80dd2`](https://github.com/FallaxIO/mailgrade/commit/9c80dd2ff9abb7c037a70d770823999fdad7c02c) Thanks [@IgnaceMaes](https://github.com/IgnaceMaes)! - New `mailgrade/verify` entry point: real message verification, still at zero
  dependencies, still running anywhere WebCrypto and `fetch` do.
  
  - `verifySpf` evaluates a policy against a connecting IP per RFC 7208:
    every mechanism, the macro language, redirects, exp= explanations, and the
    limits receivers enforce (10 lookups, 2 void lookups, 10 MX hosts).
  - `verifyDkim` verifies DKIM signatures with WebCrypto: rsa-sha256 and
    ed25519-sha256, simple and relaxed canonicalization, l= body lengths, and
    the RFC 8301 refusals (rsa-sha1, RSA keys under 1024 bits).
  - `verifyDmarc` discovers the policy with the org-domain fallback and applies
    strict or relaxed alignment; `verifyMessage` runs all three on a raw message.
  - DNS is injected through a `Resolver`: `dohResolver()` (new, in
    `mailgrade/doh`) needs nothing but `fetch`, and `staticResolver(zone)`
    makes tests and offline evaluation trivial.
  - `toAuthResults` renders a verification as an RFC 8601
    Authentication-Results header value, ready to stamp onto the message,
    and readable back by `analyzeHeaders`.
  - `checkDomain` and `resolveDomain` accept the same `resolver` option, so a
    Node service can grade domains over `node:dns` instead of DoH.
  
  Fixes in the grader:
  
  - `analyzeSpf` now grades the **first** `all` mechanism rather than the last
    one, matching how receivers evaluate a record: in `"v=spf1 ?all -all"` the
    `-all` is dead code and the record is neutral.
  - `mailProvider` matches MX hosts by domain suffix instead of substring, so
    lookalike hosts no longer name the wrong provider.
  - `isDomainName` accepts punycode TLDs, so IDN domains take part in alignment
    checks instead of being skipped.
