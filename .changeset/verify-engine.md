---
"mailgrade": minor
---

New `mailgrade/verify` entry point: real message verification, still at zero
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
