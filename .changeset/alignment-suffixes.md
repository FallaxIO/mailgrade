---
"mailgrade": minor
---

Fix relaxed DMARC alignment under registry-operated second-level domains, and
let a caller supply the real Public Suffix List.

The built-in suffix rules were a fixed list of 42 two-label pairs. A pair not
on it — `gov.uk`, `ac.jp`, `org.cn`, `com.ec` — collapsed every host under it
to the pair itself, so `dept.gov.uk` and `attacker.gov.uk` shared an
organizational domain and relaxed alignment reported them as aligned. In
`mailgrade/verify` that is a DMARC pass for a signature the From domain's
owner never made.

- The suffix rules now treat the registry's own labels (`co`, `com`, `gov`,
  `ac`, `org`, `ne`, `sch`, …) as part of the suffix under any country code,
  rather than only for enumerated pairs. The remaining approximation errs
  toward reading a host as more specific than it is, which under-reports
  alignment instead of over-reporting it.
- `registrableDomain`, `domainLabel` and `aligns` take an optional
  `{ publicSuffixes }`, and `verifyDmarc` and `verifyMessage` accept and
  forward it. Supplying a list replaces the built-in rules entirely: the
  longest entry matching a host's tail is its public suffix. Pass the ICANN
  section of the real PSL where a wrong alignment decision has a cost.
