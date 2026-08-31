---
"mailgrade": major
---

First stable release.

No API changes from 0.2.0 — this marks the surface as settled and brings it
under semver: the grading, verification, DMARC record and header-analysis
entry points will not break without a major bump.

Releases are now published from CI through npm trusted publishing, so every
version carries a provenance attestation and no long-lived token exists.
