---
"mailgrade": minor
---

First release.

Grade a domain's SPF, DMARC and DKIM configuration, build and review DMARC
records, and analyse a pasted header block. Zero runtime dependencies, no
network code outside the optional `mailgrade/doh` entry point, and a
language-neutral conformance corpus in `spec/` so the rules can be ported.
