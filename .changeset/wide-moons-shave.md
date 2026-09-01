---
"mailgrade": major
---

Rework the public interface around the calls people actually make, put a
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
