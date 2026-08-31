---
"mailgrade": minor
---

Add `mailgrade/node-dns`, a `Resolver` backed by `node:dns`.

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
