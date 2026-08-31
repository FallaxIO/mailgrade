<h1 align="center">mailgrade</h1>

<p align="center">
  <strong>Grade a domain's SPF, DMARC and DKIM.</strong><br>
  Zero dependencies. No network in the core. Runs in Node, Bun, Deno, Workers and the browser.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/mailgrade"><img alt="npm" src="https://img.shields.io/npm/v/mailgrade?color=%230b7285&label=npm"></a>
  <a href="https://bundlephobia.com/package/mailgrade"><img alt="size" src="https://img.shields.io/bundlephobia/minzip/mailgrade?color=%230b7285&label=min%2Bgzip"></a>
  <a href="./LICENSE"><img alt="license" src="https://img.shields.io/npm/l/mailgrade?color=%230b7285"></a>
</p>

---

`mailgrade` answers one question: **how far does mail claiming to be this domain
actually get?**

That is not the same question as "did this message pass". Nothing here does
cryptography or opens a socket. It reads what a domain publishes, or what a
receiving server wrote into a header block, and grades it the way a receiver
would act on it. A syntactically perfect `p=none` record is valid DMARC and
protects nothing, and `mailgrade` says so.

```ts
import { checkDomain } from "mailgrade/doh";

const grade = await checkDomain("example.com");

grade.verdict;            // "spoofable"
grade.dmarc.id;           // "dmarc-monitor"
grade.dmarc.headline;     // "DMARC is monitoring only (p=none)"
grade.recommendations[0]; // { id: "graduate-dmarc", text: "Graduate DMARC from p=none. ..." }
```

## Is this what you want?

| | `mailgrade` | [`mailauth`](https://github.com/postalsys/mailauth) | [`checkdmarc`](https://github.com/domainaware/checkdmarc) |
| --- | --- | --- | --- |
| Answers | is this domain forgeable | did **this message** pass | is this record valid |
| Verifies signatures | no | yes | no |
| Runtime deps | **0** | 10 | Python |
| Runs in a Worker or a browser | **yes** | no | no |
| Ships explanations and fixes | **yes** | no | no |

If you need to verify a message you have in hand, use `mailauth`. It is the
right tool and this is not a replacement for it. Use `mailgrade` to grade a
domain's configuration, to build a checker, or to read a header block that
somebody pasted.

## Install

```sh
npm i mailgrade
```

## Grade a domain

The core is pure, so DNS is yours to do. If you want it done for you, the
optional `mailgrade/doh` entry point resolves over DNS-over-HTTPS with nothing
but `fetch`:

```ts
import { checkDomain } from "mailgrade/doh";

const grade = await checkDomain("acme.com");
//    ^ verdict, spf, dmarc, dkim, mx, recommendations
```

Already have the records? Skip the network entirely:

```ts
import { gradeDomain } from "mailgrade";

const grade = gradeDomain({
  domain: "acme.com",
  txt: ["v=spf1 include:_spf.google.com ~all"],
  dmarc: ["v=DMARC1; p=none; rua=mailto:dmarc@acme.com"],
  dkimSelectors: ["google"],
  mx: ["aspmx.l.google.com"],
});

grade.verdict; // "spoofable"
```

The verdict is one of `protected`, `partial` or `spoofable`. DMARC policy
decides it, because DMARC is the tag receivers act on. SPF and DKIM decide
whether that policy has anything to align against, with one exception:
`+all` defeats even `p=reject`, because the forger's server is then genuinely
authorised and passes SPF honestly.

## Write and review a DMARC record

```ts
import { buildDmarcRecord, reviewDmarc, rolloutPlan } from "mailgrade/dmarc";

const options = {
  domain: "acme.com",
  policy: "reject",
  subdomainPolicy: "none",
  rua: ["dmarc@acme.com"],
  ruf: [], pct: 100, adkim: "r", aspf: "r", ri: 86400, fo: "0",
} as const;

buildDmarcRecord(options);
// "v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@acme.com"

reviewDmarc(options)[0];
// { id: "sp-weaker", severity: "high", title: "Subdomains are the weak point", detail: "..." }

rolloutPlan(options).map((s) => `${s.label}: ${s.record}`);
// four stages from monitoring to full rejection, keeping every other choice
```

Tags whose value is already the DMARC default are left out, so the record is
the shortest thing that says what you meant. `parseDmarcRecord` reads an
existing one back into the same shape, forgiving what receivers forgive and
loud about what they do not.

## Read a message's headers

```ts
import { analyzeHeaders } from "mailgrade/headers";

const result = analyzeHeaders(pastedHeaderBlock);

result.verdict;              // "suspicious"
result.spf.result;           // "pass"
result.spf.aligned;          // false  <- the pass was for somebody else's domain
result.flags.map((f) => f.id);
// ["dmarc-fail", "reply-to-mismatch", "return-path-mismatch", "php-origin"]
```

It reads the verdicts a receiving server recorded, falling back to
`Received-SPF` and then to ARC, and adds the part those headers leave out:
whether the identity that authenticated is the one in the From line. On top of
that it catches display-name tricks, bidi and zero-width characters, mixed
scripts, punycode, brand lookalikes, redirected replies and backdating.

No I/O, by design. Header blocks carry the recipient's address, their
colleagues' addresses, internal hostnames and internal IPs, and a tool that
asks a stranger to paste all of that has no business shipping it anywhere.

## Everything carries an id

Every finding, note, flag and recommendation has a stable `id` beside its
English:

```ts
{ id: "sp-weaker", severity: "high", title: "...", detail: "..." }
```

Branch on ids, not on sentences. Swap the prose for your own copy or another
language and nothing breaks. The [conformance corpus](./spec) asserts on ids
for the same reason.

## Entry points

| Import | What is in it |
| --- | --- |
| `mailgrade` | everything below except `doh` |
| `mailgrade/spf` | `analyzeSpf`, `isSpfRecord` |
| `mailgrade/dkim` | `analyzeDkim`, `isDkimKey`, `dkimHost`, `DKIM_SELECTORS` |
| `mailgrade/dmarc` | build, parse, review and roll out a record |
| `mailgrade/headers` | `analyzeHeaders` and its parsers |
| `mailgrade/domain` | `registrableDomain`, `aligns`, `coerceDomain` |
| `mailgrade/doh` | `checkDomain`, `resolveDomain`, the only code that opens a socket |

Import one and the rest is tree-shaken away. Nothing but `mailgrade/doh`
touches the network, so an app that resolves DNS its own way never bundles a
resolver.

## Ports

The rules live in [`spec/`](./spec) as JSON: an input, and a projection of the
result with ids in it and no English. A port in another language reads the same
files and is finished when they all pass. The TypeScript adapter is 120 lines.

## What this is not

- Not a message verifier. It never checks a DKIM signature or evaluates an SPF
  record against an IP. Use [`mailauth`](https://github.com/postalsys/mailauth).
- Not a DMARC report parser. Use
  [`parsedmarc`](https://github.com/domainaware/parsedmarc).
- Not a full Public Suffix List. It ships the two-label suffixes consumer mail
  lives under, and anything missing degrades safely: a host reads as more
  specific than it is, so alignment is under-reported rather than over-reported.

## License

MIT
