<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./.github/assets/banner-dark.svg">
    <img alt="mailgrade: grade a domain's SPF, DMARC and DKIM. Zero dependencies, one call, runs anywhere." src="./.github/assets/banner-light.svg" width="860">
  </picture>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/mailgrade"><img alt="npm" src="https://img.shields.io/npm/v/mailgrade?color=%23008F73&label=npm"></a>
  <a href="https://bundlephobia.com/package/mailgrade"><img alt="size" src="https://img.shields.io/bundlephobia/minzip/mailgrade?color=%23008F73&label=min%2Bgzip"></a>
  <a href="./LICENSE"><img alt="license" src="https://img.shields.io/npm/l/mailgrade?color=%23008F73"></a>
</p>

<p align="center">
  Grade and verify SPF, DKIM and DMARC. One call, no setup.<br>
  Zero dependencies. Runs wherever <code>fetch</code> and WebCrypto do: Node, Bun, Deno, Cloudflare Workers, browsers.
</p>

```sh
npm i mailgrade         # the library
npx mailgrade acme.com  # the grade, right now
```

## In the terminal

```
$ npx mailgrade acme.com

  acme.com

   D  spoofable
  mail claiming to be this domain can reach inboxes

  ✓ SPF    SPF ends in -all
  ✓ DKIM   DKIM keys published (google)
  ✗ DMARC  DMARC is monitoring only (p=none)
  · MX     Google Workspace

  → Graduate DMARC from p=none. Monitoring mode was designed as a
    transition, not a destination: once the reports show your real senders
    passing, move to p=quarantine, then p=reject.
```

`--json` prints the whole grade for scripts, and `--strict` exits non-zero
unless the verdict is `protected`, so one line of CI catches the day someone
"temporarily" weakens the DMARC record.

## Grade a domain

Is this domain spoofable, and what is the fix?

```ts
import { gradeDomain } from "mailgrade";

const grade = await gradeDomain("acme.com");

grade.letter;             // "D", from "A+" down to "F"
grade.verdict;            // "spoofable" | "partial" | "protected"
grade.dmarc.headline;     // "DMARC is monitoring only (p=none)"
grade.recommendations[0]; // { id: "graduate-dmarc", text: "Graduate DMARC from p=none. ..." }
```

The letter is the verdict as a report card. DMARC policy sets the band
(enforcing, partial, or nothing) and the details move within it, while an SPF
`+all` is an automatic `F`, because it authorises the spoof by name.
`gradeDomain` is `resolveDomain` and `gradeRecords` composed, and both are
exported: resolve once and grade later, or grade records you already hold.

## Verify a message

For when you are the receiver: a Workers email handler, an inbound webhook, an
SMTP server.

```ts
import { verifyMessage } from "mailgrade";

const result = await verifyMessage(rawMessage, {
  ip: "203.0.113.50",           // who connected
  sender: "bounce@example.com", // MAIL FROM
  helo: "mail.example.com",     // HELO/EHLO
  mta: "mx.acme.com",           // you, the authserv-id in the headers below
});

result.dmarc?.result;      // "pass" | "fail" | "none"
result.dmarc?.disposition; // what to do with it, once the policy is applied:
                           // "none" | "quarantine" | "reject"
```

`result.headers` is the block to prepend before handing the message on,
folded and CRLF-terminated:

```
Received-SPF: pass (mx.acme.com: domain of bounce@example.com designates
 203.0.113.50 as permitted sender) client-ip=203.0.113.50;
 envelope-from="bounce@example.com"; helo=mail.example.com
Authentication-Results: mx.acme.com;
 spf=pass smtp.mailfrom=bounce@example.com;
 dkim=pass header.d=example.com header.s=mail;
 dmarc=pass header.from=example.com
```

SPF is evaluated against the connecting IP (RFC 7208, macros and lookup limits
included), DKIM signatures are verified with WebCrypto (rsa-sha256 and
ed25519-sha256; rsa-sha1 and sub-1024-bit keys refused per RFC 8301), and DMARC
alignment ties them to the From domain. A DNS failure is always a `temperror`,
never a `fail`. `verifySpf`, `verifyDkim` and `verifyDmarc` are also standalone
calls.

> [!IMPORTANT]
> Alignment needs a public suffix list, and the built-in rules are an
> approximation that under-reports alignment rather than over-reporting it.
> Where a verdict decides whether mail is delivered, pass `{ publicSuffixes }`,
> the ICANN section of the real list, to `verifyMessage`, `verifyDmarc`,
> `registrableDomain` or `aligns`.

## Triage a header block

For "is this email real": the headers off a reported message, no cryptography,
no I/O, nothing leaving the process.

```ts
import { analyzeHeaders } from "mailgrade";

const headers = `Received: from vps.hosting.example (185.22.11.9) by mx.acme.example;
       Mon, 2 Jun 2025 03:41:02 +0000
Authentication-Results: mx.acme.example;
       spf=pass smtp.mailfrom=billing@acme-invoices.example;
       dkim=none;
       dmarc=fail header.from=acme.example
Return-Path: <billing@acme-invoices.example>
From: Acme Finance <invoices@acme.example>
Reply-To: finance.acme@mail-secure.example
Subject: Overdue invoice
X-PHP-Originating-Script: 0:sendmail.php`;

const result = analyzeHeaders(headers);

result.verdict;     // "suspicious" | "inconclusive" | "authentic"
result.spf.aligned; // false, the SPF pass was for acme-invoices.example
result.flags.map((f) => f.id);
// ["dmarc-fail", "reply-to-mismatch", "return-path-mismatch", "php-origin"]
```

Reads the verdicts the receiving server recorded, adds alignment, and flags
display-name tricks, lookalike domains, punycode, hidden characters and
redirected replies.

## DMARC records

```ts
import { buildDmarcRecord, reviewDmarc, rolloutPlan } from "mailgrade";

const options = {
  domain: "acme.com", policy: "reject", subdomainPolicy: "none",
  rua: ["dmarc@acme.com"], ruf: [], pct: 100,
  adkim: "r", aspf: "r", ri: 86400, fo: "0",
} as const;

buildDmarcRecord(options); // "v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@acme.com"
reviewDmarc(options)[0];   // { id: "sp-weaker", severity: "high", ... }
rolloutPlan(options);      // four staged records, monitoring to full reject
```

## Where DNS comes from

Every call that needs DNS takes an optional `resolver`, and defaults to
DNS-over-HTTPS against Cloudflare so that nothing needs configuring. Swap it:

| To resolve with | Pass |
| --- | --- |
| The system resolver | `{ resolver: nodeResolver() }` from `mailgrade/node-dns` |
| Another DoH provider | `{ resolver: dohResolver({ endpoint }) }` |
| A plain object, in tests | `{ resolver: staticResolver({ "example.com": { TXT: [...] } }) }` |
| Anything else | `{ resolver }`, any `(name, type) => Promise<string[]>` |
| Nothing at all | `gradeRecords({ domain, txt, dmarc, ... })`, records you already hold |

A long-running Node service usually wants `nodeResolver()`: it keeps lookups
inside the network you already trust.

## Entry points

`mailgrade` carries the whole documented API, so a single import is the normal
way in. The subpaths (`/verify`, `/headers`, `/dmarc`, `/spf`, `/dkim`,
`/domain`, `/doh`) narrow what a bundle pulls in and reach the helpers each
area is built from. Only `mailgrade/node-dns` has to stay separate: it is the
one file that touches `node:dns`, so nothing else can drag a Node built-in
into a Worker or a browser bundle.

## Notes

- **Ids are the contract.** Every finding carries a stable `id` next to its
  English. Branch on ids; swap or translate the prose freely.
- **The rules are portable.** They live as a language-neutral JSON corpus in
  [`spec/`](https://github.com/FallaxIO/mailgrade/tree/main/spec) in the
  repository. A port passes the same files; the TypeScript adapter is about
  150 lines.
- **No ARC.** Mail that arrived through a forwarder or a mailing list has
  usually had its SPF broken and its body rewritten, so DMARC fails here
  exactly as it does at any receiver that ignores ARC. For ARC or BIMI, or for
  a high-volume Node MTA, use
  [`mailauth`](https://github.com/postalsys/mailauth).

## About

Built and maintained by [Fallax](https://fallax.io), phishing simulations and
security awareness training on autopilot. MIT licensed.
