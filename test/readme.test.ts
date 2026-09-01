/**
 * The examples in README.md, run.
 *
 * A README that has drifted from the API is worse than none, and this is the
 * cheapest way to find out. Change an example here and in the README together.
 */

import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { expect, it } from "vitest";

// Every import the README makes is from the root, so this is where a name
// that quietly left the public barrel shows up.
import {
  analyzeHeaders,
  buildDmarcRecord,
  gradeRecords,
  reviewDmarc,
  rolloutPlan,
  staticResolver,
  verifyMessage,
} from "../src/index.ts";

it("grade example", () => {
  const grade = gradeRecords({
    domain: "acme.com",
    txt: ["v=spf1 include:_spf.google.com ~all"],
    dmarc: ["v=DMARC1; p=none; rua=mailto:dmarc@acme.com"],
    dkimSelectors: ["google"],
    mx: ["aspmx.l.google.com"],
  });
  expect(grade.verdict).toBe("spoofable");
  expect(grade.letter).toBe("D");
  expect(grade.dmarc.id).toBe("dmarc-monitor");
  expect(grade.dmarc.headline).toBe("DMARC is monitoring only (p=none)");
  expect(grade.recommendations[0]!.id).toBe("graduate-dmarc");
});

it("dmarc example", () => {
  const options = {
    domain: "acme.com", policy: "reject", subdomainPolicy: "none",
    rua: ["dmarc@acme.com"], ruf: [], pct: 100,
    adkim: "r", aspf: "r", ri: 86400, fo: "0",
  } as const;
  expect(buildDmarcRecord(options)).toBe("v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@acme.com");
  expect(reviewDmarc(options)[0]!.id).toBe("sp-weaker");
  expect(rolloutPlan(options)).toHaveLength(4);
});

it("headers example", () => {
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
  expect(result.verdict).toBe("suspicious");
  expect(result.spf.result).toBe("pass");
  expect(result.spf.aligned).toBe(false);
  expect(result.flags.map((f) => f.id)).toEqual([
    "dmarc-fail", "reply-to-mismatch", "return-path-mismatch", "php-origin",
  ]);
});

/** Relaxed header canonicalization, which is what the signature covers. */
const relax = (header: string) =>
  header.replace(/^([^:]+):\s*/, (_, name: string) => `${name.toLowerCase()}:`);

it("verify example: the header block, exactly as printed", async () => {
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });

  const from = "From: Billing <billing@example.com>";
  const to = "To: customer@acme.com";
  const subject = "Subject: Invoice 42";
  const body = "Please find the invoice attached.\r\n";

  const bh = createHash("sha256").update(Buffer.from(body, "latin1")).digest("base64");
  const value =
    `v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=mail; ` +
    `h=from:to:subject; bh=${bh}; b=`;
  const signed =
    [from, to, subject].map((h) => `${relax(h)}\r\n`).join("") +
    relax(`DKIM-Signature: ${value}`);
  const signer = createSign("RSA-SHA256");
  signer.update(Buffer.from(signed, "latin1"));
  const b = signer.sign(rsa.privateKey).toString("base64");

  const rawMessage =
    `DKIM-Signature: ${value}${b}\r\n${from}\r\n${to}\r\n${subject}\r\n\r\n${body}`;

  const result = await verifyMessage(rawMessage, {
    ip: "203.0.113.50",
    sender: "bounce@example.com",
    helo: "mail.example.com",
    mta: "mx.acme.com",
    resolver: staticResolver({
      "example.com": { TXT: ["v=spf1 ip4:203.0.113.0/24 -all"] },
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject"] },
      "mail._domainkey.example.com": {
        TXT: [
          `v=DKIM1; k=rsa; p=${rsa.publicKey
            .export({ type: "spki", format: "der" })
            .toString("base64")}`,
        ],
      },
    }),
  });

  expect(result.dmarc?.result).toBe("pass");
  // What to do with this message, not the policy the domain publishes: it
  // passed, so nothing.
  expect(result.dmarc?.disposition).toBe("none");
  expect(result.headers).toBe(
    "Received-SPF: pass (mx.acme.com: domain of bounce@example.com designates\r\n" +
      " 203.0.113.50 as permitted sender) client-ip=203.0.113.50;\r\n" +
      ' envelope-from="bounce@example.com"; helo=mail.example.com\r\n' +
      "Authentication-Results: mx.acme.com;\r\n" +
      " spf=pass smtp.mailfrom=bounce@example.com;\r\n" +
      " dkim=pass header.d=example.com header.s=mail;\r\n" +
      " dmarc=pass header.from=example.com\r\n",
  );
});
