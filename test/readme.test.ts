/**
 * The examples in README.md, run.
 *
 * A README that has drifted from the API is worse than none, and this is the
 * cheapest way to find out. Change an example here and in the README together.
 */

import { expect, it } from "vitest";
import { gradeDomain } from "../src/index.ts";
import { buildDmarcRecord, reviewDmarc, rolloutPlan } from "../src/dmarc/index.ts";
import { analyzeHeaders } from "../src/headers/index.ts";

it("grade example", () => {
  const grade = gradeDomain({
    domain: "acme.com",
    txt: ["v=spf1 include:_spf.google.com ~all"],
    dmarc: ["v=DMARC1; p=none; rua=mailto:dmarc@acme.com"],
    dkimSelectors: ["google"],
    mx: ["aspmx.l.google.com"],
  });
  expect(grade.verdict).toBe("spoofable");
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
  const raw = `Received: from vps.hosting.example (vps.hosting.example [185.22.11.9])
        by mx.acme.example with ESMTP id 4b2c1f;
        Mon, 2 Jun 2025 03:41:02 +0000
Authentication-Results: mx.acme.example;
       spf=pass smtp.mailfrom=billing@acme-invoices.example;
       dkim=none;
       dmarc=fail header.from=acme.example
Return-Path: <billing@acme-invoices.example>
From: Acme Finance <invoices@acme.example>
Reply-To: finance.acme@mail-secure.example
To: bob@acme.example
Subject: Overdue invoice
Date: Mon, 2 Jun 2025 03:41:00 +0000
X-PHP-Originating-Script: 0:sendmail.php

body`;
  const result = analyzeHeaders(raw);
  expect(result.verdict).toBe("suspicious");
  expect(result.spf.result).toBe("pass");
  expect(result.spf.aligned).toBe(false);
  expect(result.flags.map((f) => f.id)).toEqual([
    "dmarc-fail", "reply-to-mismatch", "return-path-mismatch", "php-origin",
  ]);
});
