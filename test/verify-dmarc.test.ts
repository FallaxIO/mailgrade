/**
 * DMARC evaluation: discovery with the org-domain fallback, both alignment
 * modes, and the sp= subdomain policy. Plus verifyMessage end to end.
 */

import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { analyzeHeaders } from "../src/headers/analyze.ts";
import { verifyDmarc } from "../src/verify/dmarc.ts";
import { toAuthResults, verifyMessage } from "../src/verify/index.ts";
import { staticResolver } from "../src/verify/resolver.ts";

const pass = { result: "pass" } as const;

describe("discovery", () => {
  it("reports none when no record exists anywhere", async () => {
    const r = await verifyDmarc({
      fromDomain: "example.com",
      resolver: staticResolver({}),
    });
    expect(r.result).toBe("none");
    expect(r.disposition).toBe("none");
  });

  it("falls back to the organizational domain for a subdomain", async () => {
    const r = await verifyDmarc({
      fromDomain: "mail.example.com",
      dkim: [{ ...pass, domain: "mail.example.com" }],
      resolver: staticResolver({
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject"] },
      }),
    });
    expect(r.source).toBe("example.com");
    expect(r.result).toBe("pass");
  });

  it("treats multiple records as no policy", async () => {
    const r = await verifyDmarc({
      fromDomain: "example.com",
      resolver: staticResolver({
        "_dmarc.example.com": {
          TXT: ["v=DMARC1; p=reject", "v=DMARC1; p=none"],
        },
      }),
    });
    expect(r.result).toBe("none");
  });

  it("reports temperror when DNS fails", async () => {
    const r = await verifyDmarc({
      fromDomain: "example.com",
      resolver: staticResolver({ "_dmarc.example.com": "TEMPERROR" }),
    });
    expect(r.result).toBe("temperror");
  });
});

describe("alignment", () => {
  const rejectAll = staticResolver({
    "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject"] },
  });

  it("passes on an aligned DKIM signature", async () => {
    const r = await verifyDmarc({
      fromDomain: "example.com",
      dkim: [{ ...pass, domain: "mailer.example.com" }],
      resolver: rejectAll,
    });
    expect(r.result).toBe("pass");
    expect(r.dkimAligned).toBe(true);
    expect(r.disposition).toBe("none");
  });

  it("passes on aligned SPF alone", async () => {
    const r = await verifyDmarc({
      fromDomain: "example.com",
      spf: { ...pass, domain: "bounce.example.com" },
      resolver: rejectAll,
    });
    expect(r.result).toBe("pass");
    expect(r.spfAligned).toBe(true);
  });

  it("fails when every pass belongs to someone else", async () => {
    const r = await verifyDmarc({
      fromDomain: "example.com",
      spf: { ...pass, domain: "attacker.example.net" },
      dkim: [{ ...pass, domain: "attacker.example.net" }],
      resolver: rejectAll,
    });
    expect(r.result).toBe("fail");
    expect(r.disposition).toBe("reject");
  });

  it("enforces strict alignment when asked", async () => {
    const r = await verifyDmarc({
      fromDomain: "example.com",
      dkim: [{ ...pass, domain: "mailer.example.com" }],
      resolver: staticResolver({
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=quarantine; adkim=s"] },
      }),
    });
    expect(r.result).toBe("fail");
    expect(r.disposition).toBe("quarantine");
  });

  it("ignores an unaligned pass but keeps the aligned one", async () => {
    const r = await verifyDmarc({
      fromDomain: "example.com",
      spf: { ...pass, domain: "esp.example.org" },
      dkim: [{ ...pass, domain: "example.com" }],
      resolver: rejectAll,
    });
    expect(r.result).toBe("pass");
    expect(r.spfAligned).toBe(false);
    expect(r.dkimAligned).toBe(true);
  });

  it("applies sp= to a subdomain governed by the org record", async () => {
    const r = await verifyDmarc({
      fromDomain: "billing.example.com",
      resolver: staticResolver({
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; sp=quarantine"] },
      }),
    });
    expect(r.result).toBe("fail");
    expect(r.disposition).toBe("quarantine");
  });
});

const relax = (raw: string) => {
  const i = raw.indexOf(":");
  return `${raw.slice(0, i).toLowerCase()}:${raw.slice(i + 1).replace(/[ \t]+/g, " ").trim()}`;
};

describe("verifyMessage", () => {
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });

  const from = "From: Billing <billing@example.com>";
  const to = "To: customer@example.net";
  const subject = "Subject: Invoice 42";
  const body = "Please find the invoice attached.\r\n";

  const bh = createHash("sha256")
    .update(Buffer.from(body, "latin1"))
    .digest("base64");
  const value = `v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=mail; h=from:to:subject; bh=${bh}; b=`;
  const data = [from, to, subject].map((h) => `${relax(h)}\r\n`).join("") +
    relax(`DKIM-Signature: ${value}`);
  const signer = createSign("RSA-SHA256");
  signer.update(Buffer.from(data, "latin1"));
  const b = signer.sign(rsa.privateKey).toString("base64");

  const message = `DKIM-Signature: ${value}${b}\r\n${from}\r\n${to}\r\n${subject}\r\n\r\n${body}`;

  const resolver = staticResolver({
    "mail._domainkey.example.com": {
      TXT: [
        `v=DKIM1; k=rsa; p=${rsa.publicKey.export({ type: "spki", format: "der" }).toString("base64")}`,
      ],
    },
    "example.com": { TXT: ["v=spf1 ip4:192.0.2.0/24 -all"] },
    "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject"] },
  });

  it("runs the three checks and aligns them", async () => {
    const r = await verifyMessage(message, {
      resolver,
      ip: "192.0.2.7",
      sender: "bounces@example.com",
    });
    expect(r.fromDomain).toBe("example.com");
    expect(r.spf?.result).toBe("pass");
    expect(r.dkim[0]?.result).toBe("pass");
    expect(r.dmarc?.result).toBe("pass");
    expect(r.dmarc?.spfAligned).toBe(true);
    expect(r.dmarc?.dkimAligned).toBe(true);
  });

  it("catches the classic spoof: honest SPF for the wrong domain", async () => {
    const spoofResolver = staticResolver({
      "attacker.example.org": { TXT: ["v=spf1 ip4:203.0.113.0/24 -all"] },
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject"] },
    });
    const spoof = `${from}\r\n${to}\r\n${subject}\r\n\r\n${body}`;
    const r = await verifyMessage(spoof, {
      resolver: spoofResolver,
      ip: "203.0.113.50",
      sender: "bounce@attacker.example.org",
    });
    expect(r.spf?.result).toBe("pass"); // honestly, for the attacker's domain
    expect(r.dkim).toHaveLength(0);
    expect(r.dmarc?.result).toBe("fail");
    expect(r.dmarc?.disposition).toBe("reject");
  });

  it("skips SPF without an IP and still verifies DKIM", async () => {
    const r = await verifyMessage(message, { resolver });
    expect(r.spf).toBeNull();
    expect(r.dkim[0]?.result).toBe("pass");
    expect(r.dmarc?.result).toBe("pass");
  });

  it("stamps an Authentication-Results header analyzeHeaders can read back", async () => {
    const r = await verifyMessage(message, {
      resolver,
      ip: "192.0.2.7",
      sender: "bounces@example.com",
    });
    const header = toAuthResults(r, "mx.example.net");
    expect(header).toBe(
      "mx.example.net; spf=pass smtp.mailfrom=bounces@example.com; " +
        "dkim=pass header.d=example.com header.s=mail; " +
        "dmarc=pass header.from=example.com",
    );

    const read = analyzeHeaders(`Authentication-Results: ${header}\r\n${message}`);
    expect(read.spf.result).toBe("pass");
    expect(read.dkim.result).toBe("pass");
    expect(read.dmarc.result).toBe("pass");
    expect(read.verdict).toBe("authentic");
  });

  it("stamps none when there was nothing to check", () => {
    expect(
      toAuthResults({ fromDomain: null, sender: null, spf: null, dkim: [], dmarc: null }),
    ).toBe("mailgrade; none");
  });
});

describe("public suffixes", () => {
  const zone = {
    "_dmarc.dept.gov.uk": { TXT: ["v=DMARC1; p=reject"] },
  };

  it("does not align two registrants under an administrative suffix", async () => {
    const r = await verifyDmarc({
      fromDomain: "dept.gov.uk",
      dkim: [{ ...pass, domain: "attacker.gov.uk" }],
      resolver: staticResolver(zone),
    });
    expect(r.dkimAligned).toBe(false);
    expect(r.result).toBe("fail");
    expect(r.disposition).toBe("reject");
  });

  it("follows a supplied list instead of the built-in rules", async () => {
    const r = await verifyDmarc({
      fromDomain: "dept.gov.uk",
      dkim: [{ ...pass, domain: "attacker.gov.uk" }],
      resolver: staticResolver(zone),
      // A list that says `uk` is the whole suffix makes the two share an
      // organizational domain, which is exactly what the caller asked for.
      publicSuffixes: ["uk"],
    });
    expect(r.dkimAligned).toBe(true);
    expect(r.result).toBe("pass");
  });

  it("reaches verifyMessage as an option", async () => {
    const message = [
      "From: Payroll <payroll@dept.gov.uk>",
      "Subject: hello",
      "",
      "body",
    ].join("\r\n");
    const r = await verifyMessage(message, {
      resolver: staticResolver(zone),
      publicSuffixes: ["gov.uk"],
    });
    expect(r.dmarc?.fromDomain).toBe("dept.gov.uk");
    expect(r.dmarc?.result).toBe("fail");
  });
});
