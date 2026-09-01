/**
 * The headers `verifyMessage` hands back, which are the whole point of
 * verifying on the way in: a receiver prepends them and every downstream
 * filter reads them instead of redoing the work.
 *
 * The test that matters most here is the round trip. A header this library
 * generates has to be one `analyzeHeaders` parses, folding included, or the
 * two halves of the package disagree about the same message.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { analyzeHeaders } from "../src/headers/index.ts";
import { staticResolver, verifyMessage } from "../src/verify/index.ts";

const from = "From: Billing <billing@example.com>";
const message = `${from}\r\nTo: customer@example.net\r\nSubject: Invoice 42\r\n\r\nbody\r\n`;

const resolver = staticResolver({
  "example.com": { TXT: ["v=spf1 ip4:192.0.2.0/24 -all"] },
  "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject"] },
});

const arrived = {
  resolver,
  ip: "192.0.2.7",
  sender: "bounces@example.com",
  helo: "mail.example.com",
  mta: "mx.example.net",
} as const;

/** What a receiving parser does before reading a field: undo the folding. */
const unfold = (headers: string) => headers.replace(/\r\n[ \t]/g, " ");

describe("generated headers", () => {
  it("stamps Received-SPF and Authentication-Results, ready to prepend", async () => {
    const r = await verifyMessage(message, arrived);

    expect(r.authResults).toBe(
      "mx.example.net; spf=pass smtp.mailfrom=bounces@example.com; " +
        "dmarc=pass header.from=example.com",
    );
    expect(r.headers).toBe(
      "Received-SPF: pass (mx.example.net: domain of bounces@example.com designates\r\n" +
        " 192.0.2.7 as permitted sender) client-ip=192.0.2.7;\r\n" +
        ' envelope-from="bounces@example.com"; helo=mail.example.com\r\n' +
        "Authentication-Results: mx.example.net;\r\n" +
        " spf=pass smtp.mailfrom=bounces@example.com;\r\n" +
        " dmarc=pass header.from=example.com\r\n",
    );
  });

  it("prepends onto a message and reads back the same verdict", async () => {
    const r = await verifyMessage(message, arrived);
    const delivered = `${r.headers}${message}`;

    const read = analyzeHeaders(delivered);
    expect(read.spf.result).toBe("pass");
    expect(read.spf.aligned).toBe(true);
    expect(read.dmarc.result).toBe("pass");
    expect(read.verdict).toBe("authentic");
  });

  it("folds every generated line inside the RFC 5322 limit", async () => {
    const r = await verifyMessage(message, arrived);
    for (const line of r.headers.split("\r\n")) {
      expect(line.length).toBeLessThanOrEqual(78);
    }
  });

  it("names the authserv-id mailgrade when no mta is given", async () => {
    const r = await verifyMessage(message, { resolver });
    expect(r.authResults.startsWith("mailgrade; ")).toBe(true);
  });

  it("omits Received-SPF when there was no IP to evaluate", async () => {
    const r = await verifyMessage(message, { resolver, mta: "mx.example.net" });
    expect(r.headers).not.toContain("Received-SPF");
    expect(r.headers.startsWith("Authentication-Results:")).toBe(true);
  });

  it("reports a failure honestly in the Received-SPF comment", async () => {
    const r = await verifyMessage(message, { ...arrived, ip: "203.0.113.9" });
    expect(r.spf?.result).toBe("fail");
    expect(unfold(r.headers)).toContain(
      "Received-SPF: fail (mx.example.net: domain of bounces@example.com " +
        "does not designate 203.0.113.9 as permitted sender)",
    );
  });
});

describe("hostile values", () => {
  // Every value in these headers arrived off the wire, and a receiver
  // prepends the block verbatim: a CR or LF that survives is a forged header,
  // not a value.
  it("refuses to let a CRLF in the envelope become a new header field", async () => {
    const r = await verifyMessage(message, {
      ...arrived,
      sender: "bounces@example.com\r\nX-Evil: injected",
      helo: "mail.example.com\nX-Also-Evil: yes",
    });

    // The CRLFs are flattened to spaces, so "X-Evil" survives only inside a
    // value. What must not happen is a line of the block starting anything
    // but a field this library generates or a folded continuation of one.
    for (const line of r.headers.split("\r\n").filter((l) => l !== "")) {
      expect(line).toMatch(/^(?:Received-SPF:|Authentication-Results:| )/);
    }

    // And a parser reading the prepended block sees exactly two fields.
    const fieldNames = `${r.headers}\r\n`.match(/^[!-9;-~]+:/gm) ?? [];
    expect(fieldNames).toEqual(["Received-SPF:", "Authentication-Results:"]);
  });

  it("keeps a quoted local part with a semicolon whole across the fold", async () => {
    const r = await verifyMessage(message, {
      ...arrived,
      sender: '"a;b"@example.com',
    });

    // Escaped for the quoted-string, and unfolded back to one piece: the
    // semicolon never became a segment boundary and no space crept inside.
    expect(unfold(r.headers)).toContain('envelope-from="\\"a;b\\"@example.com"');
    for (const line of r.headers.split("\r\n")) {
      expect(line.length).toBeLessThanOrEqual(78);
    }
  });
});

describe("the default resolver", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // The whole ergonomic claim of 2.0 is that this call needs no setup. If the
  // default ever stops being wired up, every example in the README breaks and
  // nothing else in the suite would notice, because everything else injects.
  it("resolves over DoH when the caller names none", async () => {
    const fetched: string[] = [];
    vi.stubGlobal("fetch", (url: string) => {
      fetched.push(url);
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ Status: 0, Answer: [] }),
      });
    });

    const r = await verifyMessage(message, { ip: "192.0.2.7", sender: "a@b.example" });

    expect(fetched.some((url) => url.startsWith("https://cloudflare-dns.com/dns-query"))).toBe(true);
    expect(fetched.some((url) => url.includes("_dmarc.example.com"))).toBe(true);
    expect(r.dmarc?.result).toBe("none");
  });
});
