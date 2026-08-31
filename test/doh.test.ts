/**
 * The DoH layer, driven by a stub fetch. Nothing here touches the network.
 */

import { describe, expect, it } from "vitest";

import { checkDomain, DnsError, resolveDomain, type FetchLike } from "../src/doh.ts";

type Zone = Record<string, { status?: number; answers?: [number, string][] }>;

function stubFetch(zone: Zone, log: string[] = []): FetchLike {
  return (url) => {
    const params = new URL(url).searchParams;
    const name = params.get("name") ?? "";
    const type = params.get("type") ?? "";
    log.push(`${type} ${name}`);
    const entry = zone[`${type} ${name}`];
    return Promise.resolve({
      ok: true,
      status: 200,
      json: () =>
        Promise.resolve({
          Status: entry?.status ?? (entry ? 0 : 3),
          Answer: (entry?.answers ?? []).map(([recordType, data]) => ({
            name,
            type: recordType,
            data,
          })),
        }),
    });
  };
}

const TXT = 16;
const MX = 15;

const serverFailure: FetchLike = () =>
  Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ Status: 2 }) });

const httpFailure: FetchLike = () =>
  Promise.resolve({ ok: false, status: 502, json: () => Promise.resolve({}) });

describe("resolveDomain", () => {
  it("joins the quoted strings of a TXT record split for DNS", async () => {
    const records = await resolveDomain("acme.com", {
      selectors: [],
      fetch: stubFetch({
        "TXT acme.com": {
          answers: [[TXT, '"v=spf1 include:_spf.google.com " "-all"']],
        },
      }),
    });
    expect(records.txt).toEqual(["v=spf1 include:_spf.google.com -all"]);
  });

  it("reads MX hosts without their priority or root dot", async () => {
    const records = await resolveDomain("acme.com", {
      selectors: [],
      fetch: stubFetch({
        "MX acme.com": {
          answers: [
            [MX, "10 aspmx.l.google.com."],
            [MX, "20 alt1.aspmx.l.google.com."],
          ],
        },
      }),
    });
    expect(records.mx).toEqual(["aspmx.l.google.com", "alt1.aspmx.l.google.com"]);
  });

  it("falls back to the organizational domain for DMARC, as a receiver does", async () => {
    const records = await resolveDomain("mail.acme.com", {
      selectors: [],
      fetch: stubFetch({
        "TXT _dmarc.acme.com": { answers: [[TXT, '"v=DMARC1; p=reject"']] },
      }),
    });
    expect(records.dmarc).toEqual(["v=DMARC1; p=reject"]);
    expect(records.dmarcSource).toBe("acme.com");
  });

  it("keeps the domain as the source when it publishes its own record", async () => {
    const records = await resolveDomain("mail.acme.com", {
      selectors: [],
      fetch: stubFetch({
        "TXT _dmarc.mail.acme.com": { answers: [[TXT, '"v=DMARC1; p=none"']] },
        "TXT _dmarc.acme.com": { answers: [[TXT, '"v=DMARC1; p=reject"']] },
      }),
    });
    expect(records.dmarcSource).toBe("mail.acme.com");
    expect(records.dmarc).toEqual(["v=DMARC1; p=none"]);
  });

  it("reports only the probed selectors that answered with a live key", async () => {
    const records = await resolveDomain("acme.com", {
      selectors: ["google", "selector1", "pm"],
      fetch: stubFetch({
        "TXT google._domainkey.acme.com": {
          answers: [[TXT, '"v=DKIM1; k=rsa; p=MIIBIjANBgkq"']],
        },
        // A revoked key is published but empty, so it does not count.
        "TXT pm._domainkey.acme.com": { answers: [[TXT, '"v=DKIM1; k=rsa; p="']] },
      }),
    });
    expect(records.dkimSelectors).toEqual(["google"]);
    expect(records.dkimProbed).toBe(3);
  });

  it("asks for exactly the hosts it needs", async () => {
    const log: string[] = [];
    await resolveDomain("acme.com", {
      selectors: ["google"],
      fetch: stubFetch({}, log),
    });
    expect(log.toSorted()).toEqual([
      "MX acme.com",
      "TXT _dmarc.acme.com",
      "TXT acme.com",
      "TXT google._domainkey.acme.com",
    ]);
  });

  it("throws rather than reading a server failure as an absent record", async () => {
    await expect(
      resolveDomain("acme.com", { selectors: [], fetch: serverFailure }),
    ).rejects.toBeInstanceOf(DnsError);
  });

  it("throws on an HTTP failure from the resolver", async () => {
    await expect(
      resolveDomain("acme.com", { selectors: [], fetch: httpFailure }),
    ).rejects.toThrow(/502/);
  });
});

describe("checkDomain", () => {
  it("resolves and grades in one call", async () => {
    const grade = await checkDomain("acme.com", {
      selectors: ["google"],
      fetch: stubFetch({
        "TXT acme.com": { answers: [[TXT, '"v=spf1 include:_spf.google.com -all"']] },
        "TXT _dmarc.acme.com": {
          answers: [[TXT, '"v=DMARC1; p=reject; rua=mailto:dmarc@acme.com"']],
        },
        "TXT google._domainkey.acme.com": {
          answers: [[TXT, '"v=DKIM1; k=rsa; p=MIIBIjANBgkq"']],
        },
        "MX acme.com": { answers: [[MX, "10 aspmx.l.google.com."]] },
      }),
    });

    expect(grade.verdict).toBe("protected");
    expect(grade.spf.id).toBe("spf-hardfail");
    expect(grade.dmarc.id).toBe("dmarc-enforcing");
    expect(grade.dkim.selectorsFound).toEqual(["google"]);
    expect(grade.mx.provider).toBe("Google Workspace");
  });
});
