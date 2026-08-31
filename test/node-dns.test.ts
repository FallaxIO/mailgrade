/**
 * The Node resolver, tested against a fake `node:dns/promises` so that no test
 * touches the network.
 *
 * What is worth testing here is only the mapping: Node's shapes and its habit
 * of throwing for "nothing published" against the `Resolver` contract the
 * verification engine is written to.
 */

import { describe, expect, it } from "vitest";

import { nodeResolver, type NodeDnsLike } from "../src/node-dns.ts";
import { verifySpf } from "../src/verify/index.ts";

function dnsError(code: string): Error {
  return Object.assign(new Error(`queryTxt ${code}`), { code });
}

const zone: NodeDnsLike = {
  resolveTxt: (name) => {
    if (name === "empty.example") return Promise.reject(dnsError("ENODATA"));
    if (name === "missing.example") return Promise.reject(dnsError("ENOTFOUND"));
    if (name === "broken.example") return Promise.reject(dnsError("ESERVFAIL"));
    if (name === "long.example") {
      return Promise.resolve([["v=spf1 ", "ip4:198.51.100.0/24 ", "-all"]]);
    }
    return Promise.resolve([["v=spf1 -all"], ["other=record"]]);
  },
  resolveMx: () =>
    Promise.resolve([
      { exchange: "mx2.example.", priority: 20 },
      { exchange: "mx1.example", priority: 10 },
    ]),
  resolve4: () => Promise.resolve(["198.51.100.7"]),
  resolve6: () => Promise.resolve(["2001:db8::1"]),
  resolvePtr: () => Promise.resolve(["host.example."]),
};

const resolve = nodeResolver({ dns: zone });

describe("nodeResolver", () => {
  it("joins the chunks of a TXT record Node split at 255 bytes", async () => {
    await expect(resolve("long.example", "TXT")).resolves.toEqual([
      "v=spf1 ip4:198.51.100.0/24 -all",
    ]);
  });

  it("returns one string per TXT record", async () => {
    await expect(resolve("acme.example", "TXT")).resolves.toEqual([
      "v=spf1 -all",
      "other=record",
    ]);
  });

  it("reduces MX answers to bare host names, preference and root dot gone", async () => {
    await expect(resolve("acme.example", "MX")).resolves.toEqual([
      "mx2.example",
      "mx1.example",
    ]);
  });

  it("strips the root dot from PTR names", async () => {
    await expect(resolve("7.100.51.198.in-addr.arpa", "PTR")).resolves.toEqual([
      "host.example",
    ]);
  });

  it("passes addresses through", async () => {
    await expect(resolve("acme.example", "A")).resolves.toEqual([
      "198.51.100.7",
    ]);
    await expect(resolve("acme.example", "AAAA")).resolves.toEqual([
      "2001:db8::1",
    ]);
  });

  // The one that matters: Node throws where the contract wants an empty
  // answer, and a throw that escaped here would be read as temperror.
  it("answers an absent name or an absent record with no records", async () => {
    await expect(resolve("missing.example", "TXT")).resolves.toEqual([]);
    await expect(resolve("empty.example", "TXT")).resolves.toEqual([]);
  });

  it("still throws for a lookup that could not be answered", async () => {
    await expect(resolve("broken.example", "TXT")).rejects.toThrow("ESERVFAIL");
  });

  it("drives a real SPF evaluation", async () => {
    const result = await verifySpf({
      ip: "198.51.100.9",
      sender: "bounce@long.example",
      helo: "mail.long.example",
      resolver: resolve,
    });
    expect(result.result).toBe("pass");

    const outside = await verifySpf({
      ip: "203.0.113.1",
      sender: "bounce@long.example",
      helo: "mail.long.example",
      resolver: resolve,
    });
    expect(outside.result).toBe("fail");
  });

  it("reports a domain with no SPF record as none, not temperror", async () => {
    const result = await verifySpf({
      ip: "198.51.100.9",
      sender: "bounce@missing.example",
      helo: "mail.missing.example",
      resolver: resolve,
    });
    expect(result.result).toBe("none");
  });
});
