/**
 * The SPF evaluation engine against hand-built zones: every mechanism, the
 * macro language, and all four of the limits receivers enforce.
 */

import { describe, expect, it } from "vitest";
import { staticResolver } from "../src/verify/resolver.ts";
import { verifySpf } from "../src/verify/spf.ts";

const zone = (records: Parameters<typeof staticResolver>[0]) =>
  staticResolver(records);

const base = {
  ip: "192.0.2.10",
  sender: "bob@example.com",
  helo: "mail.example.com",
};

describe("record selection", () => {
  it("reports none when nothing is published", async () => {
    const r = await verifySpf({ ...base, resolver: zone({ "example.com": {} }) });
    expect(r.result).toBe("none");
  });

  it("reports none for a non-domain sender", async () => {
    const r = await verifySpf({
      ...base,
      sender: "localpart",
      resolver: zone({}),
    });
    expect(r.result).toBe("none");
  });

  it("treats two records as a permanent error", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": { TXT: ["v=spf1 -all", "v=spf1 +all"] },
      }),
    });
    expect(r.result).toBe("permerror");
  });

  it("ignores TXT records that are not SPF", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": { TXT: ["google-site-verification=abc", "v=spf1 -all"] },
      }),
    });
    expect(r.result).toBe("fail");
    expect(r.mechanism).toBe("-all");
  });

  it("reports temperror when DNS is down", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({ "example.com": "TEMPERROR" }),
    });
    expect(r.result).toBe("temperror");
  });

  it("reports permerror for a malformed ip", async () => {
    const r = await verifySpf({
      ...base,
      ip: "not-an-ip",
      resolver: zone({}),
    });
    expect(r.result).toBe("permerror");
  });
});

describe("ip mechanisms", () => {
  it("matches ip4 with a prefix", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({ "example.com": { TXT: ["v=spf1 ip4:192.0.2.0/24 -all"] } }),
    });
    expect(r.result).toBe("pass");
    expect(r.mechanism).toBe("+ip4:192.0.2.0/24");
  });

  it("fails outside the prefix", async () => {
    const r = await verifySpf({
      ...base,
      ip: "192.0.3.10",
      resolver: zone({ "example.com": { TXT: ["v=spf1 ip4:192.0.2.0/24 -all"] } }),
    });
    expect(r.result).toBe("fail");
  });

  it("matches ip6", async () => {
    const r = await verifySpf({
      ...base,
      ip: "2001:db8::1",
      resolver: zone({ "example.com": { TXT: ["v=spf1 ip6:2001:db8::/32 ~all"] } }),
    });
    expect(r.result).toBe("pass");
  });

  it("treats an IPv4-mapped IPv6 connection as IPv4", async () => {
    const r = await verifySpf({
      ...base,
      ip: "::ffff:192.0.2.10",
      resolver: zone({ "example.com": { TXT: ["v=spf1 ip4:192.0.2.10 -all"] } }),
    });
    expect(r.result).toBe("pass");
  });

  it("rejects a malformed ip4 network", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({ "example.com": { TXT: ["v=spf1 ip4:999.0.2.0/24 -all"] } }),
    });
    expect(r.result).toBe("permerror");
  });
});

describe("a, mx and exists", () => {
  it("matches a", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": { TXT: ["v=spf1 a -all"], A: ["192.0.2.10"] },
      }),
    });
    expect(r.result).toBe("pass");
  });

  it("matches a:other.example with a cidr", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": { TXT: ["v=spf1 a:mail.example.net/24 -all"] },
        "mail.example.net": { A: ["192.0.2.99"] },
      }),
    });
    expect(r.result).toBe("pass");
  });

  it("matches mx through the exchanger's address", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": { TXT: ["v=spf1 mx -all"], MX: ["mx1.example.com"] },
        "mx1.example.com": { A: ["192.0.2.10"] },
      }),
    });
    expect(r.result).toBe("pass");
    expect(r.mechanism).toBe("+mx");
  });

  it("matches exists via an A lookup on the expanded name", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": { TXT: ["v=spf1 exists:%{i}.spf.example.com -all"] },
        "192.0.2.10.spf.example.com": { A: ["127.0.0.2"] },
      }),
    });
    expect(r.result).toBe("pass");
  });

  it("uses AAAA for an IPv6 connection", async () => {
    const r = await verifySpf({
      ...base,
      ip: "2001:db8::5",
      resolver: zone({
        "example.com": { TXT: ["v=spf1 a -all"], AAAA: ["2001:db8::5"] },
      }),
    });
    expect(r.result).toBe("pass");
  });
});

describe("include and redirect", () => {
  it("passes through a matching include", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": { TXT: ["v=spf1 include:_spf.example.net -all"] },
        "_spf.example.net": { TXT: ["v=spf1 ip4:192.0.2.0/24 -all"] },
      }),
    });
    expect(r.result).toBe("pass");
    expect(r.mechanism).toBe("+include:_spf.example.net");
  });

  it("keeps going past an include whose policy fails", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": {
          TXT: ["v=spf1 include:_spf.example.net ip4:192.0.2.10 -all"],
        },
        "_spf.example.net": { TXT: ["v=spf1 -all"] },
      }),
    });
    expect(r.result).toBe("pass");
    expect(r.mechanism).toBe("+ip4:192.0.2.10");
  });

  it("treats an include of a record-less domain as permerror", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": { TXT: ["v=spf1 include:nothing.example -all"] },
        "nothing.example": {},
      }),
    });
    expect(r.result).toBe("permerror");
  });

  it("follows redirect and reports the target's verdict and record", async () => {
    const r = await verifySpf({
      ...base,
      ip: "203.0.113.9",
      resolver: zone({
        "example.com": { TXT: ["v=spf1 redirect=_spf.example.org"] },
        "_spf.example.org": { TXT: ["v=spf1 ip4:192.0.2.0/24 -all"] },
      }),
    });
    expect(r.result).toBe("fail");
    expect(r.domain).toBe("_spf.example.org");
  });

  it("ignores redirect when an all is present", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": { TXT: ["v=spf1 redirect=_spf.example.org ~all"] },
      }),
    });
    expect(r.result).toBe("softfail");
    expect(r.lookups).toBe(0);
  });
});

describe("qualifiers and ordering", () => {
  it("stops at the first matching mechanism", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({ "example.com": { TXT: ["v=spf1 ?all -all"] } }),
    });
    expect(r.result).toBe("neutral");
    expect(r.mechanism).toBe("?all");
  });

  it("softfails on ~all", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({ "example.com": { TXT: ["v=spf1 ~all"] } }),
    });
    expect(r.result).toBe("softfail");
  });

  it("defaults to neutral with no all and no match", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({ "example.com": { TXT: ["v=spf1 ip4:203.0.113.0/24"] } }),
    });
    expect(r.result).toBe("neutral");
    expect(r.mechanism).toBeNull();
  });

  it("rejects an unknown mechanism", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({ "example.com": { TXT: ["v=spf1 ip5:1.2.3.4 -all"] } }),
    });
    expect(r.result).toBe("permerror");
  });
});

describe("limits", () => {
  it("permerrors past ten DNS-costing terms", async () => {
    const records: Record<string, { TXT: string[] }> = {
      "example.com": { TXT: ["v=spf1 include:i0.example -all"] },
    };
    for (let i = 0; i < 12; i++) {
      records[`i${i}.example`] = { TXT: [`v=spf1 include:i${i + 1}.example -all`] };
    }
    const r = await verifySpf({ ...base, resolver: zone(records) });
    expect(r.result).toBe("permerror");
    expect(r.lookups).toBe(11);
  });

  it("permerrors past two void lookups", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": {
          TXT: ["v=spf1 a:v1.example a:v2.example a:v3.example -all"],
        },
        "v1.example": {},
        "v2.example": {},
        "v3.example": {},
      }),
    });
    expect(r.result).toBe("permerror");
  });

  it("permerrors on more than ten MX hosts", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": {
          TXT: ["v=spf1 mx -all"],
          MX: Array.from({ length: 11 }, (_, i) => `mx${i}.example.com`),
        },
      }),
    });
    expect(r.result).toBe("permerror");
  });
});

describe("macros", () => {
  it("expands sender, domain and reversed ip", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": { TXT: ["v=spf1 exists:%{ir}.%{v}.%{d2} -all"] },
        "10.2.0.192.in-addr.example.com": { A: ["127.0.0.2"] },
      }),
    });
    expect(r.result).toBe("pass");
  });

  it("expands the local part and truncated labels", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": { TXT: ["v=spf1 exists:%{l}.%{o}.check.example -all"] },
        "bob.example.com.check.example": { A: ["127.0.0.2"] },
      }),
    });
    expect(r.result).toBe("pass");
  });

  it("uses postmaster for a bare-domain sender", async () => {
    const r = await verifySpf({
      ...base,
      sender: "example.com",
      resolver: zone({
        "example.com": { TXT: ["v=spf1 exists:%{l}.x.example -all"] },
        "postmaster.x.example": { A: ["127.0.0.2"] },
      }),
    });
    expect(r.result).toBe("pass");
  });

  it("permerrors on a malformed macro", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({ "example.com": { TXT: ["v=spf1 exists:%{q}.x.example -all"] } }),
    });
    expect(r.result).toBe("permerror");
  });

  it("fetches and expands the exp= explanation on fail", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": {
          TXT: ["v=spf1 -all exp=explain._spf.%{d}"],
        },
        "explain._spf.example.com": {
          TXT: ["%{i} is not allowed to send mail for %{d}"],
        },
      }),
    });
    expect(r.result).toBe("fail");
    expect(r.explanation).toBe(
      "192.0.2.10 is not allowed to send mail for example.com",
    );
  });
});

describe("ptr", () => {
  it("matches a forward-confirmed ptr name", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": { TXT: ["v=spf1 ptr -all"] },
        "10.2.0.192.in-addr.arpa": { PTR: ["mail.example.com."] },
        "mail.example.com": { A: ["192.0.2.10"] },
      }),
    });
    expect(r.result).toBe("pass");
  });

  it("ignores a ptr name that does not confirm", async () => {
    const r = await verifySpf({
      ...base,
      resolver: zone({
        "example.com": { TXT: ["v=spf1 ptr -all"] },
        "10.2.0.192.in-addr.arpa": { PTR: ["mail.example.com."] },
        "mail.example.com": { A: ["203.0.113.5"] },
      }),
    });
    expect(r.result).toBe("fail");
  });
});
