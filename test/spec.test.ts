/**
 * The conformance corpus, run against this implementation.
 *
 * Every case in spec/*.json is a language-neutral contract: an input, and a
 * projection of the result with stable ids in it and no English. A port in
 * another language passes by reading the same files and writing its own
 * `project` below. See spec/README.md.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { analyzeDkim, isDkimKey } from "../src/dkim.ts";
import { analyzeDmarc } from "../src/dmarc/analyze.ts";
import {
  buildDmarcRecord,
  cleanAddresses,
  DEFAULT_OPTIONS,
  externalDestinations,
  parseDmarcRecord,
  txtChunks,
  type DmarcOptions,
} from "../src/dmarc/record.ts";
import { dmarcGrade, reviewDmarc, rolloutPlan } from "../src/dmarc/review.ts";
import { aligns, coerceDomain, registrableDomain } from "../src/domain.ts";
import { gradeRecords, type DomainRecords } from "../src/grade.ts";
import { analyzeHeaders } from "../src/headers/analyze.ts";
import { detectImpersonation, editDistance } from "../src/headers/impersonation.ts";
import {
  decodeEncodedWords,
  isPrivateIp,
  parseAddress,
  parseHeaders,
  stripComments,
} from "../src/headers/parse.ts";
import { staticResolver } from "../src/verify/resolver.ts";
import { verifySpf } from "../src/verify/spf.ts";

type Case = {
  target: string;
  name: string;
  input: Record<string, unknown>;
  expect: Record<string, unknown>;
};

const SPEC_DIR = new URL("../spec/", import.meta.url).pathname;

function options(input: Record<string, unknown>): DmarcOptions {
  return {
    ...DEFAULT_OPTIONS,
    ...(input["options"] as Partial<DmarcOptions>),
  };
}

const PROJECT: Record<string, (i: Record<string, any>) => unknown> = {
  coerceDomain: (i) => ({ domain: coerceDomain(i["raw"]) }),
  registrableDomain: (i) => ({ domain: registrableDomain(i["host"]) }),
  aligns: (i) => ({ aligns: aligns(i["a"], i["b"]) }),

  analyzeSpf: (i) => {
    const r = gradeRecords({ domain: "x.example", txt: i["txt"], dmarc: [] }).spf;
    return {
      id: r.id,
      status: r.status,
      allQualifier: r.allQualifier,
      hasRecord: r.record !== null,
    };
  },

  isDkimKey: (i) => ({ isKey: isDkimKey(i["txt"]) }),
  analyzeDkim: (i) => {
    const r = analyzeDkim(i["found"], i["probed"]);
    return { id: r.id, status: r.status };
  },

  analyzeDmarc: (i) => {
    const r = analyzeDmarc(i["txt"], i["source"]);
    return { id: r.id, status: r.status, policy: r.policy, source: r.source };
  },

  buildDmarcRecord: (i) => ({ record: buildDmarcRecord(options(i)) }),
  cleanAddresses: (i) => ({ addresses: cleanAddresses(i["list"]) }),
  txtChunks: (i) => ({ chunks: txtChunks(i["record"]) }),

  parseDmarcRecord: (i) => {
    const { options: o, errors, unknown } = parseDmarcRecord(i["record"], i["domain"]);
    return {
      errorIds: errors.map((e) => e.id),
      unknown,
      policy: o.policy,
      subdomainPolicy: o.subdomainPolicy,
      pct: o.pct,
      rua: o.rua,
      ruf: o.ruf,
      adkim: o.adkim,
      aspf: o.aspf,
      ri: o.ri,
      fo: o.fo,
    };
  },

  dmarcGrade: (i) => ({ grade: dmarcGrade(options(i)) }),
  reviewDmarc: (i) => {
    const notes = reviewDmarc(options(i));
    return {
      noteIds: notes.map((n) => n.id),
      highIds: notes.filter((n) => n.severity === "high").map((n) => n.id),
      hasNote: notes.map((n) => n.id),
    };
  },
  externalDestinations: (i) => ({ destinations: externalDestinations(options(i)) }),
  rollout: (i) => {
    const stages = rolloutPlan(options(i));
    return {
      records: stages.map((s) => s.record),
      currentKeys: stages.filter((s) => s.current).map((s) => s.key),
    };
  },

  gradeRecords: (i) => {
    const g = gradeRecords(i as DomainRecords);
    return {
      verdict: g.verdict,
      letter: g.letter,
      spfId: g.spf.id,
      dmarcId: g.dmarc.id,
      dkimId: g.dkim.id,
      provider: g.mx.provider,
      recommendationIds: g.recommendations.map((r) => r.id),
    };
  },

  analyzeHeaders: (i) => {
    const a = analyzeHeaders(i["raw"]);
    return {
      verdict: a.verdict,
      authSource: a.authSource,
      fromDomain: a.identity.from?.domain ?? null,
      spfResult: a.spf.result,
      spfAligned: a.spf.aligned,
      dkimResult: a.dkim.result,
      dkimAligned: a.dkim.aligned,
      dmarcResult: a.dmarc.result,
      flagIds: a.flags.map((f) => f.id),
      recommendationIds: a.recommendations.map((r) => r.id),
      hopCount: a.route.hops.length,
      originatingIp: a.route.originatingIp,
      subject: a.message.subject,
    };
  },

  parseHeaders: (i) => ({
    fields: parseHeaders(i["raw"]).map((f) => [f.name, f.value]),
  }),
  parseAddress: (i) => {
    const a = parseAddress(i["raw"]);
    return {
      display: a?.display ?? null,
      address: a?.address ?? null,
      domain: a?.domain ?? null,
    };
  },
  decodeEncodedWords: (i) => ({ text: decodeEncodedWords(i["value"]) }),
  stripComments: (i) => ({ text: stripComments(i["value"]) }),
  isPrivateIp: (i) => ({ private: isPrivateIp(i["ip"]) }),
  editDistance: (i) => ({ distance: editDistance(i["a"], i["b"]) }),
  detectImpersonation: (i) => {
    const r = detectImpersonation(i["domain"]);
    return { brand: r?.brand ?? null, kind: r?.kind ?? null };
  },

  verifySpf: async (i) => {
    const r = await verifySpf({
      ip: i["ip"],
      sender: i["sender"],
      helo: i["helo"],
      resolver: staticResolver(i["zone"]),
    });
    return {
      result: r.result,
      mechanism: r.mechanism,
      domain: r.domain,
      lookups: r.lookups,
      explanation: r.explanation,
    };
  },
};

const files = readdirSync(SPEC_DIR).filter((f) => f.endsWith(".json"));

it("finds the corpus", () => {
  expect(files.length).toBeGreaterThan(0);
});

for (const file of files) {
  const { cases } = JSON.parse(
    readFileSync(join(SPEC_DIR, file), "utf8"),
  ) as { cases: Case[] };

  describe(`spec/${file}`, () => {
    for (const testCase of cases) {
      it(`${testCase.target}: ${testCase.name}`, async () => {
        const project = PROJECT[testCase.target];
        expect(project, `no projection for target "${testCase.target}"`).toBeTypeOf(
          "function",
        );
        const actual = (await project!(testCase.input)) as Record<string, unknown>;

        for (const [key, want] of Object.entries(testCase.expect)) {
          // `hasNote` asks whether an id is present rather than pinning the
          // whole list, for cases where the rest of the list is incidental.
          if (key === "hasNote") {
            expect(actual["hasNote"]).toContain(want);
            continue;
          }
          expect(actual, `key "${key}"`).toHaveProperty(key);
          expect(actual[key], `key "${key}"`).toEqual(want);
        }
      });
    }
  });
}
