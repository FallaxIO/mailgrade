/**
 * The only part of this library that touches the network, kept behind its own
 * entry point so that importing `mailgrade` never pulls it in.
 *
 * DNS over HTTPS rather than a platform resolver, because `fetch` is the one
 * lookup mechanism that exists in every runtime this targets. A Node service
 * that would rather not leave the process for every lookup passes the
 * `resolver` from `mailgrade/node-dns` instead.
 */

import { DKIM_SELECTORS, dkimHost, isDkimKey } from "./dkim.ts";
import { dmarcHost } from "./dmarc/analyze.ts";
import { registrableDomain } from "./domain.ts";
import { gradeDomain, type DomainGrade, type DomainRecords } from "./grade.ts";
import type { DnsRecordType, Resolver } from "./verify/resolver.ts";

export class DnsError extends Error {
  readonly host: string;
  readonly type: string;

  constructor(message: string, host: string, type: string) {
    super(message);
    this.name = "DnsError";
    this.host = host;
    this.type = type;
  }
}

/**
 * The slice of `fetch` this module uses, named structurally so the published
 * types do not depend on which DOM or Node globals a consumer has loaded.
 */
export type FetchLike = (
  url: string,
  init: {
    headers: Record<string, string>;
    signal?: AbortSignal | undefined;
  },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export type DohOptions = {
  /** A DNS-over-HTTPS JSON endpoint. Defaults to Cloudflare's. */
  readonly endpoint?: string;
  /** Injectable for tests, or for a runtime with a non-global fetch. */
  readonly fetch?: FetchLike;
  /** Selectors to probe for DKIM keys. Pass an empty array to skip DKIM. */
  readonly selectors?: readonly string[];
  readonly signal?: AbortSignal;
  /** Lookups in flight at once. */
  readonly concurrency?: number;
  /**
   * Bring your own DNS: any `Resolver` replaces DoH entirely, so a Node
   * service can grade domains over `node:dns` with the same call.
   */
  readonly resolver?: Resolver;
};

const DEFAULT_ENDPOINT = "https://cloudflare-dns.com/dns-query";

const RECORD_TYPE = { A: 1, AAAA: 28, MX: 15, PTR: 12, TXT: 16 } as const;

type DohAnswer = { name: string; type: number; data: string };
type DohResponse = { Status: number; Answer?: DohAnswer[] };

/**
 * A TXT value arrives quoted, and one longer than 255 bytes arrives as several
 * quoted strings that the reader is expected to concatenate.
 */
function unquoteTxt(data: string): string {
  const parts = data.match(/"(?:[^"\\]|\\.)*"/g);
  if (!parts) return data.trim();
  return parts
    .map((p) => p.slice(1, -1).replace(/\\(.)/g, "$1"))
    .join("");
}

async function query(
  host: string,
  type: DnsRecordType,
  options: DohOptions,
): Promise<string[]> {
  const doFetch: FetchLike = options.fetch ?? globalThis.fetch;
  const url = `${options.endpoint ?? DEFAULT_ENDPOINT}?name=${encodeURIComponent(host)}&type=${type}`;

  const response = await doFetch(url, {
    headers: { accept: "application/dns-json" },
    signal: options.signal,
  });
  if (!response.ok) {
    throw new DnsError(
      `DNS query failed with HTTP ${response.status}`,
      host,
      type,
    );
  }

  const body = (await response.json()) as DohResponse;

  // 0 is NOERROR and 3 is NXDOMAIN, which for a DMARC host or a DKIM selector
  // is a legitimate "nothing published here". Anything else means the answer
  // is unknown, and reporting unknown as absent would grade a protected
  // domain as spoofable.
  if (body.Status !== 0 && body.Status !== 3) {
    throw new DnsError(
      `DNS query returned status ${body.Status}`,
      host,
      type,
    );
  }

  return (body.Answer ?? [])
    .filter((a) => a.type === RECORD_TYPE[type])
    .map((a) => (type === "TXT" ? unquoteTxt(a.data) : a.data));
}

async function pool<T, R>(
  items: readonly T[],
  limit: number,
  run: (item: T) => Promise<R>,
): Promise<R[]> {
  const out: R[] = Array.from({ length: items.length });
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, () =>
    (async () => {
      for (;;) {
        const i = next++;
        const item = items[i];
        if (item === undefined) return;
        // Sequential inside a worker is the point: the parallelism is the
        // pool, and firing every selector at once trips DoH rate limits.
        // oxlint-disable-next-line no-await-in-loop
        out[i] = await run(item);
      }
    })(),
  );
  await Promise.all(workers);
  return out;
}

/**
 * Every record `gradeDomain` needs, in one round of lookups.
 *
 * DMARC falls back to the organizational domain the way a receiver does, so a
 * subdomain is graded on the policy that actually applies to it, and `dmarcSource`
 * records where the record was found.
 */
export async function resolveDomain(
  domain: string,
  options: DohOptions = {},
): Promise<DomainRecords> {
  const name = domain.trim().toLowerCase();
  const selectors = options.selectors ?? DKIM_SELECTORS;
  const concurrency = options.concurrency ?? 10;
  const resolve = options.resolver ?? dohResolver(options);

  const [txt, mx, dmarcAtDomain] = await Promise.all([
    resolve(name, "TXT"),
    resolve(name, "MX"),
    resolve(dmarcHost(name), "TXT"),
  ]);

  let dmarc = dmarcAtDomain;
  let dmarcSource: string = name;
  const org = registrableDomain(name);
  if (dmarc.length === 0 && org && org !== name) {
    dmarc = await resolve(dmarcHost(org), "TXT");
    if (dmarc.length > 0) dmarcSource = org;
  }

  const hits = await pool(selectors, concurrency, async (selector) => {
    const records = await resolve(dkimHost(selector, name), "TXT");
    return records.some(isDkimKey) ? selector : null;
  });

  return {
    domain: name,
    txt: [...txt],
    dmarc: [...dmarc],
    dmarcSource,
    dkimSelectors: hits.filter((s): s is string => s !== null),
    dkimProbed: selectors.length,
    mx: mx.map((record) => stripRootDot(record.split(/\s+/).pop() ?? record)),
  };
}

function stripRootDot(host: string): string {
  return host.replace(/\.$/, "");
}

/**
 * A `Resolver` for `mailgrade/verify`, made of nothing but `fetch`.
 *
 * Honours the resolver contract: empty answers come back as `[]`, failures
 * throw (and verification reports temperror rather than fail), MX values are
 * bare host names.
 */
export function dohResolver(options: DohOptions = {}): Resolver {
  return async (name, type) => {
    const records = await query(name, type, options);
    if (type === "MX") {
      return records.map((r) => stripRootDot(r.split(/\s+/).pop() ?? r));
    }
    if (type === "PTR") return records.map(stripRootDot);
    return records;
  };
}

/** Resolve a domain and grade it. */
export async function checkDomain(
  domain: string,
  options: DohOptions = {},
): Promise<DomainGrade> {
  return gradeDomain(await resolveDomain(domain, options));
}
