/**
 * A `Resolver` made of nothing but `fetch`.
 *
 * This is the library's default DNS, and it is deliberately the smallest
 * module that can be one: it imports no grading code and no verification
 * code, so `mailgrade/verify` can default its `resolver` without dragging the
 * domain grader in behind it.
 *
 * DNS over HTTPS rather than a platform resolver, because `fetch` is the one
 * lookup mechanism that exists in every runtime this targets. A Node service
 * that would rather not leave the process for every lookup passes the
 * `resolver` from `mailgrade/node-dns` instead.
 */

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

export type DohResolverOptions = {
  /** A DNS-over-HTTPS JSON endpoint. Defaults to Cloudflare's. */
  readonly endpoint?: string;
  /** Injectable for tests, or for a runtime with a non-global fetch. */
  readonly fetch?: FetchLike;
  readonly signal?: AbortSignal;
};

export const DEFAULT_ENDPOINT = "https://cloudflare-dns.com/dns-query";

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
  return parts.map((p) => p.slice(1, -1).replace(/\\(.)/g, "$1")).join("");
}

function stripRootDot(host: string): string {
  return host.replace(/\.$/, "");
}

async function query(
  host: string,
  type: DnsRecordType,
  options: DohResolverOptions,
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
    throw new DnsError(`DNS query returned status ${body.Status}`, host, type);
  }

  return (body.Answer ?? [])
    .filter((a) => a.type === RECORD_TYPE[type])
    .map((a) => (type === "TXT" ? unquoteTxt(a.data) : a.data));
}

/**
 * Honours the resolver contract: empty answers come back as `[]`, failures
 * throw (and verification reports temperror rather than fail), MX values are
 * bare host names.
 */
export function dohResolver(options: DohResolverOptions = {}): Resolver {
  return async (name, type) => {
    const records = await query(name, type, options);
    if (type === "MX") {
      return records.map((r) => stripRootDot(r.split(/\s+/).pop() ?? r));
    }
    if (type === "PTR") return records.map(stripRootDot);
    return records;
  };
}

/**
 * The resolver every call falls back to when the caller names none.
 *
 * Built once and reused, so that defaulting costs nothing per call, and built
 * lazily so that merely importing the library never reads a global that a
 * runtime may not have set up yet.
 */
let fallback: Resolver | undefined;

export function defaultResolver(): Resolver {
  return (fallback ??= dohResolver());
}
