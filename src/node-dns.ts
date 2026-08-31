/**
 * A `Resolver` backed by Node's own resolver, for services that would rather
 * not send every lookup to a third party over HTTPS.
 *
 * Kept in its own entry point because it is the one file in the library that
 * imports a Node built-in: `mailgrade`, `mailgrade/verify` and `mailgrade/doh`
 * stay loadable in a Worker or a browser, and only a caller that reaches for
 * `mailgrade/node-dns` pulls `node:dns` in.
 *
 * The mapping is the point. Node reports "nothing published" by throwing,
 * returns TXT as arrays of 255-byte chunks and MX as objects, and the
 * `Resolver` contract wants none of that: an empty answer is `[]`, a throw is
 * reserved for lookups that genuinely could not be answered, and a throw the
 * caller did not mean becomes a `temperror` where a `fail` was correct.
 */

import type { DnsRecordType, Resolver } from "./verify/resolver.ts";

/**
 * The slice of `node:dns/promises` this module uses, named structurally so the
 * published types do not depend on which Node types a consumer has installed,
 * and so a test can pass a fake zone without a socket.
 */
export type NodeDnsLike = {
  resolveTxt(name: string): Promise<string[][]>;
  resolveMx(name: string): Promise<{ exchange: string; priority: number }[]>;
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
  resolvePtr(name: string): Promise<string[]>;
};

export type NodeResolverOptions = {
  /**
   * Name servers to query, as `node:dns` spells them: `"1.1.1.1"`, or
   * `"[2606:4700:4700::1111]:53"`. Defaults to the system configuration.
   */
  readonly servers?: readonly string[];
  /** Milliseconds to wait for a reply before retrying. Node's default is -1, which adapts. */
  readonly timeout?: number;
  /** Attempts per server before the query fails. Node's default is 4. */
  readonly tries?: number;
  /** Injectable for tests, or for a resolver instance you already configured. */
  readonly dns?: NodeDnsLike;
};

/**
 * A name that does not exist, and a name with no record of the type asked
 * for, are both "nothing published" and both answer `[]`. Every other code
 * (SERVFAIL, timeout, refused) is a lookup that could not be answered and
 * must keep throwing, so that verification reports temperror.
 */
const EMPTY_CODES = new Set(["ENOTFOUND", "ENODATA", "NOTFOUND", "NODATA"]);

function isEmptyAnswer(error: unknown): boolean {
  const code: unknown = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && EMPTY_CODES.has(code);
}

function stripRootDot(host: string): string {
  return host.replace(/\.$/, "");
}

async function answer(
  dns: NodeDnsLike,
  name: string,
  type: DnsRecordType,
): Promise<readonly string[]> {
  switch (type) {
    case "TXT":
      // Node hands back one array of chunks per record, and a value longer
      // than 255 bytes is split across them for the reader to rejoin.
      return (await dns.resolveTxt(name)).map((chunks) => chunks.join(""));
    case "MX":
      return (await dns.resolveMx(name)).map((record) =>
        stripRootDot(record.exchange),
      );
    case "A":
      return await dns.resolve4(name);
    case "AAAA":
      return await dns.resolve6(name);
    case "PTR":
      return (await dns.resolvePtr(name)).map(stripRootDot);
  }
}

/**
 * Resolve with `node:dns`, honouring the `Resolver` contract.
 *
 * ```ts
 * import { verifyMessage } from "mailgrade/verify";
 * import { nodeResolver } from "mailgrade/node-dns";
 *
 * await verifyMessage(raw, { resolver: nodeResolver(), ip, sender });
 * ```
 *
 * Passing `servers`, `timeout` or `tries` builds a dedicated `dns.Resolver`
 * rather than touching the process-wide configuration, so one library call
 * cannot repoint the DNS of the whole service.
 */
export function nodeResolver(options: NodeResolverOptions = {}): Resolver {
  // Built on the first lookup rather than here, so that constructing a
  // resolver never leaves a rejected promise nobody is waiting on yet.
  let dns: Promise<NodeDnsLike> | undefined;
  return async (name, type) => {
    dns ??= options.dns ? Promise.resolve(options.dns) : build(options);
    try {
      return await answer(await dns, name, type);
    } catch (error) {
      if (isEmptyAnswer(error)) return [];
      throw error;
    }
  };
}

/**
 * The import is dynamic so that loading this module is harmless in a runtime
 * without `node:dns`; the failure arrives on the first lookup, where a caller
 * is already handling errors, rather than at import time.
 */
async function build(options: NodeResolverOptions): Promise<NodeDnsLike> {
  const dns = await import("node:dns/promises");
  const { servers, timeout, tries } = options;
  if (servers === undefined && timeout === undefined && tries === undefined) {
    return dns;
  }
  const resolver = new dns.Resolver({
    ...(timeout === undefined ? {} : { timeout }),
    ...(tries === undefined ? {} : { tries }),
  });
  if (servers !== undefined) resolver.setServers([...servers]);
  return resolver;
}
