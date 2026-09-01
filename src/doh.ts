/**
 * Resolving a whole domain, and grading what comes back.
 *
 * The DNS itself lives in `./doh-resolver.ts`; this module is the part that
 * knows which names a grade needs and in what order to ask for them.
 */

import { DKIM_SELECTORS, dkimHost, isDkimKey } from "./dkim.ts";
import { dmarcHost } from "./dmarc/analyze.ts";
import {
  defaultResolver,
  dohResolver,
  type DohResolverOptions,
} from "./doh-resolver.ts";
import { registrableDomain } from "./domain.ts";
import { gradeRecords, type DomainGrade, type DomainRecords } from "./grade.ts";
import type { Resolver } from "./verify/resolver.ts";

export { DEFAULT_ENDPOINT, DnsError } from "./doh-resolver.ts";
export { defaultResolver, dohResolver };
export type { DohResolverOptions, FetchLike } from "./doh-resolver.ts";

/** Options for `gradeDomain`, and for `resolveDomain`, its lookup half. */
export type GradeDomainOptions = DohResolverOptions & {
  /** Selectors to probe for DKIM keys. Pass an empty array to skip DKIM. */
  readonly selectors?: readonly string[];
  /** Lookups in flight at once. */
  readonly concurrency?: number;
  /**
   * Bring your own DNS: any `Resolver` replaces DoH entirely, so a Node
   * service can grade domains over `node:dns` with the same call.
   */
  readonly resolver?: Resolver;
};

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
 * Every record `gradeRecords` needs, in one round of lookups.
 *
 * DMARC falls back to the organizational domain the way a receiver does, so a
 * subdomain is graded on the policy that actually applies to it, and `dmarcSource`
 * records where the record was found.
 */
export async function resolveDomain(
  domain: string,
  options: GradeDomainOptions = {},
): Promise<DomainRecords> {
  const name = domain.trim().toLowerCase();
  const selectors = options.selectors ?? DKIM_SELECTORS;
  const concurrency = options.concurrency ?? 10;
  const resolve = resolverFor(options);

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

/**
 * A caller's own resolver wins; otherwise DoH, configured if they tuned it and
 * the shared default if they did not.
 */
function resolverFor(options: GradeDomainOptions): Resolver {
  if (options.resolver) return options.resolver;
  if (options.endpoint || options.fetch || options.signal) {
    return dohResolver(options);
  }
  return defaultResolver();
}

function stripRootDot(host: string): string {
  return host.replace(/\.$/, "");
}

/**
 * The headline call: everything a domain publishes, in one verdict.
 *
 * `resolveDomain` then `gradeRecords`, which are also exported separately for
 * a caller who wants to cache the records or grade ones they already hold.
 */
export async function gradeDomain(
  domain: string,
  options: GradeDomainOptions = {},
): Promise<DomainGrade> {
  return gradeRecords(await resolveDomain(domain, options));
}
