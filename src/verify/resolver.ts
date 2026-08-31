/**
 * The DNS contract the verification engine is written against.
 *
 * Verification needs live DNS, and whose DNS that is stays the caller's
 * decision: `mailgrade/doh` sells a resolver made of nothing but `fetch`,
 * `mailgrade/node-dns` one made of `node:dns`, and a test passes a zone
 * object. Nothing in `mailgrade/verify` opens a socket itself.
 */

export type DnsRecordType = "TXT" | "A" | "AAAA" | "MX" | "PTR";

/**
 * Resolve one name to the string values of its records.
 *
 * The contract, which every result in the engine leans on:
 * - NXDOMAIN and an empty answer both return `[]`. Both mean "nothing
 *   published", and SPF and DKIM treat them identically.
 * - A lookup that cannot be answered (SERVFAIL, timeout, no network) throws.
 *   A throw becomes a `temperror`, never a `fail`.
 * - TXT strings longer than 255 bytes arrive already concatenated.
 * - MX values are bare host names, preference stripped.
 */
export type Resolver = (
  name: string,
  type: DnsRecordType,
) => Promise<readonly string[]>;

/**
 * A resolver backed by a plain object, for tests and for callers that already
 * hold the records: `{ "example.com": { TXT: ["v=spf1 -all"] } }`.
 *
 * A name mapped to `"TEMPERROR"` throws, which is how a test reaches the
 * temperror paths.
 */
export function staticResolver(
  zone: Readonly<
    Record<string, "TEMPERROR" | Partial<Record<DnsRecordType, readonly string[]>>>
  >,
): Resolver {
  return (name, type) => {
    const entry = zone[name.toLowerCase().replace(/\.$/, "")];
    if (entry === "TEMPERROR") {
      return Promise.reject(new Error(`DNS lookup for ${name} failed`));
    }
    return Promise.resolve(entry?.[type] ?? []);
  };
}
