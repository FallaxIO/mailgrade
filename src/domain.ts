/**
 * Domain arithmetic shared by every other module: which part of a host someone
 * had to register, and whether two identities count as the same organisation.
 */

/**
 * Where a caller can supply the real Public Suffix List instead of the
 * built-in approximation. Relevant to anyone acting on `mailgrade/verify` in
 * an enforcement path; see `SuffixOptions.publicSuffixes`.
 */
export type SuffixOptions = {
  /**
   * A complete public suffix list, replacing the built-in rules entirely: the
   * longest entry matching the tail of a host is its public suffix, and a host
   * matching nothing keeps its last label. Pass the ICANN section of the real
   * PSL here when a wrong alignment decision would cost something.
   *
   * It replaces rather than extends, because a partial list is worse than the
   * heuristic it would be mixed with.
   */
  readonly publicSuffixes?: ReadonlySet<string> | readonly string[];
};

/**
 * Two-label public suffixes whose second-level label is the registry's own
 * word rather than a registrant's: `acme.co.uk` and `acme.gov.uk` are both
 * registrable domains, `co.uk` and `gov.uk` are not.
 *
 * These labels are administrative under practically every ccTLD that uses
 * them, so the rule is stated once here rather than enumerated per country.
 */
const ADMINISTRATIVE_LABELS: ReadonlySet<string> = new Set([
  "ac", "co", "com", "ed", "edu", "go", "gob", "gouv", "gov", "gr", "lg",
  "mil", "ne", "nom", "net", "or", "org", "sch",
]);

/** Two-label suffixes the rule above does not reach. */
const KNOWN_SUFFIXES: ReadonlySet<string> = new Set([
  "in.ua", "id.au", "me.uk", "ltd.uk", "plc.uk", "priv.at",
]);

/** A ccTLD: only there is a second-level label likely to be administrative. */
function isCountryCode(tld: string): boolean {
  return /^[a-z]{2}$/.test(tld);
}

/**
 * How many trailing labels of a host are its public suffix. Never zero: a host
 * matching no rule keeps its last label, the way the PSL's implicit `*` rule
 * works.
 */
function suffixLength(labels: readonly string[], options?: SuffixOptions): number {
  const custom = options?.publicSuffixes;
  if (custom) {
    const list = custom instanceof Set ? custom : new Set(custom);
    for (let n = Math.min(labels.length, 5); n > 1; n--) {
      if (list.has(labels.slice(-n).join("."))) return n;
    }
    return 1;
  }

  const tail = labels.slice(-2);
  if (tail.length < 2) return 1;
  const [second, tld] = tail as [string, string];
  if (KNOWN_SUFFIXES.has(`${second}.${tld}`)) return 2;
  return isCountryCode(tld) && ADMINISTRATIVE_LABELS.has(second) ? 2 : 1;
}

function splitRegistrable(
  host: string,
  options?: SuffixOptions,
): { label: string; suffix: string } | null {
  const labels = host.split(".");
  if (labels.length < 2) return null;
  const length = suffixLength(labels, options);
  if (labels.length <= length) return null;
  const label = labels[labels.length - length - 1];
  if (label === undefined) return null;
  return { label, suffix: labels.slice(-length).join(".") };
}

/**
 * The registrable (organizational) domain of a host, or null when the host is
 * nothing but a public suffix: `mail.acme.co.uk` gives `acme.co.uk`.
 *
 * DMARC discovery needs this. A record missing on a subdomain falls back to
 * the one published on the organizational domain, and relaxed alignment is
 * defined against it.
 *
 * Without a supplied list the suffix rules are an approximation, and the
 * direction they err in is the one that matters: an unrecognised
 * administrative label makes a host read as *more* specific than it is, so
 * two identities that do align are reported as not aligning rather than the
 * other way round.
 */
export function registrableDomain(
  host: string,
  options?: SuffixOptions,
): string | null {
  const parts = splitRegistrable(host.trim().toLowerCase(), options);
  return parts ? `${parts.label}.${parts.suffix}` : null;
}

/** The owner-identifying label alone: `mail.acme.co.uk` gives `acme`. */
export function domainLabel(
  host: string,
  options?: SuffixOptions,
): string | null {
  return splitRegistrable(host.trim().toLowerCase(), options)?.label ?? null;
}

/** A syntactic check only. It says nothing about whether the domain resolves. */
export function isDomainName(host: string): boolean {
  // The TLD is letters, or a punycode label: an IDN suffix is still a domain.
  return /^([a-z0-9-]+\.)+([a-z]{2,}|xn--[a-z0-9-]+)$/.test(host);
}

/** The domain of an email address, or null when it is not addressable. */
export function domainOf(email: string | null | undefined): string | null {
  if (!email) return null;
  const at = email.lastIndexOf("@");
  if (at < 1 || at === email.length - 1) return null;
  const host = email
    .slice(at + 1)
    .trim()
    .toLowerCase()
    .replace(/\.$/, ""); // a trailing root dot addresses the same host
  return isDomainName(host) ? host : null;
}

/**
 * Whatever someone typed, reduced to the domain they meant: a URL loses its
 * scheme and path, an address loses its local part, and `www.` is dropped
 * because mail is virtually never authenticated for it and the apex is what
 * the question is about.
 *
 * Returns a lower-cased hostname that is not necessarily valid, so callers
 * still check it with `isDomainName`.
 */
export function coerceDomain(raw: string): string {
  let s = raw.trim().toLowerCase();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  const at = s.lastIndexOf("@");
  if (at !== -1) s = s.slice(at + 1);
  s = s.split(/[/?#]/)[0] ?? "";
  s = s.split(":")[0] ?? "";
  s = s.replace(/^www\./, "");
  return s.replace(/^\.+|\.+$/g, "");
}

/**
 * Relaxed DMARC alignment: two identities share an organizational domain.
 *
 * This is the check that decides whether an authentication pass means anything
 * to a reader. A message can pass SPF honestly for a domain the sender does
 * control, while the From line names one they do not.
 */
export function aligns(
  a: string | null,
  b: string | null,
  options?: SuffixOptions,
): boolean {
  if (!a || !b) return false;
  const left = a.trim().toLowerCase();
  const right = b.trim().toLowerCase();
  if (left === right) return true;
  const orgA = registrableDomain(left, options);
  const orgB = registrableDomain(right, options);
  return orgA !== null && orgA === orgB;
}
