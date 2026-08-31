/**
 * Domain arithmetic shared by every other module: which part of a host someone
 * had to register, and whether two identities count as the same organisation.
 */

/**
 * Public suffixes made of two labels, so `yahoo.co.uk` resolves to the
 * registrable domain `yahoo.co.uk` and not to `co.uk`.
 *
 * A deliberate subset of the real Public Suffix List. Shipping the full list
 * would mean either a dependency or a megabyte of data that goes stale, and
 * anything missing here degrades in the safe direction: a host reads as more
 * specific than it is, so two identities that do align are reported as not
 * aligning rather than the other way round.
 */
const MULTI_LABEL_SUFFIXES: ReadonlySet<string> = new Set([
  "ac.uk", "co.at", "co.id", "co.il", "co.in", "co.jp", "co.kr", "co.nz",
  "co.th", "co.uk", "co.za", "com.ar", "com.au", "com.bd", "com.br", "com.cn",
  "com.co", "com.eg", "com.es", "com.gr", "com.hk", "com.mx", "com.my",
  "com.ng", "com.pe", "com.ph", "com.pk", "com.pl", "com.pt", "com.sa",
  "com.sg", "com.tr", "com.tw", "com.ua", "com.vn", "in.ua", "ne.jp",
  "net.au", "net.br", "net.mx", "net.nz", "or.jp", "org.uk",
]);

function splitRegistrable(
  host: string,
): { label: string; suffix: string } | null {
  const labels = host.split(".");
  if (labels.length < 2) return null;
  const suffixLength = MULTI_LABEL_SUFFIXES.has(labels.slice(-2).join("."))
    ? 2
    : 1;
  if (labels.length <= suffixLength) return null;
  const label = labels[labels.length - suffixLength - 1];
  if (label === undefined) return null;
  return { label, suffix: labels.slice(-suffixLength).join(".") };
}

/**
 * The registrable (organizational) domain of a host, or null when the host is
 * nothing but a public suffix: `mail.acme.co.uk` gives `acme.co.uk`.
 *
 * DMARC discovery needs this. A record missing on a subdomain falls back to
 * the one published on the organizational domain, and relaxed alignment is
 * defined against it.
 */
export function registrableDomain(host: string): string | null {
  const parts = splitRegistrable(host.trim().toLowerCase());
  return parts ? `${parts.label}.${parts.suffix}` : null;
}

/** The owner-identifying label alone: `mail.acme.co.uk` gives `acme`. */
export function domainLabel(host: string): string | null {
  return splitRegistrable(host.trim().toLowerCase())?.label ?? null;
}

/** A syntactic check only. It says nothing about whether the domain resolves. */
export function isDomainName(host: string): boolean {
  return /^([a-z0-9-]+\.)+[a-z]{2,}$/.test(host);
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
export function aligns(a: string | null, b: string | null): boolean {
  if (!a || !b) return false;
  const left = a.trim().toLowerCase();
  const right = b.trim().toLowerCase();
  if (left === right) return true;
  const orgA = registrableDomain(left);
  const orgB = registrableDomain(right);
  return orgA !== null && orgA === orgB;
}
