/**
 * Does a sending domain trade on a well-known brand's name without being it?
 */

import { domainLabel, registrableDomain } from "../domain.ts";

/**
 * Domains worth a lookalike check: the brands whose name in a From line makes
 * a stranger act, plus the logistics and government senders that carry the
 * European share of it.
 *
 * A short list on purpose. Every entry is a chance to mislabel a legitimate
 * regional domain, so it earns its place by being one attackers actually
 * reach for.
 */
export const IMPERSONATED_DOMAINS: readonly string[] = [
  "microsoft.com",
  "office.com",
  "outlook.com",
  "sharepoint.com",
  "google.com",
  "gmail.com",
  "apple.com",
  "icloud.com",
  "amazon.com",
  "paypal.com",
  "stripe.com",
  "docusign.com",
  "dropbox.com",
  "adobe.com",
  "linkedin.com",
  "netflix.com",
  "facebook.com",
  "instagram.com",
  "slack.com",
  "zoom.us",
  "salesforce.com",
  "coinbase.com",
  "binance.com",
  "wetransfer.com",
  "klarna.com",
  "revolut.com",
  "dhl.com",
  "fedex.com",
  "bpost.be",
  "hmrc.gov.uk",
];

export function editDistance(a: string, b: string): number {
  const rows = a.length + 1;
  let previous = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i < rows; i++) {
    const current = [i];
    for (let j = 1; j <= b.length; j++) {
      current[j] = Math.min(
        (previous[j] ?? 0) + 1,
        (current[j - 1] ?? 0) + 1,
        (previous[j - 1] ?? 0) + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
    previous = current;
  }
  return previous[b.length] ?? 0;
}

export type Impersonation = {
  readonly brand: string;
  readonly kind: "typosquat" | "token" | "suffix";
};

/**
 * Three shapes, in descending confidence.
 *
 * `token` is the strongest: the brand name appears as its own label or
 * hyphen-separated word somewhere in the host that is not the registrable
 * domain, which is `paypal-secure.co` and `microsoft.login-verify.ru`.
 * `typosquat` needs a single edit on a name long enough that one edit is not a
 * coincidence, so `micros0ft` is caught and `apple` versus `apply` is left
 * alone. `suffix` is the same name under a different TLD, which is also how
 * brands run their own local sites, so it is reported as something to check
 * rather than something that is wrong.
 */
export function detectImpersonation(
  domain: string,
  brands: readonly string[] = IMPERSONATED_DOMAINS,
): Impersonation | null {
  const host = domain.toLowerCase();
  const org = registrableDomain(host);
  if (!org) return null;
  const label = domainLabel(host);
  if (!label) return null;

  const tokens = new Set(host.split(/[.-]/).filter(Boolean));

  for (const brand of brands) {
    if (org === brand) return null;
    const brandLabel = domainLabel(brand);
    if (!brandLabel) continue;

    if (tokens.has(brandLabel) && label !== brandLabel) {
      return { brand, kind: "token" };
    }
    if (label === brandLabel) return { brand, kind: "suffix" };

    const distance = editDistance(label, brandLabel);
    const long = brandLabel.length >= 6;
    if (long && (distance === 1 || (distance === 2 && brandLabel.length >= 9))) {
      return { brand, kind: "typosquat" };
    }
  }
  return null;
}

/* -------------------------------------------------------------- text --- */

/** Bidi overrides and invisible characters, which exist in a name only to lie. */
export const INVISIBLE: RegExp = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/;

const CYRILLIC_OR_GREEK = /[\u0370-\u03FF\u0400-\u04FF]/;
const LATIN = /[a-z]/i;

export function hasMixedScript(text: string): boolean {
  return LATIN.test(text) && CYRILLIC_OR_GREEK.test(text);
}
