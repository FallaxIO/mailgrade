/**
 * Grading DKIM from the outside.
 *
 * Selectors are free-form, so nobody can enumerate a domain's keys. The best
 * an external check can do is probe the fixed names the large providers
 * publish under, which is why a miss is a warning and never a failure.
 */

import type { Status } from "./types.ts";

export type DkimFinding = "dkim-published" | "dkim-absent";

export type DkimAnalysis = {
  readonly id: DkimFinding;
  readonly status: Status;
  /** Selectors that answered with a usable key. */
  readonly selectorsFound: readonly string[];
  readonly probed: number;
  readonly headline: string;
  readonly detail: string;
};

/**
 * Selectors worth probing blind: fixed names the big providers publish under,
 * so a hit identifies real signing infrastructure.
 *
 * Kept short on purpose. Every entry is a DNS lookup per check, and a miss
 * across all of them still proves nothing.
 */
export const DKIM_SELECTORS: readonly string[] = [
  "google", // Google Workspace
  "selector1", // Microsoft 365
  "selector2", // Microsoft 365
  "k1", // Mailchimp
  "k2",
  "s1", // SendGrid
  "s2",
  "fm1", // Fastmail
  "fm2",
  "pm", // Postmark
  "resend", // Resend
  "mte1", // Mailtrap
  "zendesk1",
  "zendesk2",
  "protonmail", // Proton
  "default",
  "dkim",
  "mail",
];

/** The DNS name a selector's key is published at. */
export function dkimHost(selector: string, domain: string): string {
  return `${selector}._domainkey.${domain}`;
}

/**
 * True for a TXT record that is a live DKIM key.
 *
 * A revocation is the same record with an empty p=, which is a deliberate
 * "this key is dead" rather than a key, so it does not count as one.
 */
export function isDkimKey(txt: string): boolean {
  const t = txt.trim();
  return (
    /(^|;)\s*p\s*=\s*[a-z0-9+/=]/i.test(t) &&
    (/^v\s*=\s*dkim1\b/i.test(t) || !/^v\s*=/i.test(t))
  );
}

export function analyzeDkim(
  selectorsFound: readonly string[],
  probed: number = DKIM_SELECTORS.length,
): DkimAnalysis {
  if (selectorsFound.length > 0) {
    return {
      id: "dkim-published",
      status: "pass",
      selectorsFound,
      probed,
      headline: `DKIM keys published (${selectorsFound.join(", ")})`,
      detail:
        "Receivers can verify signatures made with these keys. DKIM alone does not stop spoofing, since an attacker simply omits the signature; it matters because DMARC needs a signature to align against.",
    };
  }
  return {
    id: "dkim-absent",
    status: "warn",
    selectorsFound,
    probed,
    headline: "No DKIM keys at the common selectors",
    detail: `None of the ${probed} selector names the major providers use answered with a key. Selectors are free-form, so this is not proof DKIM is off, but if your provider's setup guide lists DNS records you never added, this is the symptom.`,
  };
}
