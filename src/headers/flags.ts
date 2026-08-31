/**
 * Everything in a header block that is worth pointing at, strongest first.
 *
 * The question is not "is this well formed" but "how far would this message
 * get, and does the name on it mean anything".
 */

import { aligns, domainLabel, registrableDomain } from "../domain.ts";
import type { Severity } from "../types.ts";
import type { AuthCheck } from "./auth.ts";
import {
  detectImpersonation,
  hasMixedScript,
  INVISIBLE,
} from "./impersonation.ts";
import type { HeaderField } from "./parse.ts";
import type {
  AuthSource,
  Flag,
  Identity,
  MessageSummary,
  Route,
} from "./types.ts";

/** A domain-shaped token inside free text, used to read a display name. */
const DOMAIN_IN_TEXT = /\b([a-z0-9][a-z0-9-]{1,62}(?:\.[a-z]{2,})+)\b/gi;

const ORDER: Record<Severity, number> = { high: 0, medium: 1, info: 2 };

export function buildFlags(
  fields: readonly HeaderField[],
  identity: Identity,
  authSource: AuthSource,
  spf: AuthCheck,
  dkim: AuthCheck,
  dmarc: AuthCheck,
  route: Route,
  message: MessageSummary,
): Flag[] {
  const flags: Flag[] = [];
  const from = identity.from;
  const fromDomain = from?.domain ?? null;

  const push = (
    id: string,
    severity: Severity,
    title: string,
    detail: string,
    evidence: string | null = null,
  ) => flags.push({ id, severity, title, detail, evidence });

  /* ------------------------------------------------- authentication --- */

  if (dmarc.status === "fail") {
    push(
      "dmarc-fail",
      "high",
      "The From domain did not authenticate",
      `A receiving server checked this message against ${fromDomain ?? "the sending domain"}'s own published records and it failed. Legitimate mail from a domain that publishes those records passes them.`,
      dmarc.result ? `dmarc=${dmarc.result}` : null,
    );
  } else if (
    // Only when a receiver actually reported something. A missing DKIM
    // signature reads as `dkim=none` in the row above, but nobody checked it,
    // and "nothing authenticates the From domain" would then fire on every
    // paste that is simply too short.
    authSource !== "none" &&
    dmarc.status !== "pass" &&
    spf.aligned !== true &&
    dkim.aligned !== true
  ) {
    const authenticated = [spf.identifier, dkim.identifier]
      .filter(Boolean)
      .join(", ");
    push(
      "unaligned",
      "high",
      "Nothing here authenticates the From domain",
      authenticated
        ? `The checks that did pass authenticated ${authenticated}, not ${fromDomain ?? "the From domain"}. This is the shape of a message sent through a service the attacker controls: it passes SPF honestly, for their domain, while the From line says yours.`
        : `No passing check names ${fromDomain ?? "the From domain"}, so nothing in these headers supports the sender the reader sees.`,
      authenticated || null,
    );
  }

  if (dkim.result === "fail") {
    push(
      "dkim-fail",
      "high",
      "A DKIM signature failed to verify",
      "The message carries a signature that does not match its contents. Either it was altered after signing or the signature was fabricated.",
      dkim.identifier,
    );
  }

  if (spf.result === "fail" && dmarc.status !== "pass") {
    push(
      "spf-fail",
      "high",
      "The delivering server is not authorised to send for this domain",
      "SPF hard-failed: the domain publishes a list of its sending servers and this was not one of them.",
      spf.identifier,
    );
  }

  /* ------------------------------------------------------- identity --- */

  if (identity.fromCount > 1) {
    push(
      "multiple-from",
      "high",
      `${identity.fromCount} From headers`,
      "A message may have one From header. More than one is a header injection trick: filters read the first and the mail client shows the last, so what was scanned is not what the reader sees.",
    );
  }

  if (fromDomain?.split(".").some((l) => l.startsWith("xn--"))) {
    push(
      "punycode",
      "high",
      "The sender domain is not the ASCII it appears to be",
      "This domain is encoded punycode, which mail clients render as Unicode. It is the mechanism behind lookalike domains built from letters that are not the Latin ones they resemble.",
      fromDomain,
    );
  }

  const impersonation = fromDomain ? detectImpersonation(fromDomain) : null;
  if (impersonation && fromDomain) {
    const org = registrableDomain(fromDomain) ?? fromDomain;
    if (impersonation.kind === "token") {
      push(
        "brand-in-subdomain",
        "high",
        `"${domainLabel(impersonation.brand)}" appears in a domain that is not theirs`,
        `The name sits in the host, but the domain actually registered here is ${org}, which has nothing to do with ${impersonation.brand}. Anyone can put a brand name to the left of their own domain.`,
        fromDomain,
      );
    } else if (impersonation.kind === "typosquat") {
      push(
        "typosquat",
        "high",
        `One character away from ${impersonation.brand}`,
        `${org} differs from ${impersonation.brand} by a single edit. At a glance in a mail client, and especially on a phone, that is invisible.`,
        fromDomain,
      );
    } else {
      push(
        "brand-other-tld",
        "medium",
        `Same name as ${impersonation.brand}, different suffix`,
        `${org} carries the brand's name under another suffix. Large brands do run local domains, so check this against a known-good address rather than assuming either way.`,
        fromDomain,
      );
    }
  }

  if (from?.display) {
    const display = from.display;

    const embedded = display.match(/[^\s<>()]+@[^\s<>()]+\.[a-z]{2,}/i)?.[0];
    if (embedded && from.address && embedded.toLowerCase() !== from.address) {
      push(
        "display-name-address",
        "high",
        "The display name is a different address to the real one",
        `The name shown reads ${embedded}, and the address the reply would actually go to is ${from.address}. Most mail clients show only the first.`,
        `${display} <${from.address}>`,
      );
    } else if (!embedded && fromDomain) {
      const mentioned = [...display.matchAll(DOMAIN_IN_TEXT)]
        .map((m) => (m[1] ?? "").toLowerCase())
        .find((d) => d && !aligns(d, fromDomain));
      if (mentioned) {
        push(
          "display-name-domain",
          "medium",
          "The display name names a domain the message is not from",
          `The name shown mentions ${mentioned}, while the message was sent from ${fromDomain}.`,
          display,
        );
      }
    }

    if (INVISIBLE.test(display)) {
      push(
        "bidi-display-name",
        "high",
        "The display name contains invisible control characters",
        "Bidirectional overrides and zero-width characters have exactly one use in a sender name, which is to make it render as something other than what it is.",
        JSON.stringify(display),
      );
    } else if (hasMixedScript(display)) {
      push(
        "mixed-script",
        "medium",
        "The display name mixes alphabets",
        "Latin letters sit alongside Cyrillic or Greek ones that look identical. A reader cannot tell them apart, and neither can a name-based filter.",
        display,
      );
    }
  }

  if (message.subject && INVISIBLE.test(message.subject)) {
    push(
      "bidi-subject",
      "medium",
      "The subject contains invisible control characters",
      "Right-to-left overrides in a subject are used to disguise a file extension, so that an attachment named x.exe reads as x.pdf.",
    );
  }

  const replyTo = identity.replyTo;
  if (replyTo?.domain && fromDomain && !aligns(replyTo.domain, fromDomain)) {
    push(
      "reply-to-mismatch",
      "high",
      "Replies would go to a different domain",
      `The message says it is from ${fromDomain}, but a reply is addressed to ${replyTo.address ?? replyTo.domain}. That redirect is the whole mechanism of invoice fraud: the thread looks normal and the answers reach the attacker.`,
      replyTo.raw,
    );
  }

  const returnPath = identity.returnPath;
  if (
    returnPath?.domain &&
    fromDomain &&
    !aligns(returnPath.domain, fromDomain) &&
    dmarc.status !== "pass"
  ) {
    push(
      "return-path-mismatch",
      "medium",
      "The envelope sender is a different domain",
      `Bounces for this message go to ${returnPath.domain} rather than ${fromDomain}. Bulk senders do this legitimately all the time, which is why it is only worth noting alongside the authentication results above.`,
      returnPath.raw,
    );
  }

  /* ---------------------------------------------------------- route --- */

  if (route.hops.length === 0) {
    push(
      "no-received",
      "info",
      "No delivery path in these headers",
      "There are no Received headers, so the message either never travelled (a draft or a sent copy) or the paste is missing the top of the block.",
    );
  }

  const phpSource = fields.find(
    (f) => f.lower === "x-php-originating-script" || f.lower === "x-php-script",
  );
  if (phpSource) {
    push(
      "php-origin",
      "medium",
      "Sent by a script on a web server",
      "This header is added by PHP's mail function and names the file that sent the message. Legitimate business mail leaves a mail server; a compromised website's contact form leaves this.",
      phpSource.value,
    );
  } else if (route.mailer && /phpmailer|phpmail|swiftmailer/i.test(route.mailer)) {
    push(
      "script-mailer",
      "info",
      "Sent by a scripting library, not a mail client",
      `The X-Mailer header names ${route.mailer}. That is normal for application mail and notifications, and it is also what bulk phishing kits ship with.`,
      route.mailer,
    );
  }

  if (message.spamScore) {
    push(
      "filter-flagged",
      "medium",
      "The receiving filter already scored this as spam",
      "The mail system that delivered this message had reservations of its own and recorded them in the headers.",
      message.spamScore,
    );
  }

  /* ----------------------------------------------------- timestamps --- */

  const origin = route.hops[0]?.date;
  if (message.date && origin) {
    const stated = Date.parse(message.date);
    const actual = Date.parse(origin);
    const skewHours = Math.abs(stated - actual) / 3_600_000;
    if (Number.isFinite(skewHours) && skewHours > 24) {
      push(
        "date-skew",
        "medium",
        "The stated date is far from when it was actually sent",
        `The Date header is ${Math.round(skewHours / 24)} days away from the timestamp on the first delivery hop. Backdating is used to bury a message far down an inbox where it is read but not questioned.`,
        `${message.date} vs ${origin}`,
      );
    }
  }

  if (message.listUnsubscribe) {
    push(
      "bulk",
      "info",
      "Sent as bulk mail",
      "A List-Unsubscribe header means this came from a mailing platform rather than a person's mailbox. Expected for a newsletter, and out of place on an invoice or a password reset.",
    );
  }

  return flags.toSorted((a, b) => ORDER[a.severity] - ORDER[b.severity]);
}
