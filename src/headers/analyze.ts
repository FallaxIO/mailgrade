/**
 * The whole header analysis, from a pasted block to a verdict.
 */

import type { Recommendation } from "../types.ts";
import { blankCheck, dkimCheck, dmarcCheck, spfCheck } from "./auth.ts";
import { buildFlags } from "./flags.ts";
import {
  decodeEncodedWords,
  headerValue,
  headerValues,
  identifierDomain,
  parseAddress,
  parseAuthResults,
  parseHeaders,
  parseReceived,
  type Address,
  type MethodResult,
} from "./parse.ts";
import type {
  AuthSource,
  Flag,
  HeaderAnalysis,
  HeaderVerdict,
  Identity,
  MessageSummary,
  Route,
} from "./types.ts";

const NO_HEADERS: HeaderAnalysis = {
  verdict: "inconclusive",
  summary: "Paste the message headers to see who really sent it.",
  authSource: "none",
  spf: blankCheck("SPF"),
  dkim: blankCheck("DKIM"),
  dmarc: blankCheck("DMARC"),
  identity: {
    from: null,
    returnPath: null,
    replyTo: null,
    to: null,
    fromCount: 0,
  },
  route: { hops: [], originatingIp: null, mailer: null },
  message: {
    subject: null,
    date: null,
    messageId: null,
    listUnsubscribe: false,
    spamScore: null,
  },
  flags: [],
  recommendations: [],
};

/**
 * One high-severity finding is enough to call a message suspicious, because
 * every one of them is a thing legitimate mail does not do. Without a From
 * line or a receiver's verdict there is nothing to be confident about either
 * way, which is what inconclusive means.
 */
export function headerVerdict(
  flags: readonly Flag[],
  authSource: AuthSource,
  hasFrom: boolean,
): HeaderVerdict {
  if (flags.some((f) => f.severity === "high")) return "suspicious";
  if (!hasFrom || authSource === "none") return "inconclusive";
  return "authentic";
}

function summarize(
  verdict: HeaderVerdict,
  flags: readonly Flag[],
  from: Address | null,
): string {
  const domain = from?.domain ?? "the sending domain";
  if (verdict === "suspicious") {
    const high = flags.filter((f) => f.severity === "high").length;
    return high === 1
      ? `One finding here is serious enough on its own: this message does not hold up as mail from ${domain}.`
      : `${high} separate findings say the same thing: this message does not hold up as mail from ${domain}.`;
  }
  if (verdict === "inconclusive") {
    return "These headers do not carry enough for a verdict. No receiving server recorded an authentication result, which usually means the paste is missing the top of the block.";
  }
  return `Authentication ties this message to ${domain}, so it really was sent by someone who controls that domain. That is not the same as someone you should trust.`;
}

function recommend(
  verdict: HeaderVerdict,
  flags: readonly Flag[],
): Recommendation[] {
  const recs: Recommendation[] = [];
  const has = (id: string) => flags.some((f) => f.id === id);

  if (verdict === "suspicious") {
    recs.push({
      id: "do-not-engage",
      text: "Do not reply, click, or open attachments. Report it through whatever channel your organisation uses, so the same message can be pulled from everyone else's mailbox.",
    });
    if (has("reply-to-mismatch")) {
      recs.push({
        id: "verify-by-phone",
        text: "If this thread is about a payment or a change of bank details, verify by phone on a number you already had, never one from the message.",
      });
    }
    recs.push({
      id: "check-own-domain",
      text: "Check whether your own domain can be forged the same way: grade its SPF, DKIM and DMARC records and see what a receiver would do with a message sent in your name.",
    });
  } else if (verdict === "inconclusive") {
    recs.push({
      id: "get-full-source",
      text: "Get the full source: in Gmail open the message, then More, then Show original. In Outlook on the web, More actions, then View, then View message source. The block must start at the topmost Received line.",
    });
    recs.push({
      id: "receiver-not-recording",
      text: "If the headers really do lack authentication results, the receiving mail system is not recording them, which is worth fixing before you need them.",
    });
  } else {
    recs.push({
      id: "auth-is-not-intent",
      text: "Authentication proves the domain, not the intent. A supplier whose mailbox has been taken over sends mail that passes every check here, and so does a real domain registered by an attacker yesterday.",
    });
    recs.push({
      id: "judge-the-request",
      text: "Judge the request, not the sender: an unexpected change of bank details, a link to a login page, or urgency about something you did not start deserves a second channel regardless of what these headers say.",
    });
  }

  if (has("brand-other-tld") || has("typosquat") || has("brand-in-subdomain")) {
    recs.push({
      id: "compare-known-good",
      text: "Compare the sending domain against a message you know is genuine from the same organisation, rather than against memory.",
    });
  }

  return recs;
}

export function analyzeHeaders(raw: string): HeaderAnalysis {
  const fields = parseHeaders(raw);
  if (fields.length === 0) return NO_HEADERS;

  const fromValues = headerValues(fields, "from");
  const from = parseAddress(fromValues[0] ?? null);
  const fromDomain = from?.domain ?? null;

  /* The topmost Authentication-Results is the last one added, by the server
     that actually delivered to this mailbox. Ones below it were written by
     hosts upstream, which the recipient's own system did not vouch for. */
  const authHeaders = headerValues(fields, "authentication-results");
  const arcHeaders = headerValues(fields, "arc-authentication-results");
  const receivedSpf = headerValue(fields, "received-spf");

  const results = new Map<string, MethodResult>();
  for (const header of [...authHeaders, ...arcHeaders]) {
    for (const [method, value] of parseAuthResults(header)) {
      if (!results.has(method)) results.set(method, value);
    }
  }

  const authSource: AuthSource =
    authHeaders.length > 0
      ? "receiver"
      : arcHeaders.length > 0
        ? "arc"
        : receivedSpf
          ? "received-spf"
          : "none";

  const signatureDomains = headerValues(fields, "dkim-signature")
    .map((v) => identifierDomain(v.match(/(?:^|;)\s*d\s*=\s*([^;\s]+)/i)?.[1]))
    .filter((d): d is string => d !== null);

  const spf = spfCheck(results.get("spf"), receivedSpf, fromDomain);
  const dkim = dkimCheck(results.get("dkim"), signatureDomains, fromDomain);
  const dmarc = dmarcCheck(results.get("dmarc"), spf, dkim, fromDomain);

  // Each server prepends its own Received, so the header list runs newest
  // first and the message reads backwards until it is reversed.
  const hops = headerValues(fields, "received")
    .toReversed()
    .map((value, i) => parseReceived(value, i + 1));
  const originatingIp =
    hops.find((h) => h.ip !== null && !h.privateIp)?.ip ??
    hops[0]?.ip ??
    headerValue(fields, "x-originating-ip")?.replace(/[[\]]/g, "").trim() ??
    null;

  const identity: Identity = {
    from,
    returnPath: parseAddress(headerValue(fields, "return-path")),
    replyTo: parseAddress(headerValue(fields, "reply-to")),
    to: parseAddress(headerValue(fields, "to")),
    fromCount: fromValues.length,
  };

  const route: Route = {
    hops,
    originatingIp,
    mailer:
      headerValue(fields, "x-mailer") ?? headerValue(fields, "user-agent"),
  };

  const antispam = fields.find(
    (f) =>
      f.lower === "x-forefront-antispam-report" ||
      f.lower === "x-microsoft-antispam",
  );
  const scl = antispam?.value.match(/\bSCL:(\d+)/i);
  const spamStatus = headerValue(fields, "x-spam-status");
  const spamScore =
    scl && Number(scl[1]) >= 5
      ? `SCL:${scl[1]}`
      : spamStatus && /^yes\b/i.test(spamStatus.trim())
        ? (spamStatus.match(/^yes(?:[,\s]+score=\S+)?/i)?.[0] ?? "Yes")
        : null;

  const subject = headerValue(fields, "subject");
  const message: MessageSummary = {
    subject: subject ? decodeEncodedWords(subject) : null,
    date: headerValue(fields, "date"),
    messageId: headerValue(fields, "message-id"),
    listUnsubscribe: fields.some((f) => f.lower === "list-unsubscribe"),
    spamScore,
  };

  const flags = buildFlags(
    fields,
    identity,
    authSource,
    spf,
    dkim,
    dmarc,
    route,
    message,
  );
  const verdict = headerVerdict(flags, authSource, from !== null);

  return {
    verdict,
    summary: summarize(verdict, flags, from),
    authSource,
    spf,
    dkim,
    dmarc,
    identity,
    route,
    message,
    flags,
    recommendations: recommend(verdict, flags),
  };
}
