/**
 * Message verification: the cryptography and the DNS evaluation that
 * `analyzeHeaders` deliberately does not do.
 *
 * Nothing here opens a socket itself. DNS comes in through a `Resolver` and
 * crypto is WebCrypto, and both exist in every runtime this library targets,
 * which is how a message verifier stays at zero dependencies and runs in a
 * Worker. A caller that names no resolver gets DNS over HTTPS, which is
 * `fetch` and therefore still runs everywhere.
 */

import { defaultResolver } from "../doh-resolver.ts";
import { domainOf, type SuffixOptions } from "../domain.ts";
import { parseAddress } from "../headers/parse.ts";
import { verifyDkim, type DkimVerification } from "./dkim.ts";
import { verifyDmarc, type DmarcVerification } from "./dmarc.ts";
import { splitMessage } from "./message.ts";
import type { Resolver } from "./resolver.ts";
import { verifySpf, type SpfVerification } from "./spf.ts";

export { verifySpf } from "./spf.ts";
export type { SpfParams, SpfResult, SpfVerification } from "./spf.ts";
export { verifyDkim } from "./dkim.ts";
export type {
  DkimResult,
  DkimResultId,
  DkimVerification,
  DkimVerifyOptions,
} from "./dkim.ts";
export { verifyDmarc } from "./dmarc.ts";
export type { DmarcParams, DmarcVerification } from "./dmarc.ts";
export type { SuffixOptions } from "../domain.ts";
export { staticResolver } from "./resolver.ts";
export type { DnsRecordType, Resolver } from "./resolver.ts";

/** The authserv-id stamped into headers when the caller names no `mta`. */
const ANONYMOUS_MTA = "mailgrade";

export type VerifyMessageOptions = {
  /**
   * Where DNS comes from. Defaults to DNS over HTTPS against Cloudflare; pass
   * `nodeResolver()` from `mailgrade/node-dns` to use the system resolver, or
   * any `(name, type) => Promise<string[]>` of your own.
   */
  readonly resolver?: Resolver;
  /** The IP the message arrived from; without it SPF is skipped. */
  readonly ip?: string;
  /** The MAIL FROM (envelope sender) address. */
  readonly sender?: string;
  /** The HELO/EHLO host name, SPF's fallback identity for a null sender. */
  readonly helo?: string;
  /**
   * The host doing the verifying, which becomes the authserv-id in the
   * generated headers. Pass the name a downstream filter will trust.
   */
  readonly mta?: string;
  readonly now?: Date;
} & SuffixOptions;

export type MessageVerification = {
  readonly fromDomain: string | null;
  /** The envelope identity SPF was evaluated for: MAIL FROM, or the HELO. */
  readonly sender: string | null;
  /** Null when no IP was given to evaluate against. */
  readonly spf: SpfVerification | null;
  /** One entry per DKIM-Signature header. */
  readonly dkim: readonly DkimVerification[];
  /** Null when the message has no readable From domain. */
  readonly dmarc: DmarcVerification | null;
  /** The Authentication-Results field value, without the field name. */
  readonly authResults: string;
  /**
   * Complete header fields, folded and CRLF-terminated, ready to prepend to
   * the message before handing it on: `Received-SPF` when SPF was evaluated,
   * then `Authentication-Results`.
   */
  readonly headers: string;
};

/**
 * Verify a raw message the way a receiving server does: evaluate SPF for the
 * connecting IP, verify every DKIM signature, then ask DMARC whether anything
 * that passed aligns with the From domain.
 */
export async function verifyMessage(
  message: string | Uint8Array,
  options: VerifyMessageOptions = {},
): Promise<MessageVerification> {
  const resolver = options.resolver ?? defaultResolver();
  const parsed = splitMessage(message);
  const from = parseAddress(
    parsed.headers.find((h) => h.lower === "from")?.value ?? null,
  );
  const fromDomain = from?.domain ?? null;

  const spfIdentity = options.sender?.trim() || options.helo?.trim() || null;
  const [spf, dkim] = await Promise.all([
    options.ip && spfIdentity
      ? verifySpf({
          ip: options.ip,
          sender: spfIdentity,
          helo: options.helo,
          receiver: options.mta,
          resolver,
        })
      : Promise.resolve(null),
    verifyDkim(parsed, { resolver, now: options.now }),
  ]);

  const dmarc = fromDomain
    ? await verifyDmarc({
        fromDomain,
        spf: spf
          ? { result: spf.result, domain: domainOf(options.sender) ?? spf.domain }
          : null,
        dkim,
        resolver,
        publicSuffixes: options.publicSuffixes,
      })
    : null;

  const core = {
    fromDomain,
    sender: spf ? spfIdentity : null,
    spf,
    dkim,
    dmarc,
  };
  const authResults = toAuthResults(core, options.mta ?? ANONYMOUS_MTA);

  return {
    ...core,
    authResults,
    headers: buildHeaders(core, authResults, options),
  };
}

/**
 * The verification as an RFC 8601 Authentication-Results header value, ready
 * to stamp onto the message: what `analyzeHeaders` and every downstream
 * filter read. `verifyMessage` already returns this as `authResults`; call it
 * directly to restamp under a different authserv-id.
 */
export function toAuthResults(
  verification: AuthResultsInput,
  authservId: string = ANONYMOUS_MTA,
): string {
  const parts: string[] = [];
  const { spf, dkim, dmarc, sender, fromDomain } = verification;

  if (spf) {
    const identity = sender?.includes("@") ? sender : (sender ?? spf.domain);
    parts.push(`spf=${spf.result} smtp.mailfrom=${oneLine(identity)}`);
  }
  for (const signature of dkim) {
    parts.push(
      `dkim=${signature.result}` +
        (signature.domain ? ` header.d=${oneLine(signature.domain)}` : "") +
        (signature.selector ? ` header.s=${oneLine(signature.selector)}` : ""),
    );
  }
  if (dmarc && dmarc.result !== "none") {
    parts.push(`dmarc=${dmarc.result} header.from=${oneLine(dmarc.fromDomain)}`);
  } else if (fromDomain && (spf || dkim.length > 0)) {
    parts.push(`dmarc=none header.from=${oneLine(fromDomain)}`);
  }

  return parts.length === 0
    ? `${oneLine(authservId)}; none`
    : `${oneLine(authservId)}; ${parts.join("; ")}`;
}

/** Everything `toAuthResults` reads, so a caller can hand it a partial. */
export type AuthResultsInput = Pick<
  MessageVerification,
  "fromDomain" | "sender" | "spf" | "dkim" | "dmarc"
>;

/* ------------------------------------------------------------ headers --- */

/**
 * The values embedded in the generated headers come off the wire (MAIL FROM,
 * HELO, a hostile message's own DKIM-Signature), so anything that could start
 * a new header field is folded to a space before it is embedded. A CR or LF
 * here is a header injection, not a value.
 */
function oneLine(value: string): string {
  return value.replace(/[\r\n\0]/g, " ").replace(/[ \t]+/g, " ").trim();
}

/** As a quoted-string: RFC 7208's form for envelope-from, quotes escaped. */
function quotedString(value: string): string {
  return `"${oneLine(value).replace(/[\\"]/g, (c) => `\\${c}`)}"`;
}

/**
 * `Received-SPF` first, then `Authentication-Results`, each folded so no line
 * runs past the 78 characters RFC 5322 asks for. A receiver prepends the
 * block verbatim; the order is the order the next hop should read them in.
 */
function buildHeaders(
  verification: AuthResultsInput,
  authResults: string,
  options: VerifyMessageOptions,
): string {
  const fields: string[] = [];
  const receivedSpf = buildReceivedSpf(verification, options);
  if (receivedSpf) fields.push(receivedSpf);
  fields.push(fold("Authentication-Results", authResults));
  return fields.map((field) => `${field}\r\n`).join("");
}

/**
 * RFC 7208 section 9.1. The comment is generated rather than taken from the
 * record's own `exp=`: an explanation the sender wrote is for a human bounce,
 * not for a trace header the next hop parses.
 */
function buildReceivedSpf(
  verification: AuthResultsInput,
  options: VerifyMessageOptions,
): string | null {
  const { spf, sender } = verification;
  if (!spf || !options.ip) return null;

  const ip = oneLine(options.ip);
  const identity = oneLine(sender ?? spf.domain);
  const subject = identity.includes("@")
    ? `domain of ${identity}`
    : `${identity}`;
  const comment =
    spf.result === "pass"
      ? `${subject} designates ${ip} as permitted sender`
      : spf.result === "fail"
        ? `${subject} does not designate ${ip} as permitted sender`
        : `${spf.result} for ${subject}`;

  const keys = [`client-ip=${ip}`];
  if (options.sender) keys.push(`envelope-from=${quotedString(options.sender)}`);
  if (options.helo) keys.push(`helo=${oneLine(options.helo)}`);

  const authority = oneLine(options.mta ?? ANONYMOUS_MTA);
  return fold(
    "Received-SPF",
    `${spf.result} (${authority}: ${comment}) ${keys.join("; ")}`,
  );
}

const LINE_LIMIT = 78;

/**
 * Fold to the 78 characters RFC 5322 asks for, preferring the semicolons that
 * separate a header's parts and falling back to plain spaces when one part is
 * longer than a line on its own, which the SPF comment usually is.
 *
 * Never mid-token and never inside quotes: a signature, an address or a
 * quoted envelope-from broken across a fold is one the next parser gets
 * wrong, and a header nobody downstream can read is worse than a long line.
 */
function fold(name: string, value: string): string {
  const pieces = segments(value);

  let out = `${name}:`;
  let line = out.length;

  for (const piece of pieces) {
    // A part that will not fit starts its own line, unless that would leave
    // the field name sitting alone on the first one.
    if (line + 1 + piece.length > LINE_LIMIT && line > name.length + 1) {
      out += "\r\n";
      line = 0;
    }
    for (const word of unquotedWords(piece)) {
      if (line + 1 + word.length > LINE_LIMIT && line > 1) {
        out += `\r\n ${word}`;
        line = 1 + word.length;
      } else {
        out += ` ${word}`;
        line += 1 + word.length;
      }
    }
  }

  return out;
}

/**
 * Split after the semicolons that separate a header's parts, keeping each
 * semicolon with its part and dropping the whitespace between parts. Only
 * the semicolons outside quotes count: `envelope-from="\"a;b\"@x.com"` is
 * one part, not two.
 */
function segments(value: string): string[] {
  const out: string[] = [];
  let current = "";
  let quoted = false;
  let escaped = false;

  for (const char of value) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === "\\" && quoted) {
      current += char;
      escaped = true;
      continue;
    }
    if (char === '"') quoted = !quoted;
    if ((char === " " || char === "\t") && !quoted && current === "") continue;
    current += char;
    if (char === ";" && !quoted) {
      out.push(current);
      current = "";
    }
  }
  if (current !== "") out.push(current);

  return out;
}

/** Split on the spaces that are foldable, which is the ones outside quotes. */
function unquotedWords(value: string): string[] {
  const out: string[] = [];
  let current = "";
  let quoted = false;
  let escaped = false;

  for (const char of value) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === "\\" && quoted) {
      current += char;
      escaped = true;
      continue;
    }
    if (char === '"') quoted = !quoted;
    if ((char === " " || char === "\t") && !quoted) {
      if (current !== "") out.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  if (current !== "") out.push(current);

  return out;
}
