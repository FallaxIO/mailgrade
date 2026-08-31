/**
 * Message verification: the cryptography and the DNS evaluation that
 * `analyzeHeaders` deliberately does not do.
 *
 * Nothing here opens a socket. DNS comes in through a `Resolver`, crypto is
 * WebCrypto, and both exist in every runtime this library targets, which is
 * how a message verifier stays at zero dependencies and runs in a Worker.
 */

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

export type VerifyMessageOptions = {
  readonly resolver: Resolver;
  /** The IP the message arrived from; without it SPF is skipped. */
  readonly ip?: string;
  /** The MAIL FROM (envelope sender) address. */
  readonly sender?: string;
  /** The HELO/EHLO host name, SPF's fallback identity for a null sender. */
  readonly helo?: string;
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
};

/**
 * Verify a raw message the way a receiving server does: evaluate SPF for the
 * connecting IP, verify every DKIM signature, then ask DMARC whether anything
 * that passed aligns with the From domain.
 */
export async function verifyMessage(
  message: string | Uint8Array,
  options: VerifyMessageOptions,
): Promise<MessageVerification> {
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
          resolver: options.resolver,
        })
      : Promise.resolve(null),
    verifyDkim(parsed, { resolver: options.resolver, now: options.now }),
  ]);

  const dmarc = fromDomain
    ? await verifyDmarc({
        fromDomain,
        spf: spf
          ? { result: spf.result, domain: domainOf(options.sender) ?? spf.domain }
          : null,
        dkim,
        resolver: options.resolver,
        publicSuffixes: options.publicSuffixes,
      })
    : null;

  return { fromDomain, sender: spf ? spfIdentity : null, spf, dkim, dmarc };
}

/**
 * The verification as an RFC 8601 Authentication-Results header value, ready
 * to stamp onto the message before handing it on: what `analyzeHeaders` and
 * every downstream filter read.
 */
export function toAuthResults(
  verification: MessageVerification,
  authservId = "mailgrade",
): string {
  const parts: string[] = [];
  const { spf, dkim, dmarc, sender, fromDomain } = verification;

  if (spf) {
    const identity = sender?.includes("@") ? sender : (sender ?? spf.domain);
    parts.push(`spf=${spf.result} smtp.mailfrom=${identity}`);
  }
  for (const signature of dkim) {
    parts.push(
      `dkim=${signature.result}` +
        (signature.domain ? ` header.d=${signature.domain}` : "") +
        (signature.selector ? ` header.s=${signature.selector}` : ""),
    );
  }
  if (dmarc && dmarc.result !== "none") {
    parts.push(`dmarc=${dmarc.result} header.from=${dmarc.fromDomain}`);
  } else if (fromDomain && (spf || dkim.length > 0)) {
    parts.push(`dmarc=none header.from=${fromDomain}`);
  }

  return parts.length === 0
    ? `${authservId}; none`
    : `${authservId}; ${parts.join("; ")}`;
}
