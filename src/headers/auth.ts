/**
 * Reading the authentication verdicts a receiving server wrote down.
 *
 * These are reports, not proofs: nothing here re-runs the cryptography. What
 * this module adds on top is alignment, which is the part that decides whether
 * a pass means anything to the person reading the From line.
 */

import { aligns } from "../domain.ts";
import type { AuthStatus } from "../types.ts";
import { identifierDomain, stripComments, type MethodResult } from "./parse.ts";

export type AuthCheck = {
  readonly status: AuthStatus;
  /** The verdict token the receiver published: pass, fail, softfail, none... */
  readonly result: string | null;
  /** The identity that was authenticated, if the receiver named one. */
  readonly identifier: string | null;
  /** Whether that identity aligns with the From domain; null when unknowable. */
  readonly aligned: boolean | null;
  readonly headline: string;
  readonly detail: string;
};

export function blankCheck(method: string): AuthCheck {
  return {
    status: "neutral",
    result: null,
    identifier: null,
    aligned: null,
    headline: `No ${method} result`,
    detail: "",
  };
}

type Explanation = { status: AuthStatus; detail: string };

const SPF_DETAIL: Record<string, Explanation> = {
  pass: {
    status: "pass",
    detail:
      "The server that delivered this message is on the sending domain's published list. On its own that only vouches for the hidden envelope sender, not for the name in the From line.",
  },
  fail: {
    status: "fail",
    detail:
      "The sending domain publishes a list of servers allowed to send for it, and the machine that delivered this message is not on it.",
  },
  softfail: {
    status: "warn",
    detail:
      "The domain's record says this server probably should not be sending for it, but stops short of asking receivers to refuse the mail.",
  },
  neutral: {
    status: "warn",
    detail:
      "The domain publishes SPF but explicitly declines to judge this server, which is the same as having no opinion.",
  },
  none: {
    status: "warn",
    detail:
      "The sending domain publishes no SPF record at all, so nothing here says which servers may send in its name.",
  },
  permerror: {
    status: "warn",
    detail:
      "The domain's SPF record is malformed, so receivers could not evaluate it. Broken SPF protects nothing.",
  },
  temperror: {
    status: "warn",
    detail:
      "The receiver hit a temporary DNS failure and could not evaluate SPF for this message.",
  },
};

const DKIM_DETAIL: Record<string, Explanation> = {
  pass: {
    status: "pass",
    detail:
      "A cryptographic signature on this message verified against a key published by the signing domain, so the message really left that domain's systems and was not modified on the way.",
  },
  fail: {
    status: "fail",
    detail:
      "A signature was present and did not verify. Either the message was altered in transit or the signature was forged.",
  },
  none: {
    status: "warn",
    detail:
      "The message carries no DKIM signature, so nothing cryptographic ties it to the domain it claims. Plenty of legitimate mail is unsigned, and every forged message is.",
  },
  neutral: {
    status: "warn",
    detail: "The receiver found a signature it could not evaluate.",
  },
  permerror: {
    status: "warn",
    detail:
      "The signature or the key it points at is malformed, so verification could not be attempted.",
  },
  temperror: {
    status: "warn",
    detail: "A temporary failure stopped the receiver verifying the signature.",
  },
};

export function spfCheck(
  result: MethodResult | undefined,
  receivedSpf: string | null,
  fromDomain: string | null,
): AuthCheck {
  let token = result?.result ?? null;
  let identifier = identifierDomain(
    result?.properties["smtp.mailfrom"] ?? result?.properties["smtp.helo"],
  );

  if (!token && receivedSpf) {
    token = receivedSpf.trim().split(/\s+/)[0]?.toLowerCase() ?? null;
    identifier ??= identifierDomain(
      stripComments(receivedSpf).match(
        /(?:smtp\.mailfrom|envelope-from)=([^\s;]+)/i,
      )?.[1],
    );
  }

  if (!token) return blankCheck("SPF");

  const known: Explanation = SPF_DETAIL[token] ?? {
    status: "warn",
    detail: `The receiver reported an SPF result of "${token}".`,
  };
  const aligned = identifier ? aligns(identifier, fromDomain) : null;

  return {
    status: known.status,
    result: token,
    identifier,
    aligned,
    headline:
      token === "pass" && aligned === false
        ? "SPF passed for a different domain"
        : `SPF ${token}`,
    detail:
      token === "pass" && aligned === false && identifier
        ? `${known.detail} The envelope sender it authenticated was ${identifier}, which is not the domain in the From line, so this pass says nothing about the sender the reader sees.`
        : known.detail,
  };
}

export function dkimCheck(
  result: MethodResult | undefined,
  signatureDomains: readonly string[],
  fromDomain: string | null,
): AuthCheck {
  const token = result?.result ?? (signatureDomains.length > 0 ? null : "none");
  const identifier =
    identifierDomain(
      result?.properties["header.d"] ?? result?.properties["header.i"],
    ) ??
    signatureDomains[0] ??
    null;

  if (!token) {
    return {
      status: "warn",
      result: null,
      identifier,
      aligned: identifier ? aligns(identifier, fromDomain) : null,
      headline: "DKIM signature present, no verdict",
      detail: `The message is signed by ${identifier}, but no receiving server recorded whether the signature verified. A signature nobody checked proves nothing.`,
    };
  }

  const known: Explanation = DKIM_DETAIL[token] ?? {
    status: "warn",
    detail: `The receiver reported a DKIM result of "${token}".`,
  };
  const aligned = identifier ? aligns(identifier, fromDomain) : null;

  return {
    status: known.status,
    result: token,
    identifier,
    aligned,
    headline:
      token === "pass" && aligned === false
        ? "DKIM passed for a different domain"
        : `DKIM ${token}`,
    detail:
      token === "pass" && aligned === false && identifier
        ? `${known.detail} The signature belongs to ${identifier} though, not to the domain in the From line, so it vouches for whoever operates that domain and not for the apparent sender.`
        : known.detail,
  };
}

export function dmarcCheck(
  result: MethodResult | undefined,
  spf: AuthCheck,
  dkim: AuthCheck,
  fromDomain: string | null,
): AuthCheck {
  const token = result?.result ?? null;
  const identifier = identifierDomain(result?.properties["header.from"]);
  const anyAligned = spf.aligned === true || dkim.aligned === true;

  if (token === "pass") {
    return {
      status: "pass",
      result: token,
      identifier: identifier ?? fromDomain,
      aligned: true,
      headline: "DMARC pass",
      detail:
        "At least one authenticated identity matched the domain in the From line, which is the only check that ties the name a reader sees to a domain someone had to control.",
    };
  }
  if (token === "fail") {
    return {
      status: "fail",
      result: token,
      identifier: identifier ?? fromDomain,
      aligned: false,
      headline: "DMARC fail",
      detail:
        "Nothing authenticated matched the From domain. This message claims to be from that domain and the domain's own records do not back it up.",
    };
  }
  if (!token) {
    return {
      status: anyAligned ? "pass" : "warn",
      result: null,
      identifier: fromDomain,
      aligned: anyAligned,
      headline: anyAligned
        ? "No DMARC verdict, but the From domain is authenticated"
        : "No DMARC verdict recorded",
      detail: anyAligned
        ? "No receiver published a DMARC result, but SPF or DKIM authenticated the same domain that appears in the From line, which is what a DMARC pass is made of."
        : "No receiver published a DMARC result, and nothing that did authenticate matches the From domain, so the From line is unverified.",
    };
  }
  return {
    status: "warn",
    result: token,
    identifier: identifier ?? fromDomain,
    aligned: anyAligned,
    headline: `DMARC ${token}`,
    detail:
      token === "none"
        ? "The From domain publishes no DMARC policy, so receivers had no instruction and delivered the message on its own merits."
        : `The receiver reported a DMARC result of "${token}".`,
  };
}
