/**
 * DKIM signature verification, RFC 6376 and RFC 8463, on WebCrypto.
 *
 * Every runtime this library targets ships `crypto.subtle`, which is what
 * makes a verifier with zero dependencies possible: rsa-sha256 and
 * ed25519-sha256 verify, and rsa-sha1 is refused the way RFC 8301 orders.
 * The body hash is checked before any DNS is spent, so a tampered message
 * never costs a lookup.
 */

import type { Resolver } from "./resolver.ts";
import {
  canonicalBodyRelaxed,
  canonicalBodySimple,
  canonicalHeaderRelaxed,
  fromBinary,
  splitMessage,
  type RawHeaderField,
  type RawMessage,
} from "./message.ts";

export type DkimResultId =
  | "dkim-pass"
  | "dkim-body-modified"
  | "dkim-signature-invalid"
  | "dkim-malformed"
  | "dkim-from-unsigned"
  | "dkim-identity-mismatch"
  | "dkim-expired"
  | "dkim-length-overrun"
  | "dkim-weak-hash"
  | "dkim-weak-key"
  | "dkim-key-missing"
  | "dkim-key-revoked"
  | "dkim-key-invalid"
  | "dkim-dns-error"
  | "dkim-unsupported";

/** The Authentication-Results vocabulary, so results line up with receivers'. */
export type DkimResult = "pass" | "fail" | "neutral" | "permerror" | "temperror";

export type DkimVerification = {
  readonly id: DkimResultId;
  readonly result: DkimResult;
  /** The d= domain the signature claims. */
  readonly domain: string | null;
  readonly selector: string | null;
  readonly algorithm: string | null;
  readonly canonicalization: string;
  readonly signedHeaders: readonly string[];
  /** The key is published with t=y: the domain says it is still testing. */
  readonly testing: boolean;
  /** RSA modulus size; null for Ed25519 or before a key was read. */
  readonly keyBits: number | null;
  readonly detail: string;
};

export type DkimVerifyOptions = {
  readonly resolver: Resolver;
  /** The clock to judge x= expiry against; defaults to now. */
  readonly now?: Date;
};

/**
 * Verify every DKIM-Signature on a message, one result per signature, in
 * header order. No signatures verifies to an empty array, which for DMARC
 * purposes is the same thing as failure but is not reported as one.
 */
export async function verifyDkim(
  message: string | Uint8Array | RawMessage,
  options: DkimVerifyOptions,
): Promise<readonly DkimVerification[]> {
  const parsed =
    typeof message === "object" && "headers" in message
      ? message
      : splitMessage(message);

  const signatures = parsed.headers.filter((h) => h.lower === "dkim-signature");
  return Promise.all(
    signatures.map((field) => verifySignature(parsed, field, options)),
  );
}

/* -------------------------------------------------------------- pieces --- */

type Verdict = { id: DkimResultId; result: DkimResult; detail: string };

const VERDICT: Record<DkimResultId, { result: DkimResult; detail: string }> = {
  "dkim-pass": {
    result: "pass",
    detail: "The signature verified against the domain's published key.",
  },
  "dkim-body-modified": {
    result: "fail",
    detail:
      "The body hash in the signature does not match the body, so the message changed after it was signed.",
  },
  "dkim-signature-invalid": {
    result: "fail",
    detail:
      "The signature does not verify against the domain's published key: signed headers were altered, or the signature was never made with this key.",
  },
  "dkim-malformed": {
    result: "permerror",
    detail: "The DKIM-Signature header is missing required tags or unreadable.",
  },
  "dkim-from-unsigned": {
    result: "permerror",
    detail:
      "The signature does not cover the From header, which every DKIM signature must.",
  },
  "dkim-identity-mismatch": {
    result: "permerror",
    detail: "The i= identity is not within the d= signing domain.",
  },
  "dkim-expired": {
    result: "fail",
    detail: "The signature carries an x= expiry that has passed.",
  },
  "dkim-length-overrun": {
    result: "permerror",
    detail: "The l= tag claims more body than the message has.",
  },
  "dkim-weak-hash": {
    result: "permerror",
    detail:
      "The signature uses rsa-sha1, which RFC 8301 forbids verifiers to accept.",
  },
  "dkim-weak-key": {
    result: "permerror",
    detail:
      "The published RSA key is shorter than 1024 bits, which RFC 8301 forbids verifiers to accept.",
  },
  "dkim-key-missing": {
    result: "permerror",
    detail: "No key record is published at the selector this signature names.",
  },
  "dkim-key-revoked": {
    result: "permerror",
    detail:
      "The key record is published with an empty p=, which is a revocation.",
  },
  "dkim-key-invalid": {
    result: "permerror",
    detail: "The published key record cannot be read as a key.",
  },
  "dkim-dns-error": {
    result: "temperror",
    detail: "The key lookup failed, so verification could not be attempted.",
  },
  "dkim-unsupported": {
    result: "neutral",
    detail:
      "This runtime's WebCrypto cannot verify the signature's algorithm.",
  },
};

function verdict(id: DkimResultId, detail?: string): Verdict {
  const base = VERDICT[id];
  return { id, result: base.result, detail: detail ?? base.detail };
}

/** tag=value pairs; null on a duplicate tag, which voids the signature. */
export function parseTagList(value: string): Map<string, string> | null {
  const tags = new Map<string, string>();
  for (const part of value.split(";")) {
    if (part.trim() === "") continue;
    const match = part.match(/^\s*([a-z][a-z0-9_]*)\s*=\s*([\s\S]*?)\s*$/i);
    if (!match) return null;
    const key = (match[1] as string).toLowerCase();
    if (tags.has(key)) return null;
    tags.set(key, match[2] as string);
  }
  return tags;
}

function decodeBase64(value: string): Uint8Array<ArrayBuffer> | null {
  try {
    return fromBinary(atob(value.replace(/\s+/g, "")));
  } catch {
    return null;
  }
}

/**
 * The signed header fields, selected the way RFC 6376 section 5.4.2 says:
 * for each name in h=, the lowest not-yet-taken instance. A name listed more
 * times than it appears contributes nothing, which is oversigning.
 */
export function selectHeaders(
  headers: readonly RawHeaderField[],
  names: readonly string[],
): RawHeaderField[] {
  const cursor = new Map<string, number>();
  const out: RawHeaderField[] = [];
  for (const name of names) {
    const lower = name.toLowerCase();
    const start = cursor.get(lower) ?? headers.length - 1;
    let i = start;
    while (i >= 0 && headers[i]?.lower !== lower) i--;
    cursor.set(lower, i - 1);
    const field = headers[i];
    if (i >= 0 && field) out.push(field);
  }
  return out;
}

async function verifySignature(
  message: RawMessage,
  field: RawHeaderField,
  options: DkimVerifyOptions,
): Promise<DkimVerification> {
  const tags = parseTagList(field.value);
  const domain = tags?.get("d")?.toLowerCase().replace(/\.$/, "") ?? null;
  const selector = tags?.get("s")?.toLowerCase().replace(/\.$/, "") ?? null;
  const algorithm = tags?.get("a")?.toLowerCase() ?? null;
  const canonicalization = tags?.get("c")?.toLowerCase() ?? "simple/simple";
  const signedHeaders =
    tags
      ?.get("h")
      ?.split(":")
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean) ?? [];

  const finish = (v: Verdict, extra?: Partial<DkimVerification>): DkimVerification => ({
    id: v.id,
    result: v.result,
    domain,
    selector,
    algorithm,
    canonicalization,
    signedHeaders,
    testing: false,
    keyBits: null,
    detail: v.detail,
    ...extra,
  });

  /* ------------------------------------------------ the signature itself */

  if (!tags) return finish(verdict("dkim-malformed"));
  for (const required of ["v", "a", "b", "bh", "d", "h", "s"]) {
    if (!tags.get(required)) {
      return finish(
        verdict("dkim-malformed", `The required ${required}= tag is missing.`),
      );
    }
  }
  if (tags.get("v") !== "1") return finish(verdict("dkim-malformed"));
  if (!signedHeaders.includes("from")) {
    return finish(verdict("dkim-from-unsigned"));
  }

  if (algorithm === "rsa-sha1") return finish(verdict("dkim-weak-hash"));
  if (algorithm !== "rsa-sha256" && algorithm !== "ed25519-sha256") {
    return finish(verdict("dkim-unsupported"));
  }

  const identity = tags.get("i");
  if (identity && domain) {
    const idDomain = identity.toLowerCase().split("@").pop() ?? "";
    if (idDomain !== domain && !idDomain.endsWith(`.${domain}`)) {
      return finish(verdict("dkim-identity-mismatch"));
    }
  }

  const expiry = tags.get("x");
  if (expiry !== undefined) {
    const at = Number(expiry);
    const now = (options.now ?? new Date()).getTime() / 1000;
    if (!Number.isFinite(at) || at < now) return finish(verdict("dkim-expired"));
  }

  const [headerCanon, bodyCanon = "simple"] = canonicalization.split("/");
  if (
    (headerCanon !== "simple" && headerCanon !== "relaxed") ||
    (bodyCanon !== "simple" && bodyCanon !== "relaxed")
  ) {
    return finish(verdict("dkim-malformed"));
  }

  const signature = decodeBase64(tags.get("b") as string);
  const bodyHash = decodeBase64(tags.get("bh") as string);
  if (!signature || !bodyHash) return finish(verdict("dkim-malformed"));

  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return finish(verdict("dkim-unsupported"));

  /* ------------------------------------------------------- the body hash */

  let body =
    bodyCanon === "simple"
      ? canonicalBodySimple(message.body)
      : canonicalBodyRelaxed(message.body);

  const lengthTag = tags.get("l");
  if (lengthTag !== undefined) {
    const l = Number(lengthTag);
    if (!Number.isInteger(l) || l < 0) return finish(verdict("dkim-malformed"));
    if (l > body.length) return finish(verdict("dkim-length-overrun"));
    body = body.slice(0, l);
  }

  const digest = new Uint8Array(
    await subtle.digest("SHA-256", fromBinary(body)),
  );
  if (!bytesEqual(digest, bodyHash)) {
    return finish(verdict("dkim-body-modified"));
  }

  /* ------------------------------------------------------------- the key */

  let keyRecords: readonly string[];
  try {
    keyRecords = await options.resolver(`${selector}._domainkey.${domain}`, "TXT");
  } catch {
    return finish(verdict("dkim-dns-error"));
  }
  if (keyRecords.length === 0) return finish(verdict("dkim-key-missing"));

  const key = readKeyRecord(keyRecords, algorithm);
  if (key.error) return finish(verdict(key.error));

  /* ----------------------------------------------------- the header hash */

  const pieces = selectHeaders(message.headers, signedHeaders).map((h) =>
    headerCanon === "simple" ? h.raw : canonicalHeaderRelaxed(h.raw),
  );
  // The DKIM-Signature header itself, b= value emptied, no trailing CRLF.
  const unsigned = field.raw.replace(/([;\s]b[ \t\r\n]*=)[^;]*/, "$1");
  pieces.push(
    headerCanon === "simple" ? unsigned : canonicalHeaderRelaxed(unsigned),
  );
  const data = fromBinary(`${pieces.slice(0, -1).join("\r\n")}${pieces.length > 1 ? "\r\n" : ""}${pieces[pieces.length - 1]}`);

  try {
    let valid: boolean;
    let keyBits: number | null = null;
    if (algorithm === "rsa-sha256") {
      const publicKey = await subtle.importKey(
        "spki",
        key.bytes,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"],
      );
      keyBits =
        (publicKey.algorithm as { modulusLength?: number }).modulusLength ??
        null;
      if (keyBits !== null && keyBits < 1024) {
        return finish(verdict("dkim-weak-key"), { keyBits, testing: key.testing });
      }
      valid = await subtle.verify(
        "RSASSA-PKCS1-v1_5",
        publicKey,
        signature,
        data,
      );
    } else {
      // Ed25519 signs the SHA-256 digest of the header hash input (RFC 8463).
      const publicKey = await subtle.importKey(
        "raw",
        key.bytes,
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      const headerDigest = await subtle.digest("SHA-256", data);
      valid = await subtle.verify(
        "Ed25519",
        publicKey,
        signature,
        headerDigest,
      );
    }
    return finish(
      verdict(valid ? "dkim-pass" : "dkim-signature-invalid"),
      { keyBits, testing: key.testing },
    );
  } catch {
    // An import that throws is either a mangled key or a runtime without the
    // algorithm; Ed25519 support is the one that varies.
    return finish(
      verdict(algorithm === "ed25519-sha256" ? "dkim-unsupported" : "dkim-key-invalid"),
      { testing: key.testing },
    );
  }
}

type KeyRecord =
  | { error: DkimResultId; bytes?: undefined; testing: boolean }
  | { error?: undefined; bytes: Uint8Array<ArrayBuffer>; testing: boolean };

function readKeyRecord(
  records: readonly string[],
  algorithm: "rsa-sha256" | "ed25519-sha256",
): KeyRecord {
  // More than one TXT record at the selector is undefined behaviour; the
  // first that parses as a key record is used, which is what receivers do.
  let sawRevoked = false;
  for (const record of records) {
    const tags = parseTagList(record);
    if (!tags) continue;
    const version = tags.get("v");
    if (version !== undefined && version.toUpperCase() !== "DKIM1") continue;
    const p = tags.get("p");
    if (p === undefined) continue;
    const flags = (tags.get("t") ?? "").toLowerCase().split(":");
    const testing = flags.includes("y");
    if (p.replace(/\s+/g, "") === "") {
      sawRevoked = true;
      continue;
    }
    const keyType = (tags.get("k") ?? "rsa").toLowerCase();
    const expected = algorithm === "rsa-sha256" ? "rsa" : "ed25519";
    if (keyType !== expected) return { error: "dkim-key-invalid", testing };
    const hashes = tags.get("h");
    if (
      hashes !== undefined &&
      !hashes.toLowerCase().split(":").map((h) => h.trim()).includes("sha256")
    ) {
      return { error: "dkim-key-invalid", testing };
    }
    const bytes = decodeBase64(p);
    if (!bytes) return { error: "dkim-key-invalid", testing };
    return { bytes, testing };
  }
  return { error: sawRevoked ? "dkim-key-revoked" : "dkim-key-invalid", testing: false };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
