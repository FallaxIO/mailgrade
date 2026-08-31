/**
 * DKIM verification against messages signed here in the test, with a signer
 * written independently of the library's canonicalization: node:crypto signs,
 * WebCrypto verifies, and the bytes in between are produced twice.
 */

import { createHash, createSign, generateKeyPairSync, sign as edSign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { verifyDkim } from "../src/verify/dkim.ts";
import { staticResolver } from "../src/verify/resolver.ts";

const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const weakRsa = generateKeyPairSync("rsa", { modulusLength: 512 });
const ed25519 = generateKeyPairSync("ed25519");

const rsaTxt = `v=DKIM1; k=rsa; p=${rsa.publicKey.export({ type: "spki", format: "der" }).toString("base64")}`;
const weakTxt = `v=DKIM1; k=rsa; p=${weakRsa.publicKey.export({ type: "spki", format: "der" }).toString("base64")}`;
const edTxt = `v=DKIM1; k=ed25519; p=${ed25519.publicKey
  .export({ type: "spki", format: "der" })
  .subarray(-32)
  .toString("base64")}`;

/* An independent implementation of RFC 6376 canonicalization. */

function relaxBody(body: string): string {
  const lines = body.split("\r\n").map((l) => l.replace(/[ \t]+/g, " ").trimEnd());
  while (lines.length && lines.at(-1) === "") lines.pop();
  return lines.length ? `${lines.join("\r\n")}\r\n` : "";
}

function simpleBody(body: string): string {
  const out = body.replace(/(\r\n)+$/, "");
  return out === "" ? "\r\n" : `${out}\r\n`;
}

function relaxHeader(raw: string): string {
  const i = raw.indexOf(":");
  return `${raw.slice(0, i).trim().toLowerCase()}:${raw
    .slice(i + 1)
    .replace(/\r\n/g, "")
    .replace(/[ \t]+/g, " ")
    .trim()}`;
}

type SignOptions = {
  headers?: readonly [string, string][];
  body?: string;
  d?: string;
  s?: string;
  h?: string;
  c?: "relaxed/relaxed" | "simple/simple";
  algorithm?: "rsa-sha256" | "ed25519-sha256" | "rsa-sha1";
  extraTags?: string;
  /** Sign only the first N bytes of the canonical body, via l=. */
  length?: number;
  tamperBody?: string;
  tamperSubject?: string;
};

function signedMessage(options: SignOptions = {}): string {
  const {
    headers = [
      ["From", "Alice <alice@sender.example>"],
      ["To", "bob@example.com"],
      ["Subject", "An entirely ordinary message"],
    ],
    body = "Hello Bob,\r\n\r\nNothing unusual here.\r\n",
    d = "sender.example",
    s = "test",
    h = "from:to:subject",
    c = "relaxed/relaxed",
    algorithm = "rsa-sha256",
    extraTags = "",
  } = options;

  let canonBody = c === "relaxed/relaxed" ? relaxBody(body) : simpleBody(body);
  const lengthTag =
    options.length === undefined ? "" : ` l=${options.length};`;
  if (options.length !== undefined) canonBody = canonBody.slice(0, options.length);
  const bh = createHash("sha256").update(Buffer.from(canonBody, "latin1")).digest("base64");
  const value = `v=1; a=${algorithm}; c=${c}; d=${d}; s=${s};${extraTags}${lengthTag} h=${h}; bh=${bh}; b=`;
  const sigHeaderRaw = `DKIM-Signature: ${value}`;

  const rawHeaders = headers.map(([name, v]) => `${name}: ${v}`);
  const selected = h.split(":").map((name) => {
    const found = rawHeaders.find(
      (raw) => raw.toLowerCase().startsWith(`${name.toLowerCase()}:`),
    );
    return found as string;
  });

  const canon = (raw: string) => (c === "relaxed/relaxed" ? relaxHeader(raw) : raw);
  const data = Buffer.from(
    `${selected.map((raw) => `${canon(raw)}\r\n`).join("")}${canon(sigHeaderRaw)}`,
    "latin1",
  );

  let b: string;
  if (algorithm === "ed25519-sha256") {
    const digest = createHash("sha256").update(data).digest();
    b = edSign(null, digest, ed25519.privateKey).toString("base64");
  } else {
    const signer = createSign(algorithm === "rsa-sha1" ? "RSA-SHA1" : "RSA-SHA256");
    signer.update(data);
    b = signer.sign(rsa.privateKey).toString("base64");
  }

  const finalBody = options.tamperBody ?? body;
  const finalHeaders = rawHeaders.map((raw) =>
    options.tamperSubject && raw.startsWith("Subject:")
      ? `Subject: ${options.tamperSubject}`
      : raw,
  );
  return `${sigHeaderRaw}${b}\r\n${finalHeaders.join("\r\n")}\r\n\r\n${finalBody}`;
}

const keys = staticResolver({
  "test._domainkey.sender.example": { TXT: [rsaTxt] },
  "weak._domainkey.sender.example": { TXT: [weakTxt] },
  "ed._domainkey.sender.example": { TXT: [edTxt] },
  "gone._domainkey.sender.example": { TXT: [] },
  "revoked._domainkey.sender.example": { TXT: ["v=DKIM1; k=rsa; p="] },
  "down._domainkey.sender.example": "TEMPERROR",
  "testing._domainkey.sender.example": { TXT: [`${rsaTxt}; t=y`] },
});

const verify = (message: string) => verifyDkim(message, { resolver: keys });

describe("verification", () => {
  it("passes a relaxed/relaxed rsa-sha256 signature", async () => {
    const [r] = await verify(signedMessage());
    expect(r?.id).toBe("dkim-pass");
    expect(r?.result).toBe("pass");
    expect(r?.domain).toBe("sender.example");
    expect(r?.selector).toBe("test");
    expect(r?.keyBits).toBe(2048);
  });

  it("passes a simple/simple signature", async () => {
    const [r] = await verify(signedMessage({ c: "simple/simple" }));
    expect(r?.id).toBe("dkim-pass");
  });

  it("passes an ed25519-sha256 signature", async () => {
    const [r] = await verify(signedMessage({ algorithm: "ed25519-sha256", s: "ed" }));
    expect(r?.id).toBe("dkim-pass");
    expect(r?.keyBits).toBeNull();
  });

  it("survives a message whose line endings became bare LF", async () => {
    const [r] = await verify(signedMessage().replace(/\r\n/g, "\n"));
    expect(r?.id).toBe("dkim-pass");
  });

  it("returns one result per signature", async () => {
    const one = signedMessage();
    const another = signedMessage({ s: "gone" });
    const merged = `${another.split("\r\n")[0]}\r\n${one}`;
    const results = await verify(merged);
    expect(results.map((r) => r.id)).toEqual(["dkim-key-missing", "dkim-pass"]);
  });

  it("reports the key's testing flag", async () => {
    const [r] = await verify(signedMessage({ s: "testing" }));
    expect(r?.id).toBe("dkim-pass");
    expect(r?.testing).toBe(true);
  });
});

describe("tampering", () => {
  it("fails on a modified body, before any DNS", async () => {
    let lookups = 0;
    const counting = (name: string, type: "TXT") => {
      lookups++;
      return keys(name, type);
    };
    const [r] = await verifyDkim(
      signedMessage({ tamperBody: "Hello Bob,\r\n\r\nSend the money elsewhere.\r\n" }),
      { resolver: counting as never },
    );
    expect(r?.id).toBe("dkim-body-modified");
    expect(r?.result).toBe("fail");
    expect(lookups).toBe(0);
  });

  it("fails on a modified signed header", async () => {
    const [r] = await verify(signedMessage({ tamperSubject: "URGENT: wire change" }));
    expect(r?.id).toBe("dkim-signature-invalid");
    expect(r?.result).toBe("fail");
  });
});

describe("signature hygiene", () => {
  it("rejects a signature that does not cover From", async () => {
    const [r] = await verify(signedMessage({ h: "to:subject" }));
    expect(r?.id).toBe("dkim-from-unsigned");
  });

  it("rejects rsa-sha1 outright", async () => {
    const [r] = await verify(signedMessage({ algorithm: "rsa-sha1" }));
    expect(r?.id).toBe("dkim-weak-hash");
  });

  it("rejects a key below 1024 bits", async () => {
    const [r] = await verify(signedMessage({ s: "weak" }));
    expect(r?.id).toBe("dkim-weak-key");
    expect(r?.keyBits).toBe(512);
  });

  it("fails an expired signature", async () => {
    const [r] = await verify(signedMessage({ extraTags: " x=1000000000;" }));
    expect(r?.id).toBe("dkim-expired");
  });

  it("honours l= for a partially signed body", async () => {
    const message = signedMessage({ length: 5 });
    const grown = `${message}P.S. appended after signing\r\n`;
    const [r] = await verify(grown);
    expect(r?.id).toBe("dkim-pass");
  });

  it("permerrors when l= exceeds the body", async () => {
    const [r] = await verify(signedMessage({ extraTags: " l=100000;" }));
    expect(r?.id).toBe("dkim-length-overrun");
  });

  it("rejects an i= outside the signing domain", async () => {
    const [r] = await verify(signedMessage({ extraTags: " i=@other.example;" }));
    expect(r?.id).toBe("dkim-identity-mismatch");
  });
});

describe("key records", () => {
  it("permerrors on a missing key", async () => {
    const [r] = await verify(signedMessage({ s: "gone" }));
    expect(r?.id).toBe("dkim-key-missing");
    expect(r?.result).toBe("permerror");
  });

  it("permerrors on a revoked key", async () => {
    const [r] = await verify(signedMessage({ s: "revoked" }));
    expect(r?.id).toBe("dkim-key-revoked");
  });

  it("temperrors when the key lookup fails", async () => {
    const [r] = await verify(signedMessage({ s: "down" }));
    expect(r?.id).toBe("dkim-dns-error");
    expect(r?.result).toBe("temperror");
  });
});
