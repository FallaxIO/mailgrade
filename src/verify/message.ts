/**
 * A raw RFC 5322 message, byte-exact, for verification.
 *
 * DKIM is a signature over bytes, so this parser works on a binary string
 * (one character per byte) rather than decoded text: a UTF-8 body has to hash
 * as the bytes that were signed, not as the code points they decode to.
 * Callers pass a string (encoded as UTF-8) or their own Uint8Array.
 */

export type RawHeaderField = {
  readonly name: string;
  readonly lower: string;
  /** The entire original field, folding intact, without the trailing CRLF. */
  readonly raw: string;
  /** The value after the colon, unfolded, trimmed. */
  readonly value: string;
};

export type RawMessage = {
  readonly headers: readonly RawHeaderField[];
  /** The body as a binary string, CRLF line endings. */
  readonly body: string;
};

/** One character per byte, so hashing sees exactly what was signed. */
export function toBinary(input: string | Uint8Array): string {
  const bytes =
    typeof input === "string" ? new TextEncoder().encode(input) : input;
  let out = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return out;
}

export function fromBinary(binary: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i) & 0xff;
  }
  return bytes;
}

/**
 * Split a message into header fields and body.
 *
 * Line endings are normalised to CRLF first: DKIM is defined over CRLF, and a
 * message that has been through a file or a clipboard usually has bare LF.
 */
export function splitMessage(input: string | Uint8Array): RawMessage {
  const text = toBinary(input).replace(/\r\n|\r|\n/g, "\r\n");
  const divide = text.indexOf("\r\n\r\n");
  const headerBlock = divide === -1 ? text : text.slice(0, divide);
  const body = divide === -1 ? "" : text.slice(divide + 4);

  const headers: RawHeaderField[] = [];
  let current: string[] = [];
  const flush = () => {
    if (current.length === 0) return;
    const raw = current.join("\r\n");
    const colon = raw.indexOf(":");
    if (colon > 0) {
      const name = raw.slice(0, colon).trim();
      headers.push({
        name,
        lower: name.toLowerCase(),
        raw,
        value: raw
          .slice(colon + 1)
          .replace(/\r\n/g, "")
          .trim(),
      });
    }
    current = [];
  };

  for (const line of headerBlock.split("\r\n")) {
    if (/^[ \t]/.test(line) && current.length > 0) {
      current.push(line);
    } else {
      flush();
      current = [line];
    }
  }
  flush();

  return { headers, body };
}

/* --------------------------------------------------- canonicalization --- */

/** Simple body: trailing empty lines collapse to one CRLF; empty means CRLF. */
export function canonicalBodySimple(body: string): string {
  const trimmed = body.replace(/(\r\n)+$/, "");
  return trimmed === "" ? "\r\n" : `${trimmed}\r\n`;
}

/**
 * Relaxed body: whitespace runs become one space, line-end whitespace goes,
 * trailing empty lines go, and only an entirely empty body stays empty.
 */
export function canonicalBodyRelaxed(body: string): string {
  const lines = body
    .split("\r\n")
    .map((line) => line.replace(/[ \t]+/g, " ").replace(/ $/, ""));
  while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return lines.length === 0 ? "" : `${lines.join("\r\n")}\r\n`;
}

/** Relaxed header: lower-cased name, unfolded value, single spaces, no CRLF. */
export function canonicalHeaderRelaxed(raw: string): string {
  const colon = raw.indexOf(":");
  const name = raw.slice(0, colon).trim().toLowerCase();
  const value = raw
    .slice(colon + 1)
    .replace(/\r\n/g, "")
    .replace(/[ \t]+/g, " ")
    .trim();
  return `${name}:${value}`;
}
