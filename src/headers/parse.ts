/**
 * Turning a pasted RFC 5322 header block into things worth grading.
 *
 * No I/O anywhere, which is a design constraint rather than a convenience.
 * Headers carry the recipient's address, their colleagues' addresses, internal
 * hostnames and internal IPs, and anything that asks a stranger to paste all
 * of that has no business shipping it to a server.
 */

export type HeaderField = {
  readonly name: string;
  readonly lower: string;
  value: string;
};

export type Address = {
  readonly raw: string;
  readonly display: string | null;
  readonly address: string | null;
  readonly domain: string | null;
};

/**
 * Split a pasted message into unfolded header fields.
 *
 * Continuation lines (RFC 5322 folding) are joined onto the field above, and
 * everything from the first blank line on is treated as the body: people paste
 * the whole "Show original" output, and a body line reading "Subject: Re: your
 * invoice" would otherwise be read as a second Subject header.
 */
export function parseHeaders(raw: string): HeaderField[] {
  const text = raw.replace(/\r\n?/g, "\n").replace(/^\n+/, "");
  const end = text.indexOf("\n\n");
  const block = end === -1 ? text : text.slice(0, end);

  const fields: HeaderField[] = [];
  for (const line of block.split("\n")) {
    if (/^[ \t]/.test(line)) {
      const last = fields[fields.length - 1];
      if (last) last.value = `${last.value} ${line.trim()}`.trim();
      continue;
    }
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    const name = line.slice(0, colon).trim();
    // RFC 5322 printable US-ASCII except colon. Keeps mbox "From " separators
    // and stray prose out of the field list.
    if (!/^[!-9;-~]+$/.test(name)) continue;
    fields.push({
      name,
      lower: name.toLowerCase(),
      value: line.slice(colon + 1).trim(),
    });
  }
  return fields;
}

export function headerValues(
  fields: readonly HeaderField[],
  name: string,
): string[] {
  return fields.filter((f) => f.lower === name).map((f) => f.value);
}

export function headerValue(
  fields: readonly HeaderField[],
  name: string,
): string | null {
  return fields.find((f) => f.lower === name)?.value ?? null;
}

/* ----------------------------------------------------- encoded words --- */

function decodeBase64(payload: string, charset: string): string {
  const binary = atob(payload.replace(/\s+/g, ""));
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  try {
    return new TextDecoder(charset).decode(bytes);
  } catch {
    return new TextDecoder().decode(bytes);
  }
}

function decodeQuoted(payload: string, charset: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < payload.length; i++) {
    const c = payload.charAt(i);
    if (c === "_") {
      bytes.push(0x20);
    } else if (c === "=" && /^[0-9a-f]{2}$/i.test(payload.slice(i + 1, i + 3))) {
      bytes.push(parseInt(payload.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      bytes.push(c.charCodeAt(0));
    }
  }
  const array = Uint8Array.from(bytes);
  try {
    return new TextDecoder(charset).decode(array);
  } catch {
    return new TextDecoder().decode(array);
  }
}

/**
 * Decode RFC 2047 encoded words, because a display name is exactly where an
 * attacker hides one: `=?utf-8?B?...?=` renders as the bank's name in every
 * mail client while the header looks like harmless base64 to a reader.
 */
export function decodeEncodedWords(value: string): string {
  return value.replace(
    /=\?([^?]+)\?([BQbq])\?([^?]*)\?=/g,
    (match: string, charset: string, encoding: string, payload: string) => {
      try {
        return encoding.toUpperCase() === "B"
          ? decodeBase64(payload, charset.toLowerCase())
          : decodeQuoted(payload, charset.toLowerCase());
      } catch {
        return match;
      }
    },
  );
}

/* ---------------------------------------------------------- addresses --- */

/** `Display Name <user@host>`, `<user@host>` or a bare address. */
export function parseAddress(raw: string | null): Address | null {
  if (!raw) return null;
  const decoded = decodeEncodedWords(raw).trim();
  if (!decoded) return null;

  const angled = decoded.match(/<([^<>]*)>\s*$/);
  const addressPart = (angled ? (angled[1] ?? "") : decoded).trim();
  let display = angled ? decoded.slice(0, angled.index ?? 0).trim() : "";
  if (
    display.length > 1 &&
    ((display.startsWith('"') && display.endsWith('"')) ||
      (display.startsWith("'") && display.endsWith("'")))
  ) {
    display = display.slice(1, -1).trim();
  }

  const address = /^[^\s@]+@[^\s@]+$/.test(addressPart)
    ? addressPart.toLowerCase()
    : null;
  const domain = address ? (address.split("@").pop() ?? null) : null;

  return {
    raw: decoded,
    display: display || null,
    address,
    domain: domain || null,
  };
}

/* --------------------------------------- Authentication-Results -------- */

/**
 * Strip CFWS comments, which is what makes the rest of the parse safe: a
 * receiver's explanatory `(p=REJECT sp=REJECT dis=NONE)` sits right beside the
 * real tags, and a naive scan for `p=` reads the comment as policy.
 */
export function stripComments(value: string): string {
  let out = "";
  let depth = 0;
  let quoted = false;
  for (const c of value) {
    if (quoted) {
      if (c === '"') quoted = false;
      if (depth === 0) out += c;
      continue;
    }
    if (c === '"' && depth === 0) {
      quoted = true;
      out += c;
      continue;
    }
    if (c === "(") {
      depth++;
      continue;
    }
    if (c === ")") {
      if (depth > 0) depth--;
      else out += c;
      continue;
    }
    if (depth === 0) out += c;
  }
  return out.replace(/\s+/g, " ").trim();
}

export type MethodResult = {
  readonly result: string;
  readonly properties: Readonly<Record<string, string>>;
};

/**
 * The method results in one Authentication-Results header, keyed by method.
 *
 * Only the first result per method is kept: a receiver that reports `dkim=fail`
 * then `dkim=pass` for a second signature is reported by both, and the leading
 * one is the one it acted on.
 */
export function parseAuthResults(value: string): Map<string, MethodResult> {
  const found = new Map<string, MethodResult>();
  for (const chunk of stripComments(value).split(";")) {
    const head = chunk.trim().match(/^([a-z][a-z0-9-]*)\s*=\s*([a-z]+)/i);
    const method = head?.[1]?.toLowerCase();
    const result = head?.[2]?.toLowerCase();
    if (!method || !result) continue;
    const properties: Record<string, string> = {};
    for (const match of chunk.matchAll(
      /([a-z]+\.[a-z-]+)\s*=\s*("[^"]*"|\S+)/gi,
    )) {
      const key = match[1];
      const raw = match[2];
      if (key && raw) properties[key.toLowerCase()] = raw.replace(/^"|"$/g, "");
    }
    if (!found.has(method)) found.set(method, { result, properties });
  }
  return found;
}

/** The domain in an identifier that is an address (`x@y.com`) or a bare domain. */
export function identifierDomain(value: string | undefined): string | null {
  if (!value) return null;
  const cleaned = value.replace(/^@/, "").trim().toLowerCase();
  const domain = cleaned.includes("@")
    ? (cleaned.split("@").pop() ?? "")
    : cleaned;
  return domain || null;
}

/* -------------------------------------------------------------- route --- */

export type Hop = {
  /** 1 is the hop nearest the origin, so the list reads in travel order. */
  readonly index: number;
  readonly from: string | null;
  readonly ip: string | null;
  readonly by: string | null;
  readonly protocol: string | null;
  readonly date: string | null;
  readonly privateIp: boolean;
};

const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

export function isPrivateIp(ip: string): boolean {
  const v4 = ip.match(IPV4)?.[0];
  if (v4) {
    const octets = v4.split(".").map(Number);
    const a = octets[0] ?? -1;
    const b = octets[1] ?? -1;
    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      a === 0
    );
  }
  const v6 = ip.toLowerCase();
  return v6 === "::1" || /^f[cd][0-9a-f]{2}:/.test(v6) || v6.startsWith("fe80:");
}

export function parseReceived(value: string, index: number): Hop {
  const bracketed = value.match(/\[(?:ipv6:)?([0-9a-f:.]+)\]/i);
  const ip = bracketed?.[1] ?? value.match(IPV4)?.[0] ?? null;
  const semicolon = value.lastIndexOf(";");
  const date = semicolon === -1 ? null : value.slice(semicolon + 1).trim();

  return {
    index,
    from: value.match(/\bfrom\s+([^\s;()]+)/i)?.[1] ?? null,
    ip,
    by: value.match(/\bby\s+([^\s;()]+)/i)?.[1] ?? null,
    protocol: value.match(/\bwith\s+([A-Za-z0-9]+)/i)?.[1] ?? null,
    date: date || null,
    privateIp: ip !== null && isPrivateIp(ip),
  };
}
