/**
 * The IP arithmetic SPF evaluation runs on: parse both families to bytes,
 * compare under a CIDR prefix, and render the reverse-lookup and macro forms.
 */

export type ParsedIp = {
  readonly version: 4 | 6;
  /** 4 bytes for IPv4, 16 for IPv6. */
  readonly bytes: Uint8Array;
};

function parseV4(raw: string): Uint8Array | null {
  const match = raw.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const octet = Number(match[i + 1]);
    if (octet > 255) return null;
    bytes[i] = octet;
  }
  return bytes;
}

function parseV6(raw: string): Uint8Array | null {
  let head = raw;
  let tail = "";
  const gap = raw.indexOf("::");
  if (gap !== -1) {
    if (raw.indexOf("::", gap + 1) !== -1) return null; // one gap at most
    head = raw.slice(0, gap);
    tail = raw.slice(gap + 2);
  }

  const groups = (part: string): number[] | null => {
    if (part === "") return [];
    const out: number[] = [];
    for (const piece of part.split(":")) {
      const v4 = parseV4(piece);
      if (v4) {
        // An embedded dotted quad ("::ffff:1.2.3.4") is two groups.
        out.push(((v4[0] ?? 0) << 8) | (v4[1] ?? 0), ((v4[2] ?? 0) << 8) | (v4[3] ?? 0));
        continue;
      }
      if (!/^[0-9a-f]{1,4}$/i.test(piece)) return null;
      out.push(parseInt(piece, 16));
    }
    return out;
  };

  const front = groups(head);
  const back = groups(tail);
  if (!front || !back) return null;
  const missing = 8 - front.length - back.length;
  if (gap === -1 ? missing !== 0 : missing < 1) return null;

  const words = [...front, ...Array.from({ length: missing }, () => 0), ...back];
  const bytes = new Uint8Array(16);
  words.forEach((w, i) => {
    bytes[i * 2] = w >> 8;
    bytes[i * 2 + 1] = w & 0xff;
  });
  return bytes;
}

/**
 * Parse either family. An IPv4-mapped IPv6 address ("::ffff:1.2.3.4") comes
 * back as the IPv4 it carries, which is what RFC 7208 says SPF must do with
 * one: the connection is an IPv4 connection wearing v6 framing.
 */
export function parseIp(raw: string): ParsedIp | null {
  const trimmed = raw.trim();
  const v4 = parseV4(trimmed);
  if (v4) return { version: 4, bytes: v4 };
  const v6 = parseV6(trimmed);
  if (!v6) return null;
  if (
    v6.slice(0, 10).every((b) => b === 0) &&
    v6[10] === 0xff &&
    v6[11] === 0xff
  ) {
    return { version: 4, bytes: v6.slice(12) };
  }
  return { version: 6, bytes: v6 };
}

/** True when `ip` falls inside `net`'s first `bits`. Families must match. */
export function inCidr(ip: Uint8Array, net: Uint8Array, bits: number): boolean {
  if (ip.length !== net.length) return false;
  const wholeBytes = bits >> 3;
  for (let i = 0; i < wholeBytes; i++) {
    if (ip[i] !== net[i]) return false;
  }
  const rest = bits & 7;
  if (rest === 0) return true;
  const mask = (0xff << (8 - rest)) & 0xff;
  return ((ip[wholeBytes] ?? 0) & mask) === ((net[wholeBytes] ?? 0) & mask);
}

/** The macro form of an address: dotted decimal, or dot-separated nibbles. */
export function macroIp(ip: ParsedIp): string {
  if (ip.version === 4) return Array.from(ip.bytes).join(".");
  return Array.from(ip.bytes)
    .flatMap((b) => [(b >> 4).toString(16), (b & 0xf).toString(16)])
    .join(".");
}

/** A human-readable rendering, for the %{c} macro in explanations. */
export function readableIp(ip: ParsedIp): string {
  if (ip.version === 4) return Array.from(ip.bytes).join(".");
  const words: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    words.push((((ip.bytes[i] ?? 0) << 8) | (ip.bytes[i + 1] ?? 0)).toString(16));
  }
  return words.join(":");
}

/** The name PTR records for this address live at. */
export function reverseName(ip: ParsedIp): string {
  if (ip.version === 4) {
    return `${Array.from(ip.bytes).toReversed().join(".")}.in-addr.arpa`;
  }
  return `${macroIp(ip).split(".").toReversed().join(".")}.ip6.arpa`;
}
