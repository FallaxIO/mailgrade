/**
 * SPF evaluation, RFC 7208: given the connecting IP and the envelope sender,
 * the verdict the domain's published policy yields.
 *
 * This is check_host() with the resolver injected. All of the limits receivers
 * enforce are enforced here, because a record that works only until a receiver
 * counts its lookups is a record that fails in production: ten DNS-costing
 * terms, two void lookups, ten MX hosts, ten PTR names.
 */

import { macroIp, parseIp, readableIp, reverseName, inCidr, type ParsedIp } from "./ip.ts";
import { defaultResolver } from "../doh-resolver.ts";
import type { Resolver } from "./resolver.ts";

export type SpfResult =
  | "none"
  | "neutral"
  | "pass"
  | "fail"
  | "softfail"
  | "temperror"
  | "permerror";

export type SpfVerification = {
  readonly result: SpfResult;
  /** The domain whose record decided it, after any redirects. */
  readonly domain: string;
  readonly record: string | null;
  /** The mechanism that matched, qualifier included, e.g. "-all". */
  readonly mechanism: string | null;
  /** DNS-costing terms spent, out of the limit of 10. */
  readonly lookups: number;
  /** The domain's exp= explanation, only ever present on a fail. */
  readonly explanation: string | null;
};

export type SpfParams = {
  /** The IP the SMTP client connected from. */
  readonly ip: string;
  /** MAIL FROM address; a bare domain is accepted and gets `postmaster@`. */
  readonly sender: string;
  /** HELO/EHLO host name, used by the %{h} macro. */
  readonly helo?: string;
  /** Receiving host name, used by the %{r} macro. */
  readonly receiver?: string;
  /** Where DNS comes from. Defaults to DNS over HTTPS against Cloudflare. */
  readonly resolver?: Resolver;
};

const LOOKUP_LIMIT = 10;
const VOID_LIMIT = 2;
const MX_LIMIT = 10;
const PTR_LIMIT = 10;

class Interrupt extends Error {
  readonly outcome: "permerror" | "temperror";

  constructor(outcome: "permerror" | "temperror") {
    super(outcome);
    this.outcome = outcome;
  }
}

type Context = {
  readonly resolver: Resolver;
  readonly ip: ParsedIp;
  readonly sender: string;
  readonly local: string;
  readonly senderDomain: string;
  readonly helo: string;
  readonly receiver: string;
  lookups: number;
  voids: number;
};

type Evaluation = {
  readonly result: SpfResult;
  readonly domain: string;
  readonly record: string | null;
  readonly mechanism: string | null;
  readonly expDomain: string | null;
};

/** Evaluate a domain's SPF policy against a connecting IP. */
export async function verifySpf(params: SpfParams): Promise<SpfVerification> {
  const ip = parseIp(params.ip);
  const rawSender = params.sender.trim().toLowerCase();
  const at = rawSender.lastIndexOf("@");
  const local = at > 0 ? rawSender.slice(0, at) : "postmaster";
  const senderDomain = at === -1 ? rawSender : rawSender.slice(at + 1);

  const blank = (result: SpfResult): SpfVerification => ({
    result,
    domain: senderDomain,
    record: null,
    mechanism: null,
    lookups: 0,
    explanation: null,
  });

  if (!ip) return blank("permerror");
  if (!senderDomain || !senderDomain.includes(".")) return blank("none");

  const ctx: Context = {
    resolver: params.resolver ?? defaultResolver(),
    ip,
    sender: `${local}@${senderDomain}`,
    local,
    senderDomain,
    helo: params.helo?.trim().toLowerCase() || "unknown",
    receiver: params.receiver?.trim().toLowerCase() || "unknown",
    lookups: 0,
    voids: 0,
  };

  let evaluation: Evaluation;
  try {
    evaluation = await evaluate(ctx, senderDomain);
  } catch (error) {
    const result = error instanceof Interrupt ? error.outcome : "temperror";
    return { ...blank(result), lookups: ctx.lookups };
  }

  return {
    result: evaluation.result,
    domain: evaluation.domain,
    record: evaluation.record,
    mechanism: evaluation.mechanism,
    lookups: ctx.lookups,
    explanation:
      evaluation.result === "fail" && evaluation.expDomain
        ? await explanation(ctx, evaluation.domain, evaluation.expDomain)
        : null,
  };
}

/* ------------------------------------------------------------- engine --- */

function spend(ctx: Context): void {
  if (++ctx.lookups > LOOKUP_LIMIT) throw new Interrupt("permerror");
}

async function dns(
  ctx: Context,
  name: string,
  type: "TXT" | "A" | "AAAA" | "MX" | "PTR",
): Promise<readonly string[]> {
  let records: readonly string[];
  try {
    records = await ctx.resolver(name, type);
  } catch {
    throw new Interrupt("temperror");
  }
  return records;
}

/** Empty answers to mechanism lookups are limited, to cap wasted queries. */
function countVoid(ctx: Context, records: readonly string[]): void {
  if (records.length === 0 && ++ctx.voids > VOID_LIMIT) {
    throw new Interrupt("permerror");
  }
}

function isSpfVersion(txt: string): boolean {
  return /^v=spf1(?:\s|$)/i.test(txt);
}

async function evaluate(ctx: Context, domain: string): Promise<Evaluation> {
  const found = (await dns(ctx, domain, "TXT")).filter(isSpfVersion);
  const none: Evaluation = {
    result: "none",
    domain,
    record: null,
    mechanism: null,
    expDomain: null,
  };
  if (found.length === 0) return none;
  if (found.length > 1) throw new Interrupt("permerror");

  const record = found[0] as string;
  const terms = record.split(/\s+/).slice(1).filter(Boolean);

  let redirect: string | null = null;
  let expDomain: string | null = null;
  const done = (result: SpfResult, mechanism: string): Evaluation => ({
    result,
    domain,
    record,
    mechanism,
    expDomain,
  });

  // Modifiers apply wherever they sit, so read them before any mechanism can
  // match: a record may put exp= after the -all it explains.
  for (const term of terms) {
    const modifier = term.match(/^([a-z][a-z0-9_.-]*)=(.*)$/i);
    if (!modifier) continue;
    const name = (modifier[1] as string).toLowerCase();
    const value = modifier[2] as string;
    if (name === "redirect") {
      if (redirect !== null) throw new Interrupt("permerror");
      redirect = value;
    } else if (name === "exp") {
      if (expDomain !== null) throw new Interrupt("permerror");
      expDomain = value;
    }
    // Unknown modifiers are explicitly allowed and ignored.
  }

  for (const term of terms) {
    if (/^[a-z][a-z0-9_.-]*=/i.test(term)) continue; // modifier, handled above

    const parsed = term.match(/^([+\-~?]?)([a-z][a-z0-9]*)([:/]\S*)?$/i);
    if (!parsed) throw new Interrupt("permerror");
    const qualifier = (parsed[1] || "+") as "+" | "-" | "~" | "?";
    const mechanism = (parsed[2] as string).toLowerCase();
    const argument = parsed[3] ?? "";

    // Mechanisms are strictly ordered: the first match ends evaluation.
    // oxlint-disable-next-line no-await-in-loop
    const matched = await matches(ctx, domain, mechanism, argument);
    if (matched) {
      const result: SpfResult =
        qualifier === "+"
          ? "pass"
          : qualifier === "-"
            ? "fail"
            : qualifier === "~"
              ? "softfail"
              : "neutral";
      return done(result, `${qualifier}${mechanism}${argument}`);
    }
  }

  if (redirect !== null) {
    spend(ctx);
    const target = await targetName(ctx, domain, redirect, true);
    const redirected = await evaluate(ctx, target);
    // A redirect target with no record is a broken policy, not a missing one.
    if (redirected.result === "none") throw new Interrupt("permerror");
    return redirected;
  }

  return { ...none, record, result: "neutral", expDomain };
}

/* --------------------------------------------------------- mechanisms --- */

type Argument = {
  readonly domainSpec: string | null;
  readonly cidr4: number;
  readonly cidr6: number;
};

/**
 * CIDR suffixes are peeled off the end so a macro delimiter list containing a
 * slash ("%{d1r/-}") never reads as one.
 */
function parseArgument(argument: string): Argument {
  let rest = argument;
  let cidr4 = 32;
  let cidr6 = 128;
  const dual = rest.match(/\/\/(\d+)$/);
  if (dual) {
    cidr6 = Number(dual[1]);
    rest = rest.slice(0, dual.index);
  }
  const single = rest.match(/(?<!\/)\/(\d+)$/);
  if (single) {
    cidr4 = Number(single[1]);
    rest = rest.slice(0, single.index);
  }
  if (cidr4 > 32 || cidr6 > 128) throw new Interrupt("permerror");
  if (rest === "") return { domainSpec: null, cidr4, cidr6 };
  if (!rest.startsWith(":") || rest.length < 2) throw new Interrupt("permerror");
  return { domainSpec: rest.slice(1), cidr4, cidr6 };
}

function hostCidr(ctx: Context, arg: Argument): number {
  return ctx.ip.version === 4 ? arg.cidr4 : arg.cidr6;
}

function addressMatches(
  ctx: Context,
  addresses: readonly string[],
  bits: number,
): boolean {
  return addresses.some((raw) => {
    const parsed = parseIp(raw);
    return (
      parsed !== null &&
      parsed.version === ctx.ip.version &&
      inCidr(ctx.ip.bytes, parsed.bytes, bits)
    );
  });
}

async function forwardAddresses(
  ctx: Context,
  host: string,
): Promise<readonly string[]> {
  return dns(ctx, host, ctx.ip.version === 4 ? "A" : "AAAA");
}

async function matches(
  ctx: Context,
  domain: string,
  mechanism: string,
  argument: string,
): Promise<boolean> {
  switch (mechanism) {
    case "all":
      if (argument !== "") throw new Interrupt("permerror");
      return true;

    case "ip4":
    case "ip6": {
      const match = argument.match(/^:([^/\s]+)(?:\/(\d+))?$/);
      if (!match) throw new Interrupt("permerror");
      const net = parseIp(match[1] as string);
      const version = mechanism === "ip4" ? 4 : 6;
      const width = version === 4 ? 32 : 128;
      const bits = match[2] === undefined ? width : Number(match[2]);
      if (!net || net.version !== version || bits > width) {
        throw new Interrupt("permerror");
      }
      return ctx.ip.version === version && inCidr(ctx.ip.bytes, net.bytes, bits);
    }

    case "a": {
      const arg = parseArgument(argument);
      spend(ctx);
      const target = arg.domainSpec
        ? await targetName(ctx, domain, arg.domainSpec, false)
        : domain;
      const addresses = await forwardAddresses(ctx, target);
      countVoid(ctx, addresses);
      return addressMatches(ctx, addresses, hostCidr(ctx, arg));
    }

    case "mx": {
      const arg = parseArgument(argument);
      spend(ctx);
      const target = arg.domainSpec
        ? await targetName(ctx, domain, arg.domainSpec, false)
        : domain;
      const hosts = await dns(ctx, target, "MX");
      countVoid(ctx, hosts);
      if (hosts.length > MX_LIMIT) throw new Interrupt("permerror");
      for (const host of hosts) {
        // These A lookups are limited by MX_LIMIT above rather than counted.
        // oxlint-disable-next-line no-await-in-loop
        const addresses = await forwardAddresses(ctx, host);
        if (addressMatches(ctx, addresses, hostCidr(ctx, arg))) return true;
      }
      return false;
    }

    case "ptr": {
      const arg = parseArgument(argument);
      spend(ctx);
      const target = arg.domainSpec
        ? await targetName(ctx, domain, arg.domainSpec, false)
        : domain;
      const names = await dns(ctx, reverseName(ctx.ip), "PTR");
      countVoid(ctx, names);
      for (const name of names.slice(0, PTR_LIMIT)) {
        const host = name.toLowerCase().replace(/\.$/, "");
        if (host !== target && !host.endsWith(`.${target}`)) continue;
        let confirmed: readonly string[];
        try {
          // oxlint-disable-next-line no-await-in-loop
          confirmed = await forwardAddresses(ctx, host);
        } catch {
          continue; // an unconfirmable name is skipped, not fatal
        }
        if (addressMatches(ctx, confirmed, ctx.ip.version === 4 ? 32 : 128)) {
          return true;
        }
      }
      return false;
    }

    case "exists": {
      const spec = argument.match(/^:(\S+)$/)?.[1];
      if (!spec) throw new Interrupt("permerror");
      spend(ctx);
      const target = await targetName(ctx, domain, spec, false);
      // Always an A lookup, even for an IPv6 connection; the RFC is explicit.
      const found = await dns(ctx, target, "A");
      countVoid(ctx, found);
      return found.length > 0;
    }

    case "include": {
      const spec = argument.match(/^:(\S+)$/)?.[1];
      if (!spec) throw new Interrupt("permerror");
      spend(ctx);
      const target = await targetName(ctx, domain, spec, false);
      const included = await evaluate(ctx, target);
      if (included.result === "pass") return true;
      if (
        included.result === "fail" ||
        included.result === "softfail" ||
        included.result === "neutral"
      ) {
        return false;
      }
      // none or an error state: the record points at a broken policy.
      throw new Interrupt(
        included.result === "temperror" ? "temperror" : "permerror",
      );
    }

    default:
      throw new Interrupt("permerror");
  }
}

/* -------------------------------------------------------------- macros --- */

async function targetName(
  ctx: Context,
  domain: string,
  spec: string,
  inExp: boolean,
): Promise<string> {
  let name = (await expandMacros(ctx, domain, spec, inExp))
    .replace(/\.$/, "")
    .toLowerCase();
  // Over 253 octets, labels are dropped from the left until it fits.
  while (name.length > 253) {
    const dot = name.indexOf(".");
    if (dot === -1) throw new Interrupt("permerror");
    name = name.slice(dot + 1);
  }
  if (!name || !name.includes(".")) throw new Interrupt("permerror");
  return name;
}

const MACRO = /^([slodipvhcrt])(\d*)(r?)([.\-+,/_=]*)$/i;

export async function expandMacros(
  ctx: Context,
  domain: string,
  spec: string,
  inExp: boolean,
): Promise<string> {
  let out = "";
  for (let i = 0; i < spec.length; i++) {
    const c = spec[i] as string;
    if (c !== "%") {
      out += c;
      continue;
    }
    const next = spec[i + 1];
    if (next === "%") {
      out += "%";
      i++;
      continue;
    }
    if (next === "_") {
      out += " ";
      i++;
      continue;
    }
    if (next === "-") {
      out += "%20";
      i++;
      continue;
    }
    if (next !== "{") throw new Interrupt("permerror");
    const close = spec.indexOf("}", i + 2);
    if (close === -1) throw new Interrupt("permerror");
    const inside = spec.slice(i + 2, close).match(MACRO);
    if (!inside) throw new Interrupt("permerror");
    const letter = inside[1] as string;
    const digits = inside[2] as string;
    const reversed = (inside[3] as string) !== "";
    const delimiters = (inside[4] as string) || ".";

    // oxlint-disable-next-line no-await-in-loop
    let value = await macroValue(ctx, domain, letter.toLowerCase(), inExp);

    let parts = value.split(new RegExp(`[${delimiters.replace(/[-/]/g, "\\$&")}]`));
    if (reversed) parts = parts.toReversed();
    if (digits) {
      const keep = Number(digits);
      if (keep === 0) throw new Interrupt("permerror");
      parts = parts.slice(-keep);
    }
    value = parts.join(".");

    out += letter === letter.toUpperCase() ? encodeURIComponent(value) : value;
    i = close;
  }
  return out;
}

async function macroValue(
  ctx: Context,
  domain: string,
  letter: string,
  inExp: boolean,
): Promise<string> {
  switch (letter) {
    case "s":
      return ctx.sender;
    case "l":
      return ctx.local;
    case "o":
      return ctx.senderDomain;
    case "d":
      return domain;
    case "i":
      return macroIp(ctx.ip);
    case "v":
      return ctx.ip.version === 4 ? "in-addr" : "ip6";
    case "h":
      return ctx.helo;
    case "p":
      return validatedDomain(ctx, domain);
    case "c":
    case "r":
    case "t":
      if (!inExp) throw new Interrupt("permerror");
      if (letter === "c") return readableIp(ctx.ip);
      if (letter === "r") return ctx.receiver;
      return String(Math.floor(Date.now() / 1000));
    default:
      throw new Interrupt("permerror");
  }
}

/**
 * The %{p} macro: a PTR name for the IP that forward-confirms. The RFC says
 * senders should not publish it, and tells verifiers "unknown" is always an
 * acceptable answer, which is also the answer when DNS will not cooperate.
 */
async function validatedDomain(ctx: Context, domain: string): Promise<string> {
  let names: readonly string[];
  try {
    names = await ctx.resolver(reverseName(ctx.ip), "PTR");
  } catch {
    return "unknown";
  }
  let fallback: string | null = null;
  for (const raw of names.slice(0, PTR_LIMIT)) {
    const host = raw.toLowerCase().replace(/\.$/, "");
    let confirmed: readonly string[];
    try {
      // oxlint-disable-next-line no-await-in-loop
      confirmed = await ctx.resolver(host, ctx.ip.version === 4 ? "A" : "AAAA");
    } catch {
      continue;
    }
    const valid = confirmed.some((a) => {
      const parsed = parseIp(a);
      return (
        parsed !== null &&
        parsed.version === ctx.ip.version &&
        inCidr(ctx.ip.bytes, parsed.bytes, ctx.ip.version === 4 ? 32 : 128)
      );
    });
    if (!valid) continue;
    if (host === domain || host.endsWith(`.${domain}`)) return host;
    fallback ??= host;
  }
  return fallback ?? "unknown";
}

/* --------------------------------------------------------- explanation --- */

/**
 * The exp= text, fetched and expanded only for a fail, and never allowed to
 * turn a clean fail into an error: a broken explanation is just no explanation.
 */
async function explanation(
  ctx: Context,
  domain: string,
  expSpec: string,
): Promise<string | null> {
  try {
    const target = await targetName(ctx, domain, expSpec, true);
    const records = await ctx.resolver(target, "TXT");
    if (records.length !== 1) return null;
    return await expandMacros(ctx, domain, records[0] as string, true);
  } catch {
    return null;
  }
}
