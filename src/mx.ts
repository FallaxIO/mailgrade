/**
 * Naming the mail provider behind a set of MX hosts.
 *
 * Only used to make advice concrete ("turn DKIM on in Google Workspace"), so
 * an unrecognised host is a null and never an error.
 */

const MX_PROVIDERS: readonly (readonly [pattern: string, name: string])[] = [
  ["google.com", "Google Workspace"],
  ["googlemail.com", "Google Workspace"],
  ["protection.outlook.com", "Microsoft 365"],
  ["mx.cloudflare.net", "Cloudflare Email Routing"],
  ["mimecast", "Mimecast"],
  ["pphosted.com", "Proofpoint"],
  ["barracuda", "Barracuda"],
  ["mxrouting", "MXroute"],
  ["zoho", "Zoho Mail"],
  ["fastmail", "Fastmail"],
  ["messagingengine.com", "Fastmail"],
  ["mail.protection.icloud.com", "iCloud Mail"],
  ["protonmail.ch", "Proton Mail"],
  ["proton.me", "Proton Mail"],
  ["yandex", "Yandex 360"],
  ["titan.email", "Titan"],
  ["emailsrvr.com", "Rackspace Email"],
  ["migadu.com", "Migadu"],
  ["improvmx.com", "ImprovMX"],
  ["forwardemail.net", "Forward Email"],
];

export function mailProvider(mxHosts: readonly string[]): string | null {
  for (const raw of mxHosts) {
    const host = raw.toLowerCase().replace(/\.$/, "");
    for (const [pattern, name] of MX_PROVIDERS) {
      // A dotted pattern is a domain and matches as a suffix, so that
      // "aspmx.l.google.com" names Google and "mygoogle.com.mx" does not.
      const hit = pattern.includes(".")
        ? host === pattern || host.endsWith(`.${pattern}`)
        : host.includes(pattern);
      if (hit) return name;
    }
  }
  return null;
}
