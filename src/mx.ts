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
  const joined = mxHosts.join(" ").toLowerCase();
  for (const [pattern, name] of MX_PROVIDERS) {
    if (joined.includes(pattern)) return name;
  }
  return null;
}
