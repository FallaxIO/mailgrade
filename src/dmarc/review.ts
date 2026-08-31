/**
 * What a DMARC record will actually do, and how to move it forward.
 *
 * These are not validation errors. A record can be flawless DMARC and still
 * leave the domain wide open, and the notes that matter most (p=none, an open
 * sp, enforcement with nowhere to report) are all in that category.
 */

import type { Note, Severity } from "../types.ts";
import {
  buildDmarcRecord,
  cleanAddresses,
  DEFAULT_RI,
  externalDestinations,
  type DmarcOptions,
  type DmarcPolicy,
  type SubdomainPolicy,
} from "./record.ts";

/**
 * The only three states worth distinguishing: the record watches, it catches
 * some of it, or it refuses it.
 *
 * A record at quarantine is doing real work, which is why it is not lumped in
 * with none, and it is still not the end state, which is why it is not lumped
 * in with reject.
 */
export type Grade = "monitor" | "partial" | "enforcing";

export type DmarcNote = Note;

export function dmarcGrade(o: DmarcOptions): Grade {
  if (o.policy === "none") return "monitor";
  if (o.policy === "reject" && o.pct >= 100) return "enforcing";
  return "partial";
}

const RANK: Record<Severity, number> = { high: 0, medium: 1, info: 2 };
const STRENGTH: Record<DmarcPolicy, number> = {
  none: 0,
  quarantine: 1,
  reject: 2,
};

/** Everything worth saying about a record, strongest first. */
export function reviewDmarc(o: DmarcOptions): DmarcNote[] {
  const notes: DmarcNote[] = [];
  const rua = cleanAddresses(o.rua);
  const ruf = cleanAddresses(o.ruf);
  const enforcing = o.policy !== "none";

  if (rua.length === 0) {
    notes.push({
      id: "no-rua",
      severity: enforcing ? "high" : "medium",
      title: "No report address",
      detail: enforcing
        ? "You are asking receivers to hold back mail and giving yourself no way to see what they held back. The first casualty of an unwatched rollout is a real invoice from a system nobody remembered was sending mail."
        : "Without a rua address the record is a monitoring policy that never reports. Nothing arrives, nothing is learned, and the rollout cannot move past this step.",
    });
  }

  if (o.policy === "none") {
    notes.push({
      id: "monitor-only",
      severity: "medium",
      title: "p=none delivers the forgery",
      detail:
        "This is the correct place to start and a bad place to stop. Until the policy reaches quarantine or reject, a message with your domain in the From line lands in the inbox exactly like a real one.",
    });
  }

  if (o.pct < 100 && o.policy === "none") {
    notes.push({
      id: "pct-under-none",
      severity: "medium",
      title: "pct does nothing here",
      detail:
        "pct only decides how much failing mail gets quarantined or rejected. Under p=none there is nothing to apply it to, so the tag reads like caution while changing nothing.",
    });
  } else if (o.pct < 100) {
    notes.push({
      id: "pct-partial",
      severity: "info",
      title: `${100 - o.pct}% of failing mail still gets through`,
      detail:
        "That is the point of the dial during a rollout: a sample gets the policy, the rest is delivered, and your reports tell you whether the sample contained anything you wanted delivered.",
    });
  }

  if (
    o.subdomainPolicy !== "inherit" &&
    STRENGTH[o.subdomainPolicy] < STRENGTH[o.policy]
  ) {
    notes.push({
      id: "sp-weaker",
      severity: "high",
      title: "Subdomains are the weak point",
      detail: `p=${o.policy} protects the domain itself while sp=${o.subdomainPolicy} leaves everything under it open, including subdomains that do not exist. Nothing stops a forger putting billing.${o.domain || "yourdomain.com"} in the From line, and to a reader it looks more official, not less.`,
    });
  }

  if (o.adkim === "s" || o.aspf === "s") {
    notes.push({
      id: "strict-alignment",
      severity: "medium",
      title: "Strict alignment breaks ordinary senders",
      detail:
        "Most mail vendors sign as a subdomain of yours and bounce to one too, which relaxed alignment accepts and strict alignment fails. Turn it on only once your reports show every legitimate sender aligning exactly.",
    });
  }

  if (ruf.length > 0) {
    notes.push({
      id: "ruf-privacy",
      severity: "medium",
      title: "Failure reports carry other people's mail",
      detail:
        "A ruf destination receives headers, and sometimes the body, of individual messages that failed, including real mail of yours that broke in transit. Most large receivers never send them at all. Point it at a mailbox you would be comfortable disclosing, or leave it out.",
    });
  }

  if (o.fo !== "0" && ruf.length === 0) {
    notes.push({
      id: "fo-without-ruf",
      severity: "medium",
      title: "fo without ruf is inert",
      detail:
        "fo decides which failures earn a failure report, and failure reports need somewhere to go. With no ruf address the tag is ignored.",
    });
  }

  if (rua.length > 2) {
    notes.push({
      id: "many-rua",
      severity: "medium",
      title: "More than two report destinations",
      detail:
        "Receivers are allowed to cap how many destinations they send to, and two is the common cap. The addresses after the second are not guaranteed to hear anything.",
    });
  }

  const external = externalDestinations(o);
  if (external.length > 0) {
    notes.push({
      id: "external-reports",
      severity: "info",
      title: "Reports going to another domain",
      detail: `${external.map((e) => e.domain).join(" and ")} ${external.length === 1 ? "has" : "have"} to publish an authorization record before receivers will send reports there. DMARC vendors do this for you; a colleague's mailbox at another company does not.`,
    });
  }

  if (o.ri !== DEFAULT_RI) {
    notes.push({
      id: "ri-nonstandard",
      severity: "info",
      title: "A non-standard report interval",
      detail:
        "ri is a request, not an instruction. Receivers are only required to manage one report a day, and the large ones send exactly that whatever the tag says.",
    });
  }

  const record = buildDmarcRecord(o);
  if (record.length > 255) {
    notes.push({
      id: "long-record",
      severity: "medium",
      title: "Longer than one TXT string",
      detail: `The value is ${record.length} characters, and a single DNS string holds 255. It has to be published as several quoted strings, which most panels do for you and a few refuse without explaining why.`,
    });
  }

  if (dmarcGrade(o) === "enforcing" && rua.length > 0) {
    notes.push({
      id: "at-destination",
      severity: "info",
      title: "This is the finished state",
      detail:
        "Full rejection, reported. Nobody can put your domain in a From line and reach an inbox. What is left is every phishing message that never needed your domain, which is most of them.",
    });
  }

  return notes.toSorted((a, b) => RANK[a.severity] - RANK[b.severity]);
}

/* -------------------------------------------------------------- rollout --- */

export type RolloutStage = {
  readonly key: string;
  readonly label: string;
  readonly title: string;
  readonly record: string;
  readonly detail: string;
  /** True for the stage the given options sit at. */
  readonly current: boolean;
};

/**
 * The same record at four settings, which is what a DMARC rollout is.
 *
 * Every stage keeps the reporting and alignment choices, because the only
 * variable worth moving is how much failing mail is held back. Going straight
 * to reject is not reckless because reject is harsh; it is reckless because
 * you find out which of your own systems were never authenticating by having
 * their mail refused.
 */
export function rolloutPlan(o: DmarcOptions): RolloutStage[] {
  const base: DmarcOptions = {
    ...o,
    subdomainPolicy: "inherit" satisfies SubdomainPolicy,
  };
  const at = (policy: DmarcPolicy, pct: number) =>
    buildDmarcRecord({ ...base, policy, pct });

  const grade = dmarcGrade(o);
  return [
    {
      key: "monitor",
      label: "Weeks 1-4",
      title: "Watch, change nothing",
      record: at("none", 100),
      detail:
        "Not one message is treated differently. Reports start arriving the next day, and the job of this month is to read them until every server sending in your name is one you recognise: the mail platform, the invoicing tool, the CRM, the thing marketing bought in 2019.",
      current: grade === "monitor",
    },
    {
      key: "quarantine-sample",
      label: "Week 5",
      title: "Quarantine a quarter",
      record: at("quarantine", 25),
      detail:
        "A quarter of failing mail goes to spam. If a system you missed is still unauthenticated, this is where you hear about it from a colleague rather than from a customer, and rolling back is one DNS edit.",
      current: o.policy === "quarantine" && o.pct < 100,
    },
    {
      key: "quarantine",
      label: "Week 7",
      title: "Quarantine everything",
      record: at("quarantine", 100),
      detail:
        "All failing mail goes to spam. Forged invoices stop reaching the inbox, and anything of yours that is still broken is now visibly broken, which is the last chance to find it before it is refused outright.",
      current: o.policy === "quarantine" && o.pct >= 100,
    },
    {
      key: "reject",
      label: "Week 9",
      title: "Reject",
      record: at("reject", 100),
      detail:
        "Receivers refuse the message during the SMTP conversation. It is never delivered, never filed in spam, and never a judgement call for the person it was aimed at. This is where the domain stops being usable by anyone else.",
      current: grade === "enforcing",
    },
  ];
}
