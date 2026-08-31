import type { Note, Recommendation } from "../types.ts";
import type { AuthCheck } from "./auth.ts";
import type { Address, Hop } from "./parse.ts";

export type HeaderVerdict = "suspicious" | "inconclusive" | "authentic";

/** Where the authentication verdicts came from, which decides how much they weigh. */
export type AuthSource = "receiver" | "arc" | "received-spf" | "none";

export type Flag = Note & { readonly evidence: string | null };

export type Identity = {
  readonly from: Address | null;
  readonly returnPath: Address | null;
  readonly replyTo: Address | null;
  readonly to: Address | null;
  readonly fromCount: number;
};

export type Route = {
  readonly hops: readonly Hop[];
  readonly originatingIp: string | null;
  readonly mailer: string | null;
};

export type MessageSummary = {
  readonly subject: string | null;
  readonly date: string | null;
  readonly messageId: string | null;
  readonly listUnsubscribe: boolean;
  readonly spamScore: string | null;
};

export type HeaderAnalysis = {
  readonly verdict: HeaderVerdict;
  readonly summary: string;
  readonly authSource: AuthSource;
  readonly spf: AuthCheck;
  readonly dkim: AuthCheck;
  readonly dmarc: AuthCheck;
  readonly identity: Identity;
  readonly route: Route;
  readonly message: MessageSummary;
  readonly flags: readonly Flag[];
  readonly recommendations: readonly Recommendation[];
};
