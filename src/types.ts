/** Where a single check lands. */
export type Status = "pass" | "warn" | "fail";

/** As above, plus the case where the receiver reported nothing at all. */
export type AuthStatus = Status | "neutral";

export type Severity = "high" | "medium" | "info";

/**
 * Every piece of prose this library produces carries a stable `id`.
 *
 * The English is a convenience, not the contract: swap it for your own copy or
 * another language by keying off the id, and pin behaviour in tests against
 * ids rather than sentences. The conformance corpus in `spec/` asserts on ids
 * for the same reason, so a port to another language can share it.
 */
export type Identified = { readonly id: string };

export type Recommendation = Identified & { readonly text: string };

export type Note = Identified & {
  readonly severity: Severity;
  readonly title: string;
  readonly detail: string;
};
