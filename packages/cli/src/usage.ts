/**
 * A refusal the operator can act on. Everything thrown from a command path for a reason the person
 * typing can fix exits 2 and prints its message alone, so a stack trace stays reserved for the bugs
 * nobody at a terminal can do anything about.
 */
export class UsageError extends Error {}
