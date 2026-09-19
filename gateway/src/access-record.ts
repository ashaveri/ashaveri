/**
 * One JSONL line per request, and the field names are the whole allowlist: nothing a
 * future hook learns about a caller can reach the log, because only these keys are
 * ever read out of an object. Bodies, headers, keys, secrets, query strings, source
 * addresses and user agents have no field to be written into.
 */
export interface AccessRecord {
  /** Epoch milliseconds at the request's arrival. */
  readonly t: number;
  /** Server-generated request id, the join key between a line and a support ticket. */
  readonly rid: string;
  readonly cred: string | null;
  readonly auth: 'pop' | 'bearer' | null;
  readonly scope: string | null;
  readonly m: string;
  /** Path only. The query string is dropped: it carries report data and receipt ids. */
  readonly p: string;
  /** The receipt a read route was asked for. Only /v1/receipts/:id names one in its target, so a
   * completion that issues a receipt leaves this null, as does a request refused before admission. */
  readonly rcp: string | null;
  readonly nce: string | null;
  readonly st: number;
  readonly dur: number;
  /** The refusal code, on any request the pipeline rejected. */
  readonly deny: string | null;
}
