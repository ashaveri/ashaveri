import { parseSnpReport, SNP_REPORT_SIZE } from '../src/index.js';
import fc from 'fast-check';

/**
 * Set from the environment so a red run replays exactly: set `FC_SEED=1234` on the package's test
 * run. A fixed default keeps the ordinary suite deterministic, which is what makes a failure here
 * worth reading.
 */
export const SEED = Number(process.env['FC_SEED'] ?? '20260916');

/** Kept low enough that the whole file runs inside a couple of seconds. */
export const RUNS = Number(process.env['FC_RUNS'] ?? '300');

/**
 * The report inside the envelope, found by asking the parser. A hardcoded offset would be a
 * second claim about a file that can be regenerated, and one nobody would notice going stale:
 * this returns only what `parseSnpReport` accepts, and throws if the envelope stops carrying one.
 */
export function snpReportCorpus(envelope: Uint8Array): Uint8Array {
  for (let start = 0; start + SNP_REPORT_SIZE <= envelope.length; start += 1) {
    const candidate = envelope.slice(start, start + SNP_REPORT_SIZE);
    try {
      parseSnpReport(candidate);
      return candidate;
    } catch {
      // Not a report at this offset.
    }
  }
  throw new Error(`no ${String(SNP_REPORT_SIZE)}-byte SNP report found inside the envelope fixture`);
}

/**
 * What a stranger actually sends: noise, and the three ways real traffic differs from the one
 * document that worked yesterday. Every family copies, because mutating a shared corpus in place
 * would make the next test's green meaningless.
 */
export function hostile(source: Uint8Array): fc.Arbitrary<Uint8Array> {
  const random = fc.uint8Array({ minLength: 0, maxLength: Math.max(64, source.length * 2) });
  const edited = fc
    .tuple(fc.nat({ max: Math.max(0, source.length - 1) }), fc.integer({ min: 0, max: 255 }))
    .map(([index, value]) => {
      const out = source.slice();
      out[index] = value;
      return out;
    });
  const truncated = fc.integer({ min: 0, max: source.length }).map((length) => source.slice(0, length));
  const extended = fc
    .tuple(truncated, fc.uint8Array({ minLength: 1, maxLength: 8 }))
    .map(([head, tail]) => new Uint8Array([...head, ...tail]));
  return fc.oneof(random, edited, truncated, extended);
}

/**
 * A stable sketch of a parsed value, so two runs over the same bytes can be compared without a
 * deep-equality library: byte strings become their length, numbers and bigints become their text,
 * and containers are walked in a fixed order. It is total, which matters because it runs inside a
 * property: an unknown shape reports as a type name rather than throwing on its own.
 */
export function fingerprint(value: unknown): string {
  if (value instanceof Uint8Array) {
    return `b[${value.length}]`;
  }
  if (typeof value === 'bigint') {
    return `g${value.toString(16)}`;
  }
  if (Array.isArray(value)) {
    return `[${value.map(fingerprint).join(',')}]`;
  }
  if (value === null || typeof value !== 'object') {
    return `${typeof value}:${String(value)}`;
  }
  const fields: string[] = [];
  for (const key of Object.keys(value).sort()) {
    fields.push(`${key}=${fingerprint((value as Record<string, unknown>)[key])}`);
  }
  return `{${fields.join(',')}}`;
}

/** What a parser decided about one input: the value it built, or the code it refused with. */
export type Outcome =
  | { readonly kind: 'value'; readonly shape: string }
  | { readonly kind: 'error'; readonly code: string }
  | { readonly kind: 'foreign'; readonly name: string };

/**
 * Runs a parser and records how it got out, distinguishing the package's own error from any
 * other throw. A `TypeError` escaping here is the defect these properties exist to catch: the
 * error vocabulary is the package's, and a caller cannot branch on whatever a builtin raises.
 */
export function outcome<T>(parse: (input: T) => unknown, input: T, isOwnError: (err: unknown) => boolean): Outcome {
  try {
    return { kind: 'value', shape: fingerprint(parse(input)) };
  } catch (err) {
    if (isOwnError(err)) {
      return { kind: 'error', code: (err as { code: string }).code };
    }
    return { kind: 'foreign', name: (err as Error).name };
  }
}

/**
 * Asserts one property over `arbitrary`, starting from `examples`. Each example is a list of the
 * property's arguments, and the wrap is load-bearing: measured against 4.10.1 with a property
 * written false only for the corpus value, `[[corpus]]` reports a failure after one test and
 * `[corpus]` reports nothing at all, the same as passing no examples. A byte corpus and a text
 * corpus both behave that way. Dropping the wrap would therefore void the claim that a green run
 * parsed the real document, and nothing would go red. A probe that disagrees has usually tested a
 * value that is not iterable: a number example goes red under either spelling, so a property over
 * `fc.integer` says nothing about a corpus of bytes or text. That claim is asserted directly as
 * well, by the case which measures the length at which each parser starts accepting its corpus.
 */
export function check<T>(
  arbitrary: fc.Arbitrary<T>,
  examples: readonly T[],
  predicate: (value: T) => boolean,
): void {
  fc.assert(fc.property(arbitrary, predicate), {
    numRuns: RUNS,
    seed: SEED,
    examples: examples.map((each) => [each] as [T]),
  });
}
