import { afterAll, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  AttestationError,
  decodeAttestation,
  parseNvidiaEvidenceBundle,
  parseSnpReport,
  parseTdxQuote,
  SNP_REPORT_SIZE,
} from '../src/index.js';
import { check, hostile, outcome, RUNS, SEED, snpReportCorpus, type Outcome } from './generators.js';
import { encodeV0Tdx, fixture, MsgpackWriter, ScaleWriter } from './helpers.js';

const isOwnError = (err: unknown): boolean => err instanceof AttestationError;
const toBase64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');

const envelope = fixture('sev-snp-attestation.bin');
const quote = fixture('tdx-quote-v4.bin');
const report = snpReportCorpus(envelope);

// The bundle is what `nvattest` writes, not what one entry of it holds: `nvidia-hopper-report.bin`
// is a single device's `evidence` field, which the bundle parser refuses outright.
const gpuBundle = new TextEncoder().encode(
  JSON.stringify([
    {
      arch: 'hopper',
      evidence: toBase64(fixture('nvidia-hopper-report.bin')),
      certificate: toBase64(fixture('nvidia-hopper-cert-chain.pem')),
      version: '1.1.0',
    },
  ]),
);

/** The longest byte string anywhere inside a parsed value, which is what a parser can invent. */
function longestByteField(value: unknown): number {
  if (value instanceof Uint8Array) {
    return value.length;
  }
  if (Array.isArray(value)) {
    return value.reduce((max, item) => Math.max(max, longestByteField(item)), 0);
  }
  if (value !== null && typeof value === 'object') {
    return Object.values(value).reduce((max, item) => Math.max(max, longestByteField(item)), 0);
  }
  return 0;
}

/** The quote's fixed layout: the last field ends at 0x238 + 64, and nothing before it is optional. */
const QUOTE_LAYOUT_BYTES = 0x238 + 64;

/**
 * The shortest prefix of the corpus the parser accepts, found by asking it rather than by
 * restating a constant. Below it the format is definitionally incomplete, and that is what the
 * third property asserts against; a stale number here would make the assertion vacuous, and this
 * cannot go stale because it is measured from the same bytes every run.
 */
function acceptanceBoundary(parse: (input: Uint8Array) => unknown, source: Uint8Array): number {
  for (let length = 0; length <= source.length; length += 1) {
    try {
      parse(source.slice(0, length));
      return length;
    } catch (err) {
      if (!isOwnError(err)) {
        throw err;
      }
    }
  }
  return source.length + 1;
}

interface Target {
  readonly name: string;
  readonly parse: (input: Uint8Array) => unknown;
  readonly source: Uint8Array;
  /** The length the format's own layout requires, spelled out so the measured boundary means something. */
  readonly layoutMinimum: number;
  readonly layoutWhy: string;
  /**
   * A claim about a value the parser returned for input of `length` bytes, stated in the target's
   * own terms: which fields are fixed-width, and therefore which widths prove the bytes were there.
   */
  readonly widths: ((input: Uint8Array, value: unknown) => boolean) | null;
}

const TARGETS: readonly Target[] = [
  {
    name: 'decodeAttestation',
    parse: decodeAttestation,
    source: envelope,
    layoutMinimum: envelope.length,
    layoutWhy: 'the envelope has no optional tail: every section is read in order and any left-over byte is refused',
    widths: null,
  },
  {
    name: 'parseTdxQuote',
    parse: parseTdxQuote,
    source: quote,
    layoutMinimum: QUOTE_LAYOUT_BYTES,
    layoutWhy: 'report_data is the last fixed field and ends at 0x238 + 64',
    widths: (_input, value) => {
      const parsed = value as {
        mrTd: Uint8Array;
        mrConfigId: Uint8Array;
        mrOwner: Uint8Array;
        mrOwnerConfig: Uint8Array;
        rtmr: readonly Uint8Array[];
        reportData: Uint8Array;
      };
      return (
        parsed.mrTd.length === 48 &&
        parsed.mrConfigId.length === 48 &&
        parsed.mrOwner.length === 48 &&
        parsed.mrOwnerConfig.length === 48 &&
        parsed.rtmr.length === 4 &&
        parsed.rtmr.every((field) => field.length === 48) &&
        parsed.reportData.length === 64
      );
    },
  },
  {
    name: 'parseSnpReport',
    parse: parseSnpReport,
    source: report,
    layoutMinimum: SNP_REPORT_SIZE,
    layoutWhy: 'the AMD report is a fixed 0x4a0-byte structure',
    widths: null,
  },
  {
    name: 'parseNvidiaEvidenceBundle',
    parse: parseNvidiaEvidenceBundle,
    source: gpuBundle,
    layoutMinimum: gpuBundle.length,
    layoutWhy: 'the document is one JSON array with no optional tail, so a truncation is not JSON at all',
    widths: null,
  },
];

function sameOutcome(a: Outcome, b: Outcome): boolean {
  if (a.kind === 'value' && b.kind === 'value') {
    return a.shape === b.shape;
  }
  if (a.kind === 'error' && b.kind === 'error') {
    return a.code === b.code;
  }
  return a.kind === 'foreign' && b.kind === 'foreign' && a.name === b.name;
}

describe('untrusted parsers, by property', () => {
  afterAll(() => {
    if (process.env['FC_SEED'] === undefined) {
      process.stdout.write(`property seeds for this run: ${String(SEED)} (runs per property: ${String(RUNS)})\n`);
    }
  });

  for (const target of TARGETS) {
    const boundary = acceptanceBoundary(target.parse, target.source);

    describe(target.name, () => {
      it('reports the acceptance boundary the truncation rule is stated against', () => {
        // The measured boundary has to be the layout's own number, or the third property below is
        // asserting a boundary that came from nowhere. This is also the claim that a corpus which
        // stopped being readable cannot quietly pass the other three.
        expect(boundary).toBe(target.layoutMinimum);
        expect(target.source.length).toBeGreaterThanOrEqual(target.layoutMinimum);
      });

      it('either returns a value or throws its own error, for any input', () => {
        check(hostile(target.source), [target.source, new Uint8Array(0)], (input) => {
          const result = outcome(target.parse, input, isOwnError);
          // A silent `undefined` is a third way out, and not one a caller can act on.
          return result.kind === 'error' || (result.kind === 'value' && result.shape !== 'undefined:undefined');
        });
      });

      it('decides the same way twice on the same bytes, and leaves them alone', () => {
        check(hostile(target.source), [target.source], (input) => {
          const before = input.slice();
          const first = outcome(target.parse, input, isOwnError);
          const second = outcome(target.parse, before.slice(), isOwnError);
          const untouched = before.length === input.length && before.every((byte, index) => input[index] === byte);
          return untouched && sameOutcome(first, second);
        });
      });

      it('refuses a truncation below the format boundary and invents no bytes at or above it', () => {
        // Every prefix below the boundary, walked rather than sampled: this is the claim that a
        // parser which trusted a length it read from its own input would fail, and a sample of 300
        // lengths out of a few thousand can miss the one that parses. The walk is the same work the
        // boundary measurement above already does, so it doubles that fixed cost and adds no
        // property run.
        for (let length = 0; length < boundary; length += 1) {
          const result = outcome(target.parse, target.source.slice(0, length), isOwnError);
          expect(result.kind, `${target.name} accepted a ${String(length)}-byte prefix`).toBe('error');
        }
        check(hostile(target.source), [target.source], (input) => {
          const result = outcome(target.parse, input, isOwnError);
          if (result.kind !== 'value') {
            return true;
          }
          // Nothing in the value may be wider than the bytes that were handed over, and a field
          // the format pins to a width has to carry that width: a short one is a read past the end.
          if (longestByteField(target.parse(input)) > input.length) {
            return false;
          }
          return target.widths === null || target.widths(input, target.parse(input));
        });
      });
    });
  }
});

describe('the three sites that decode text, which is where a stranger chooses the bytes', () => {
  // These three cases exist because `TextDecoder` with `fatal: true` throws a bare `TypeError`,
  // and the vocabulary every caller of this package branches on is `AttestationError`. The offset
  // in the message is asserted too: it is the reason the sentence is worth logging.

  const invalidTail = new Uint8Array([0xff, 0xfe]);

  it('refuses a V0 SCALE string that is not valid UTF-8, naming where it starts', () => {
    // The shortest V0 envelope the decoder walks all the way down to its last field, which is the
    // `config` string, so this aims at one read site and nothing else. The field is written raw
    // because it is not text the encoder would produce.
    const writer = new ScaleWriter();
    writer.byte(0x00).byte(0x00); // V0 tag, then the tdx platform variant
    writer.vec(new Uint8Array(0)); // quote
    writer.compact(0); // no platform event log
    writer.compact(1); // one runtime event, whose name is read as a string and is well formed
    writer.string('boot').vec(new Uint8Array(0));
    writer.fixed(new Uint8Array(64)); // report_data
    const bytes = writer.vec(invalidTail).finish();
    try {
      decodeAttestation(bytes);
      throw new Error('expected a refusal');
    } catch (err) {
      expect(err).toBeInstanceOf(AttestationError);
      const failure = err as AttestationError;
      expect(failure.code).toBe('MALFORMED_ATTESTATION');
      expect(failure.message).toContain(`offset ${String(bytes.length - invalidTail.length)}`);
    }
  });

  it('refuses a V1 msgpack map key that is not valid UTF-8, naming where it starts', () => {
    // A one-entry map whose single key is two bytes that cannot start a UTF-8 sequence.
    const bytes = new Uint8Array([0x81, 0xa2, 0xff, 0xfe]);
    try {
      decodeAttestation(bytes);
      throw new Error('expected a refusal');
    } catch (err) {
      expect(err).toBeInstanceOf(AttestationError);
      const failure = err as AttestationError;
      expect(failure.code).toBe('MALFORMED_ATTESTATION');
      expect(failure.message).toContain('offset 2');
    }
  });

  it('refuses a V1 msgpack value read as a string that is not valid UTF-8, naming where it starts', () => {
    // platform = { kind: "tdx", data: <two bytes that are not UTF-8> }, read through the
    // general value decoder rather than the map-key path above.
    const text = new TextEncoder();
    const bytes = new Uint8Array([
      0x81,
      0xa8,
      ...text.encode('platform'),
      0x82,
      0xa4,
      ...text.encode('kind'),
      0xa3,
      ...text.encode('tdx'),
      0xa4,
      ...text.encode('data'),
      0xa2,
      ...invalidTail,
    ]);
    try {
      decodeAttestation(bytes);
      throw new Error('expected a refusal');
    } catch (err) {
      expect(err).toBeInstanceOf(AttestationError);
      const failure = err as AttestationError;
      expect(failure.code).toBe('MALFORMED_ATTESTATION');
      expect(failure.message).toContain(`offset ${String(bytes.length - invalidTail.length)}`);
    }
  });
});

/**
 * The characters `errors.ts` promises never to leave raw. Stated again here rather than imported
 * from the producer on purpose: a test that borrows the code's own pattern can only restate it,
 * and what these cases hold is the promise a reader of a log or a terminal depends on.
 */
const INVISIBLE = /[\p{Cc}\p{Cf}\u{2028}\u{2029}\u{e0000}-\u{e007f}]/u;

/**
 * A V1 envelope naming its one entry `name`, then a byte nothing reads, so the refusal the decoder
 * raises is about the name. 0xc1 is the marker msgpack never uses.
 */
function v1Quoting(name: string): Uint8Array {
  const writer = new MsgpackWriter();
  writer.map(1).str(name);
  return new Uint8Array([...writer.finish(), 0xc1]);
}

/** Accepted, or refused with a message that is one line of visible text. */
function staysOnOneLine(bytes: Uint8Array): boolean {
  try {
    decodeAttestation(bytes);
    return true;
  } catch (err) {
    return err instanceof AttestationError && !INVISIBLE.test(err.message);
  }
}

describe('a refusal that quotes a name out of the document', () => {
  // `decode.ts` folds a decoded map key into the context of whatever follows it, and a key is
  // checked only to be valid UTF-8, which every character below is. The alphabet is the two ways
  // that reaches a reader: a break a line-splitting log reader honours, and the invisible
  // formatting a terminal or an editor honours.
  const hostileName = fc.string({
    unit: fc.constantFrom(...['a', 'b', '=', '\n', '\r', '\v', '\f', '\u001c', '\u0085', '\u2028', '\u2029', '\u200e', '\u202a', '\0']),
    maxLength: 12,
  });

  it('leaves a name built from anything that can break a line inside one line', () => {
    check(hostileName.map(v1Quoting), [v1Quoting('att\nx'), v1Quoting('plain'), new Uint8Array(0)], staysOnOneLine);
  });

  it('holds once the bytes around the name are hostile too', () => {
    const corpus = v1Quoting('att\u2028x');
    check(hostile(corpus), [corpus, new Uint8Array(0)], staysOnOneLine);
  });

  it('escapes the name it quoted, not a fixed sentence that never carried one', () => {
    try {
      decodeAttestation(v1Quoting('att\nx'));
      throw new Error('expected a refusal');
    } catch (err) {
      expect(err).toBeInstanceOf(AttestationError);
      const failure = err as AttestationError;
      expect(failure.code).toBe('MALFORMED_ATTESTATION');
      // Without this the two properties above could pass on a decoder that refuses map keys before
      // it reads one, since a message that never carried the name has nothing to escape.
      expect(failure.message).toContain('attestation.att\\u000ax');
      expect(failure.message.split('\n')).toHaveLength(1);
    }
  });
});

describe('a length the document states about itself, in each width the format writes one in', () => {
  /** One V0 tdx envelope whose single runtime-event name is `name`. */
  function v0EventName(name: string): Uint8Array {
    return encodeV0Tdx({
      quote: new Uint8Array(64),
      eventLog: [],
      runtimeEvents: [{ event: name, payload: new Uint8Array(0), version: 1 }],
      reportData: new Uint8Array(64),
      config: 'test',
    });
  }

  it('reads a name as long as the text it holds, in every compact width', () => {
    // 63 and 64 are where SCALE moves a length from one byte to two, and 16383 and 16384 where it
    // moves to four. The last pair is where a four-byte length stops being itself: the width holds
    // the value shifted by two with the mode in the low bits, so reading it back without the shift
    // asks for about four times the bytes the document promised.
    for (const length of [0, 1, 63, 64, 4096, 16383, 16384, 40000]) {
      const decoded = decodeAttestation(v0EventName('x'.repeat(length)));
      expect(decoded.stack.runtimeEvents, `a ${String(length)}-byte name`).toHaveLength(1);
      expect(decoded.stack.runtimeEvents[0]?.event).toBe('x'.repeat(length));
    }
  });

  it('passes an event name through as written, because nothing here sanitises one', () => {
    // The limit a report route has to respect: a name is bounded in length only by the cap on the
    // whole document and in character by nothing at all, so an event this deployment never heard of
    // arrives at whoever prints it exactly as the sender wrote it.
    const name = `\u001b[2J\u0085second line\u2028${'x'.repeat(50000)}`;
    expect(decodeAttestation(v0EventName(name)).stack.runtimeEvents[0]?.event).toBe(name);
  });

  it('refuses a stated length above the whole-document cap, naming the length it read', () => {
    const writer = new ScaleWriter();
    writer.byte(0x00).byte(0); // V0 tag, then the tdx platform variant
    writer.vec(new Uint8Array(64)); // quote
    writer.compact(0); // no firmware event log
    writer.compact(1); // one runtime event, whose name claims more bytes than any document holds
    writer.compact(10 * 1024 * 1024 + 1);
    try {
      decodeAttestation(writer.finish());
      throw new Error('expected a refusal');
    } catch (err) {
      expect(err).toBeInstanceOf(AttestationError);
      const failure = err as AttestationError;
      expect(failure.code).toBe('MALFORMED_ATTESTATION');
      // The number in the sentence is the length the decoder understood, not the integer it read
      // off the wire, so an unshifted 41943046 here is the width bug above from this side.
      expect(failure.message).toContain('length 10485761 exceeds size limit');
    }
  });
});
