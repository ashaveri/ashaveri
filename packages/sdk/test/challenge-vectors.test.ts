import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  decodeReceipt,
  fromBase64Url,
  toHex,
  type Encryption,
  type ReceiptPayloadV2,
} from '@ashaveri/receipt';
import { encodeV0Tdx } from '../../attest-core/test/helpers.js';
import { SdkError, evidenceReportData, verifyCompletionEvidence } from '../src/index.js';

/**
 * The published challenge family, replayed through the shipped derivation and the shipped verifier.
 *
 * `data/challenge-v1.json` states the rule as bytes: for each arm, the triple a receipt this repository signs
 * carries, the concatenation the rule builds from it, and the digest that concatenation hashes to. This file
 * asks two questions of it. First, whether `evidenceReportData`, the function the client runs, gives each
 * published digest, which is what keeps the published arithmetic and the shipped code from drifting apart in
 * either direction. Second, whether each published refusal is the code the shipped verifier actually answers
 * when it is handed a document bound to the other reading, because a vector whose negative is a sentence is
 * a vector a port can pass by refusing everything.
 *
 * What neither question can reach here is the platform's seal. A captured quote's report data is fixed by the
 * signature over it, so no test in this repository can hand the verifier a genuine document carrying a
 * composite; that leg is owed to a capture and the suite says so in `layout.owedPlatformCapture`.
 */

const DATA = join(dirname(fileURLToPath(new URL('../../fixtures/data/challenge-v1.json', import.meta.url))));

interface ChallengeFile {
  version: number;
  description: string;
  layout: Record<string, unknown>;
  vectors: Array<{
    name: string;
    document: string;
    arm: string;
    nonceBase64Url: string;
    sessionKeyBase64Url?: string;
    requestDigestHex: string;
    digestHex: string;
  }>;
  refusals: Array<{
    name: string;
    document: string;
    presentedDigestHex: string;
    statedDigestHex: string;
    code: string;
    notCode: string;
  }>;
}

const file = JSON.parse(readFileSync(join(DATA, 'challenge-v1.json'), 'utf8')) as ChallengeFile;

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const all = new Uint8Array(parts.reduce((total, one) => total + one.length, 0));
  let at = 0;
  for (const part of parts) {
    all.set(part, at);
    at += part.length;
  }
  return all;
}

const hexToBytes = (value: string): Uint8Array => new Uint8Array(value.match(/../g)!.map((pair) => Number.parseInt(pair, 16)));
const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value);

/** The arm the published row states, in the shape the derivation takes. */
function armOf(row: ChallengeFile['vectors'][number]): Encryption {
  if (row.arm === 'none') return { sch: 'none' };
  if (row.sessionKeyBase64Url === undefined) throw new Error(`${row.name} names a scheme and publishes no key`);
  if (row.arm !== 'x25519-aes-256-gcm-v1') throw new Error(`${row.name} states a label outside the registry`);
  return { sch: row.arm, pk: fromBase64Url(row.sessionKeyBase64Url) };
}

/** The receipt the row reads its triple out of, as the published bytes sign it. */
function publishedPayload(reference: string): ReceiptPayloadV2 {
  const rowName = reference.split('#')[1]!;
  const bytes = new Uint8Array(readFileSync(join(DATA, 'receipts', `${rowName}.cbor`)));
  const decoded = decodeReceipt(bytes).payload;
  if (decoded.v !== 2) throw new Error(`${rowName} states no encryption arm`);
  return decoded;
}

// The estate's one Intel-signed capture, re-wrapped in the envelope dStack serves. Its REPORT_DATA is the
// fixture host's own value: it is the document the binding step is asked about, because nothing in this
// repository can sign a field carrying a digest of our choosing.
const QUOTE = new Uint8Array(readFileSync(new URL('../../attest-core/test/fixtures/tdx-quote-v4.bin', import.meta.url)));
const CAPTURED_REPORT_DATA = concat(hexToBytes('48656c6c6f2066726f6d20456467656c6573732053797374656d7321'), new Uint8Array(36));
const CAPTURED_DOCUMENT = encodeV0Tdx({
  quote: QUOTE,
  eventLog: [],
  runtimeEvents: [],
  reportData: CAPTURED_REPORT_DATA,
  config: 'ashaveri-challenge-vectors',
});
const CAPTURED_MILLIS = Date.UTC(2026, 0, 15);
/** The launch measurement this quote attests, so the receipt weighed against it claims the same platform. */
const MR_TD = 'b65ea009e424e6f761fdd3d7c8962439453b37ecdf62da04f7bc5d327686bb8bafc8a5d24a9c31cee60e4aba87c2f71b';

/** The document a deployment mints for one named value, standing in for a route that mints rather than looks up. */
const mint = (reportData: Uint8Array): Uint8Array => concat(utf8('evidence-minted-for-'), reportData);

function refusalCode(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    if (error instanceof SdkError) return error.code;
    throw error;
  }
  throw new Error('expected a refusal and the call returned normally');
}

describe('data/challenge-v1.json through the shipped derivation', () => {
  it.each(file.vectors)('$name', (row) => {
    const payload = publishedPayload(row.document);
    expect(toHex(payload.nce)).toBe(toHex(fromBase64Url(row.nonceBase64Url)));
    expect(toHex(payload.req)).toBe(row.requestDigestHex);
    expect(toHex(evidenceReportData(payload.nce, payload.req, armOf(row)))).toBe(row.digestHex);
  });

  it('reads the plain arm as the two-part value it shipped as', () => {
    const row = file.vectors.find((each) => each.arm === 'none')!;
    const payload = publishedPayload(row.document);
    expect(toHex(evidenceReportData(payload.nce, payload.req))).toBe(row.digestHex);
  });
});

describe('data/challenge-v1.json refusals are the codes they state', () => {
  for (const row of file.refusals) {
    it(`${row.name}: the shipped path answers ${row.code}`, () => {
      const stated = hexToBytes(row.statedDigestHex);
      const presented = hexToBytes(row.presentedDigestHex);
      // The receipt is the published one over the same triple, committing either to the document minted for
      // its own value or to the captured quote, so the only thing that can move the answer is which value the
      // reader asked for.
      const payload = publishedPayload(row.document);
      const digestMismatch = row.code === 'EVIDENCE_DIGEST_MISMATCH';
      const committed = digestMismatch ? mint(stated) : CAPTURED_DOCUMENT;
      // The published receipt declares a composite AMD measurement, so a row weighed against the captured
      // Intel quote states the platform that quote can answer for; the triple the row publishes is unchanged.
      const weighed: ReceiptPayloadV2 = {
        ...payload,
        att: { ...payload.att, d: sha256(committed) },
        ...(digestMismatch ? {} : { meas: { tee: 'tdx' as const, m: hexToBytes(MR_TD) } }),
      };
      const code = refusalCode(() =>
        verifyCompletionEvidence({
          document: digestMismatch ? mint(presented) : CAPTURED_DOCUMENT,
          expectedReportData: presented,
          payload: weighed,
          nowMillis: digestMismatch ? payload.iat * 1000 : CAPTURED_MILLIS,
        }),
      );
      expect(code).toBe(row.code);
      // The answer a stale reader must not give: the route mints for any named value, so a skew cannot be
      // reported as evidence that has aged out.
      expect(code).not.toBe(row.notCode);
      // The pairing, which says the refusal above came from this rule and not from the double or from an
      // unrelated step. Over a minted document, the value the receipt states walks past the digest check and
      // the only thing left to refuse is that these bytes are no platform document. Over the captured quote,
      // whose field is the host's own value rather than a digest of this file's choosing, the same call with
      // that value returns verified evidence, and it is exactly that difference, a field no test here can
      // write, that the owed platform capture is about.
      if (digestMismatch) {
        expect(
          refusalCode(() =>
            verifyCompletionEvidence({
              document: committed,
              expectedReportData: stated,
              payload: weighed,
              nowMillis: payload.iat * 1000,
            }),
          ),
        ).toBe('EVIDENCE_VERIFICATION_FAILED');
      } else {
        const accepted = verifyCompletionEvidence({
          document: CAPTURED_DOCUMENT,
          expectedReportData: CAPTURED_REPORT_DATA,
          payload: weighed,
          nowMillis: CAPTURED_MILLIS,
        });
        expect(toHex(accepted.reportData)).toBe(toHex(CAPTURED_REPORT_DATA));
      }
    });
  }
});
