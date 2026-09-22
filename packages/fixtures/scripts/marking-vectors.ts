import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MARKING_SCHEMES,
  extractMarkedRegion,
  hashRequest,
  toBase64Url,
  toHex,
  type MarkingScheme,
} from '@ashaveri/receipt';
import {
  MARKING_AT,
  bufferedWithTwoMembers,
  markedBuffered,
  markedStreamed,
  memberText,
  streamedWithTwoMarkingFrames,
  substitutedMember,
  unmarkedResponse,
  unmarkedStream,
} from './marking-shapes.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

const encoded = (text: string): Uint8Array => new TextEncoder().encode(text);

/**
 * One case, stated as the pair a verifier actually holds.
 *
 * `attested` is the span whose digest a receipt would carry in `mk.d` — for `none` it is the empty
 * input, so the declaration is a value rather than an omission. `found` is the span the published rule
 * locates in `response`, and it is `null` exactly where the rule finds no single region, which is a
 * refusal of its own and never an empty string to hash. Keeping the two apart is what lets a negative
 * case say which of the two disagreed: a stripped response has an attested span and no found one, a
 * substituted one has both and they differ by their digest.
 */
interface MarkingCase {
  readonly name: string;
  readonly note: string;
  readonly sch: MarkingScheme;
  readonly shape: 'buffered' | 'streamed';
  readonly response: string;
  readonly attested: string;
  readonly found: string | null;
  readonly expected: 'verify-ok' | 'MARK_MISMATCH';
}

const CLEAN_STREAM = unmarkedStream();
const CLEAN_BODY = unmarkedResponse();
const MARKED_BODY = markedBuffered();
const MARKED_STREAM = markedStreamed();
const TWICE_BODY = bufferedWithTwoMembers();
const TWICE_STREAM = streamedWithTwoMarkingFrames();

const CASES: readonly MarkingCase[] = [
  {
    name: 'buffered-member',
    note: 'The top-level marking member of a JSON completion: its name, its colon and its value, with the multi-byte content of the completion ahead of it and untouched.',
    sch: 'provenance-v1',
    shape: 'buffered',
    response: MARKED_BODY.response,
    attested: MARKED_BODY.region,
    found: MARKED_BODY.region,
    expected: 'verify-ok',
  },
  {
    name: 'streamed-frame',
    note: 'One `data:` field line of a stream, its terminator excluded, whose payload is a chunk carrying an empty `choices` beside the member. The frame sits ahead of `data: [DONE]`, so it is inside the bytes the response digest covers.',
    sch: 'provenance-v1',
    shape: 'streamed',
    response: MARKED_STREAM.response,
    attested: MARKED_STREAM.region,
    found: MARKED_STREAM.region,
    expected: 'verify-ok',
  },
  {
    name: 'absence-declared',
    note: 'A `none` receipt over a response carrying no marking. The region is the empty input and `d` is sha256 over zero bytes, which is why the absence is a value the field holds rather than a member left out.',
    sch: 'none',
    shape: 'buffered',
    response: CLEAN_BODY,
    attested: '',
    found: '',
    expected: 'verify-ok',
  },
  {
    name: 'absence-declared-over-marked',
    note: 'The same `none` attestation over a response that does carry a marked region, which is what a backend that marks its own output leaves a deployment that marks nothing. The label declares that no region of these bytes is marked and the bytes disagree with it.',
    sch: 'none',
    shape: 'buffered',
    response: MARKED_BODY.response,
    attested: '',
    found: null,
    expected: 'MARK_MISMATCH',
  },
  {
    name: 'region-stripped',
    note: 'The member deleted from a response that was served with it, `d` left as the digest of the span that went away. A reader holding these bytes finds no region at all, and zero candidates is a refusal rather than an empty span to hash.',
    sch: 'provenance-v1',
    shape: 'buffered',
    response: CLEAN_BODY,
    attested: MARKED_BODY.region,
    found: null,
    expected: 'MARK_MISMATCH',
  },
  {
    name: 'region-substituted',
    note: 'A well-formed marking member carrying a marking time an hour off from the one the receipt digested: exactly one region, found as the rule says to find it, hashing to something else. This is the case the region digest exists for, and it is the one the response digest cannot see.',
    sch: 'provenance-v1',
    shape: 'buffered',
    response: markedBuffered(substitutedMember()).response,
    attested: MARKED_BODY.region,
    found: substitutedMember(),
    expected: 'MARK_MISMATCH',
  },
  {
    name: 'region-duplicated',
    note: 'Two marking members at the top level of one body, which is the shape of a response somebody appended a mark to. The rule names exactly one candidate and refuses rather than taking the first or the last, so no port is entitled to choose.',
    sch: 'provenance-v1',
    shape: 'buffered',
    response: TWICE_BODY.response,
    attested: memberText(),
    found: null,
    expected: 'MARK_MISMATCH',
  },
  {
    name: 'streamed-region-stripped',
    note: 'The streaming shape with its marking frame removed and the frame\'s digest still attested: the four content chunks and the sentinel are untouched, and what is missing is one line of a stream a reader has to walk.',
    sch: 'provenance-v1',
    shape: 'streamed',
    response: CLEAN_STREAM,
    attested: MARKED_STREAM.region,
    found: null,
    expected: 'MARK_MISMATCH',
  },
  {
    name: 'streamed-region-duplicated',
    note: 'Two frames whose payload is an empty-`choices` chunk with the member beside it, which is a stream a backend that marks itself and a gateway that marks both produce.',
    sch: 'provenance-v1',
    shape: 'streamed',
    response: TWICE_STREAM.response,
    attested: MARKED_STREAM.region,
    found: null,
    expected: 'MARK_MISMATCH',
  },
];

/** What a reader that implements the published rule owes each case, so the file cannot lie about itself. */
function verdictOf(one: MarkingCase): { found: string | null; code: 'verify-ok' | 'MARK_MISMATCH' } {
  try {
    return { found: new TextDecoder().decode(extractMarkedRegion(one.sch, encoded(one.response))), code: 'verify-ok' };
  } catch {
    return { found: null, code: 'MARK_MISMATCH' };
  }
}

function main() {
  for (const one of CASES) {
    const observed = verdictOf(one);
    let outcome = observed.code;
    if (outcome === 'verify-ok' && toHex(hashRequest(encoded(observed.found ?? ''))) !== toHex(hashRequest(encoded(one.attested)))) {
      // The region was found and its digest is not the attested one, which is the second way a
      // marking refuses and the only way a well-formed substitute does.
      outcome = 'MARK_MISMATCH';
    }
    if (outcome !== one.expected) {
      throw new Error(`${one.name}: the rule this file publishes answers ${outcome}, not the ${one.expected} it states`);
    }
    if (observed.found !== one.found) {
      throw new Error(`${one.name}: the rule locates a different span than this file says it does`);
    }
  }

  const vectors = CASES.map((one) => ({
    name: one.name,
    note: one.note,
    shape: one.shape,
    sch: one.sch,
    responseBase64Url: toBase64Url(encoded(one.response)),
    responseByteLength: encoded(one.response).length,
    attestedRegionBase64Url: toBase64Url(encoded(one.attested)),
    attestedRegionByteLength: encoded(one.attested).length,
    foundRegionBase64Url: one.found === null ? null : toBase64Url(encoded(one.found)),
    foundRegionByteLength: one.found === null ? null : encoded(one.found).length,
    dHex: toHex(hashRequest(encoded(one.attested))),
    expected: one.expected,
  }));

  writeFileSync(
    join(DATA, 'marking-v1.json'),
    JSON.stringify(
      {
        version: 1,
        description:
          'The marked region a receipt digests in `mk.d`, for both response shapes, and the refusals the published rule owes a response that carries too few, too many, or not the attested one.',
        rule: {
          registry: 'docs/receipt-spec.md section 3.3',
          executable: 'extractMarkedRegion in @ashaveri/receipt',
          schemes: [...MARKING_SCHEMES],
          digestField: 'mk.d',
          algorithm: 'sha256',
          input: 'the marked region exactly as the response bytes carry it, and nothing beside it',
          candidates: 'exactly one region matching the label shape, or the response is refused',
          member: {
            name: '"ashaveri"',
            sch: 'ashaveri/provenance-v1',
            gen: 'ai',
            at: MARKING_AT,
            note: 'The member is serialized JSON text inside the response, and it is that text, byte for byte, that is hashed.',
          },
          encodings: 'byte strings unpadded base64url, digests lowercase hex',
          note: 'A region is a span of bytes inside the response and is published beside it rather than reconstructed: an implementation that re-serializes the member has hashed different bytes. The empty region of `none` is zero bytes, so its digest is sha256 over an empty input.',
        },
        vectors,
      },
      null,
      2,
    ) + '\n',
  );

  for (const one of vectors) console.log(`${one.name}: ${one.expected} ${one.dHex}`);
}

main();
