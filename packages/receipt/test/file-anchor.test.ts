import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { FILE_ANCHOR_MEMBER_NAME, MARKING_MEMBER_NAME, verifyFileAnchor } from '../src/index.js';

/**
 * The reading half of a file anchor: a digest a client computed before it uploaded anything, weighed
 * against bytes a verifier was handed afterwards.
 *
 * The three answers are what this suite is shaped around, because a reader that reports an absence as
 * a disagreement, or a disagreement as an absence, tells a verifier something about a conversation
 * that never happened. A match here says the request stated this digest and these bytes are that
 * digest. It says nothing about who held the file, and nothing about whether a provider read it.
 *
 * Every expectation below is a value spelled out in this file. No case asks what the reader says about
 * bytes by asking what the reader said about other bytes, and none takes its expected digest from the
 * hashing under test: the two digests are literals produced over their own bytes away from this
 * repository, checked against `node:crypto`, a second implementation, in the cases that use them.
 */

const FILE = new TextEncoder().encode('a recording of the conversation, in full');
const OTHER_FILE = new TextEncoder().encode('a recording of the conversation, in part');

/** sha256 from `node:crypto`, used only where a literal would be too long to read. */
function otherSha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * The digests of the two fixtures above, written down rather than computed here. Each was produced
 * over those exact bytes by `node:crypto`; this package reaches its hex through `@noble/hashes`, so
 * what a match witnesses is two implementations agreeing over fixed bytes rather than one function
 * returning what it returns.
 */
const FILE_SHA256_HEX = '7d4214c1df232f32b9e6935af6a7a422de12cdfecd6ba35a9b11f43113e52e45';
const OTHER_FILE_SHA256_HEX = '70613f5e0981e52cba4d2a6cbba1e00534292f0fadb4ea750c8c9c37b81a7362';

const COMPLETE_CLAIM = { sha256: FILE_SHA256_HEX, bytes: FILE.byteLength, media_type: 'audio/wav' };

/** The namespace member as one body states it, with the fields a caller can get wrong written wrong. */
function memberStaking(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { file: { ...COMPLETE_CLAIM, ...over } };
}

/** One chat completion body stating a member, everything else in it irrelevant to this reader. */
function bodyStaking(member: unknown): string {
  return JSON.stringify({
    model: 'a-model',
    messages: [{ role: 'user', content: 'what is in this file?' }],
    [FILE_ANCHOR_MEMBER_NAME]: member,
  });
}

const ANCHORED_BODY = bodyStaking(memberStaking());

/** The answer for the claim above met by the bytes it names. */
const MATCH = { status: 'match', sha256: FILE_SHA256_HEX, bytes: FILE.byteLength };

/** The answer for a claim stated in a shape no verifier can weigh: no text of its own is quoted back. */
const UNWEIGHABLE = {
  status: 'mismatch',
  computedSha256: FILE_SHA256_HEX,
  computedBytes: FILE.byteLength,
  claimedSha256: null,
  claimedBytes: null,
};

describe('a verifier holding the file a request claimed', () => {
  it('reaches the digest written down for these bytes, and the digest is not its own doing', () => {
    // The literal above came from `node:crypto` over the fixture bytes, away from this repository, and
    // the line below is that check run in the open. The claim in the body was written with the same
    // literal, so a `match` here is the reader's hex agreeing with an outside implementation.
    expect(otherSha256Hex(FILE)).toBe(FILE_SHA256_HEX);
    expect(verifyFileAnchor(ANCHORED_BODY, FILE)).toEqual(MATCH);
  });

  it('takes the body as bytes as readily as it takes it as text', () => {
    // Both spellings of the body are weighed against the answer written out above, because a case that
    // asks whether the bytes form agrees with the text form would agree whatever the reader returned.
    expect(verifyFileAnchor(new TextEncoder().encode(ANCHORED_BODY), FILE)).toEqual(MATCH);
    expect(verifyFileAnchor(ANCHORED_BODY, FILE)).toEqual(MATCH);
  });

  it('tolerates a disclosed filename without letting it move the answer', () => {
    expect(verifyFileAnchor(bodyStaking(memberStaking({ name: 'session-12.wav' })), FILE)).toEqual(MATCH);
  });
});

describe('a verifier handed some other file', () => {
  it('reports the disagreement, at the very length the claim states, and never a match', () => {
    // Same byte count, different content: a reader that weighed only the length would call this a
    // match, which is the mistake this case exists to make impossible.
    expect(OTHER_FILE.byteLength).toBe(FILE.byteLength);
    expect(otherSha256Hex(OTHER_FILE)).toBe(OTHER_FILE_SHA256_HEX);
    expect(verifyFileAnchor(ANCHORED_BODY, OTHER_FILE)).toEqual({
      status: 'mismatch',
      computedSha256: OTHER_FILE_SHA256_HEX,
      computedBytes: OTHER_FILE.byteLength,
      claimedSha256: FILE_SHA256_HEX,
      claimedBytes: FILE.byteLength,
    });
  });

  it('reports the disagreement when the claim states the right digest and the wrong length', () => {
    expect(verifyFileAnchor(bodyStaking(memberStaking({ bytes: FILE.byteLength + 1 })), FILE)).toEqual({
      status: 'mismatch',
      computedSha256: FILE_SHA256_HEX,
      computedBytes: FILE.byteLength,
      claimedSha256: FILE_SHA256_HEX,
      claimedBytes: FILE.byteLength + 1,
    });
  });

  it('reports a claim no verifier can weigh as a disagreement rather than as an absence', () => {
    // Sixty-four uppercase characters are the same number as the digest and a different statement:
    // the claim this member declares is lowercase, and reading the two as agreeing would be reading
    // a hex spelling rather than a digest. The guard below says this fixture's digest carries the
    // letters that make that sentence true rather than sixty digits that would make it empty.
    expect(FILE_SHA256_HEX).not.toBe(FILE_SHA256_HEX.toUpperCase());
    const cases: readonly string[] = [
      FILE_SHA256_HEX.toUpperCase(),
      FILE_SHA256_HEX.slice(0, 63),
      FILE_SHA256_HEX.padEnd(65, '0'),
      'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz',
    ];
    for (const digest of cases) {
      expect(verifyFileAnchor(bodyStaking(memberStaking({ sha256: digest })), FILE), digest).toEqual(UNWEIGHABLE);
    }
  });

  it('refuses a length that is not a whole number a JSON reader reproduces exactly', () => {
    for (const bytes of [1.5, -3, '40', null]) {
      expect(verifyFileAnchor(bodyStaking(memberStaking({ bytes })), FILE), String(bytes)).toEqual(UNWEIGHABLE);
    }
    // A count written past the width a reader holds exactly is the one refusal no object literal can
    // state, because the literal is the number before it reaches the text: the body is written out.
    const wide = ANCHORED_BODY.replace(`"bytes":${FILE.byteLength}`, '"bytes":123456789012345678901234567890');
    expect(wide).not.toBe(ANCHORED_BODY);
    expect(verifyFileAnchor(wide, FILE)).toEqual(UNWEIGHABLE);
  });

  it('refuses a claim that declares no media type, and one that declares it as something else', () => {
    for (const member of [memberStaking({ media_type: undefined }), memberStaking({ media_type: 4 })]) {
      expect(verifyFileAnchor(bodyStaking(member), FILE)).toEqual(UNWEIGHABLE);
    }
  });
});

describe('a verifier handed a claim no client can state', () => {
  /** The digest of no bytes at all, written down like the two above and for the same reason. */
  const EMPTY_SHA256_HEX = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const NO_BYTES = new Uint8Array(0);

  it('refuses a length of nothing and a declaration of nothing, which the writer also refuses', () => {
    for (const over of [{ bytes: 0 }, { media_type: '' }]) {
      expect(verifyFileAnchor(bodyStaking(memberStaking(over)), FILE), JSON.stringify(over)).toEqual(UNWEIGHABLE);
    }
  });

  it('does not reach a match on the one body an empty file and an empty claim used to agree to', () => {
    // Both sides of that comparison were true at once: these bytes are nothing, and the claim said
    // they were nothing. The format refuses the claim, because a claim of no file states no file, so
    // the answer here is the disagreement the shape earns rather than a pass over a member no client
    // ever sent. `packages/sdk/test/file-anchor.test.ts` asks the writer the same question.
    expect(otherSha256Hex(NO_BYTES)).toBe(EMPTY_SHA256_HEX);
    expect(verifyFileAnchor(bodyStaking(memberStaking({ sha256: EMPTY_SHA256_HEX, bytes: 0, media_type: 'audio/wav' })), NO_BYTES)).toEqual({
      status: 'mismatch',
      computedSha256: EMPTY_SHA256_HEX,
      computedBytes: 0,
      claimedSha256: null,
      claimedBytes: null,
    });
  });
});

describe('a verifier handed a request that claimed nothing', () => {
  it('names each absence it met rather than throwing, and never calls one a match', () => {
    const withoutNamespace = JSON.stringify({ model: 'a-model', messages: [{ role: 'user', content: 'hi' }] });
    const cases: readonly (readonly [string, string, 'no-member' | 'no-claim'])[] = [
      ['a body that names no namespace at all', withoutNamespace, 'no-member'],
      ['a namespace holding something else', bodyStaking({ other: 1 }), 'no-claim'],
      ['a namespace holding a mark and no claim', bodyStaking({ marking: { sch: 'ashaveri/provenance-v1', gen: 'ai', at: 1 } }), 'no-claim'],
      ['a namespace holding an empty object', bodyStaking({}), 'no-claim'],
      ['a namespace stated as text', bodyStaking('a note'), 'no-claim'],
      ['a namespace stated as a list', bodyStaking([COMPLETE_CLAIM]), 'no-claim'],
    ];
    for (const [where, body, reason] of cases) {
      expect(verifyFileAnchor(body, FILE), where).toEqual({ status: 'absent', reason });
    }
  });

  it('holds the marking member and the file claim apart, which is what the shared namespace needs', () => {
    // The response marking rule reads a `marking` object under this same top-level name and refuses
    // to see anything else there; this reader does the mirror of that, so neither format can borrow
    // the other's name for a claim it never made.
    const marked = bodyStaking({ marking: { sch: 'ashaveri/provenance-v1', gen: 'ai', at: 1 } });
    expect(MARKING_MEMBER_NAME).toBe(FILE_ANCHOR_MEMBER_NAME);
    expect(verifyFileAnchor(marked, FILE)).toEqual({ status: 'absent', reason: 'no-claim' });
    expect(verifyFileAnchor(ANCHORED_BODY, FILE)).toEqual(MATCH);
  });

  it('reads a body that is not one JSON object as an absence it names', () => {
    for (const body of ['not json at all', '', '[1,2,3]', '{"ashaveri":']) {
      expect(verifyFileAnchor(body, FILE)).toEqual({ status: 'absent', reason: 'body-is-not-a-json-object' });
    }
  });
});
