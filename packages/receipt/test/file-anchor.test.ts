import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { FILE_ANCHOR_MEMBER_NAME, MARKING_MEMBER_NAME, verifyFileAnchor } from '../src/index.js';

/**
 * The reading half of a file anchor: a digest a client computed before it uploaded anything, weighed
 * against bytes a verifier was handed afterwards.
 *
 * The three answers are what this suite is shaped around, because a reader that reports an absence as
 * a disagreement, or a disagreement as an absence, tells a verifier something about a conversation
 * that never happened. A match here says the request stated this digest and these bytes are that
 * digest. It says nothing about who held the file, and nothing about whether a provider read it.
 */

const FILE = new TextEncoder().encode('a recording of the conversation, in full');
const OTHER_FILE = new TextEncoder().encode('a recording of the conversation, in part');

/** The claim's digest, reached by the hash function directly rather than through this package's hex. */
const DIGEST = Array.from(sha256(FILE), (byte) => byte.toString(16).padStart(2, '0')).join('');

const COMPLETE_CLAIM = { sha256: DIGEST, bytes: FILE.byteLength, media_type: 'audio/wav' };

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

describe('a verifier holding the file a request claimed', () => {
  it('reaches the digest both sides compute, by the hash this package reaches its hex through', () => {
    // The claim above was digested by `@noble/hashes` taken straight from the dependency, and this
    // reader digests through `sha256Hex`, so a `match` is the witness that the two are one function
    // rather than two that happen to agree today.
    const verdict = verifyFileAnchor(ANCHORED_BODY, FILE);
    expect(verdict).toEqual({ status: 'match', sha256: DIGEST, bytes: FILE.byteLength });
  });

  it('takes the body as bytes as readily as it takes it as text', () => {
    expect(verifyFileAnchor(new TextEncoder().encode(ANCHORED_BODY), FILE)).toEqual(verifyFileAnchor(ANCHORED_BODY, FILE));
  });

  it('tolerates a disclosed filename without letting it move the answer', () => {
    expect(verifyFileAnchor(bodyStaking(memberStaking({ name: 'session-12.wav' })), FILE)).toEqual({
      status: 'match',
      sha256: DIGEST,
      bytes: FILE.byteLength,
    });
  });
});

describe('a verifier handed some other file', () => {
  it('reports the disagreement, at the very length the claim states, and never a match', () => {
    // Same byte count, different content: a reader that weighed only the length would call this a
    // match, which is the mistake this case exists to make impossible.
    expect(OTHER_FILE.byteLength).toBe(FILE.byteLength);
    const verdict = verifyFileAnchor(ANCHORED_BODY, OTHER_FILE);
    expect(verdict.status).toBe('mismatch');
    if (verdict.status !== 'mismatch') return;
    expect(verdict.claimedSha256).toBe(DIGEST);
    expect(verdict.computedSha256).not.toBe(DIGEST);
    expect(verdict.claimedBytes).toBe(verdict.computedBytes);
  });

  it('reports the disagreement when the claim states the right digest and the wrong length', () => {
    const verdict = verifyFileAnchor(bodyStaking(memberStaking({ bytes: FILE.byteLength + 1 })), FILE);
    expect(verdict.status).toBe('mismatch');
    if (verdict.status !== 'mismatch') return;
    expect(verdict.claimedSha256).toBe(DIGEST);
    expect(verdict.computedSha256).toBe(DIGEST);
    expect(verdict.claimedBytes).toBe(FILE.byteLength + 1);
    expect(verdict.computedBytes).toBe(FILE.byteLength);
  });

  it('reports a claim no verifier can weigh as a disagreement rather than as an absence', () => {
    // Sixty-four uppercase characters are the same number as the digest and a different statement:
    // the claim this member declares is lowercase, and reading the two as agreeing would be reading
    // a hex spelling rather than a digest. The guard below says this fixture's digest carries the
    // letters that make that sentence true rather than sixty digits that would make it empty.
    expect(DIGEST).not.toBe(DIGEST.toUpperCase());
    const cases: readonly string[] = [
      DIGEST.toUpperCase(),
      DIGEST.slice(0, 63),
      DIGEST.padEnd(65, '0'),
      'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz',
    ];
    for (const digest of cases) {
      const verdict = verifyFileAnchor(bodyStaking(memberStaking({ sha256: digest })), FILE);
      expect(verdict.status, digest).toBe('mismatch');
      if (verdict.status !== 'mismatch') continue;
      expect(verdict.claimedSha256, digest).toBeNull();
      expect(verdict.claimedBytes, digest).toBeNull();
    }
  });

  it('refuses a length that is not a whole number a JSON reader reproduces exactly', () => {
    for (const bytes of [1.5, -3, '40', null]) {
      const verdict = verifyFileAnchor(bodyStaking(memberStaking({ bytes })), FILE);
      expect(verdict.status, String(bytes)).toBe('mismatch');
    }
    // A count written past the width a reader holds exactly is the one refusal no object literal can
    // state, because the literal is the number before it reaches the text: the body is written out.
    const wide = ANCHORED_BODY.replace(`"bytes":${FILE.byteLength}`, '"bytes":123456789012345678901234567890');
    expect(wide).not.toBe(ANCHORED_BODY);
    expect(verifyFileAnchor(wide, FILE).status).toBe('mismatch');
  });

  it('refuses a claim that declares no media type, and one that declares it as something else', () => {
    for (const member of [memberStaking({ media_type: undefined }), memberStaking({ media_type: 4 })]) {
      expect(verifyFileAnchor(bodyStaking(member), FILE).status).toBe('mismatch');
    }
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
    expect(verifyFileAnchor(ANCHORED_BODY, FILE).status).toBe('match');
  });

  it('reads a body that is not one JSON object as an absence it names', () => {
    for (const body of ['not json at all', '', '[1,2,3]', '{"ashaveri":']) {
      expect(verifyFileAnchor(body, FILE)).toEqual({ status: 'absent', reason: 'body-is-not-a-json-object' });
    }
  });
});
