import { sha256Hex } from './pop.js';

/**
 * The file anchor: a claim, made by the client inside the request body, that a file it did not send
 * has a stated digest.
 *
 * The gateway hashes the bytes it read and signs that digest as `req`, and a buffered body goes on to
 * its upstream as those same bytes, so a claim written into the body is inside the signed evidence the
 * moment a client sends it. Nothing here interprets it: the deployment reads `model`, `messages` and
 * `stream` out of a chat completion and says nothing about the rest, which is why this file is a reader
 * on the verification side and a shape on the client side rather than a rule a gateway enforces. The
 * streamed arm re-serializes the body to ask its upstream for a usage frame, which carries this member
 * along and is stated, with what it costs, in `docs/file-anchor-v1.md`.
 *
 * What a match reaches is therefore narrower than it first reads. It says this request carried this
 * claimed digest. It does not say the digest is that of the file a person held, and it does not say
 * the provider read any file at all: a verifier holding the file recomputes and compares, and a
 * verifier holding only the receipt can say the claim was made, not that it was true. The two
 * readings are kept apart in every sentence below, because collapsing them is the one way this field
 * could mislead somebody who trusts it.
 *
 * The namespace is the one a marked response also writes into, and the two are not the same member:
 * the marking rule in `marking.ts` reads a `marking` object of a scheme it names, and refuses to see
 * anything else under the name, so a `file` claim is never mistaken for a mark and a mark is never
 * mistaken for a claim. The two spellings are kept apart on purpose: they belong to two documents
 * travelling in two directions, and a change to one of those names is a change to the other's format
 * if they are shared.
 */

/** The top-level request member a file claim travels in. */
export const FILE_ANCHOR_MEMBER_NAME = 'ashaveri';

/** The member of that namespace holding one file's claim. */
export const FILE_ANCHOR_CLAIM_MEMBER_NAME = 'file';

/** The digest the client computed before it handed the file to anybody else, as lowercase hex. */
export interface FileAnchorClaim {
  readonly sha256: string;
  /**
   * The decoded length of those bytes, as a whole number that a JSON reader reproduces exactly. A
   * length of nothing is outside the shape: a claim of no bytes states no file, and the client's own
   * writer refuses to produce one, so this reader weighs none either.
   */
  readonly bytes: number;
  /**
   * What the client says the bytes are. Declared, never weighed: nothing here opens a media type. A
   * declaration of empty text declares nothing, which is the one thing this shape has no room for.
   */
  readonly media_type: string;
  /**
   * Absent unless the client chooses to disclose a filename. A name is personal data about whoever
   * saved the file, and a field that is easy to fill is a field that gets filled, so it is stated
   * here as what the reader tolerates and the writer declines by default.
   */
  readonly name?: string;
}

/** The value of the top-level member: one file claim, beside whatever else the client namespaces. */
export interface FileAnchorMember {
  readonly file: FileAnchorClaim;
}

/**
 * The three answers a verifier can be handed, named rather than inferred from a falsy value.
 *
 * `match` and `mismatch` are the two outcomes of one comparison. `absent` is not a third spelling of
 * `mismatch`: a request that stated no claim and a request that stated a claim these bytes disagree
 * with are two facts about a conversation, and the second one is the only place a file can be
 * contradicted. Reporting the first as the second would let a receipt that carries no claim at all
 * read as a receipt that refutes one.
 *
 * Each is a value and none is a thrown refusal, because the reader of an offline bundle is asked a
 * question about a file it may or may not hold, and an answer that arrives only when the answer is
 * favourable is not an answer. The refusal codes in `errors.ts` name what a document is; these name
 * what a comparison came to.
 */
export interface FileAnchorMatch {
  readonly status: 'match';
  /** The digest both sides reach, spelled the way the claim spells it. */
  readonly sha256: string;
  readonly bytes: number;
}

export interface FileAnchorMismatch {
  readonly status: 'mismatch';
  /** What these bytes are. */
  readonly computedSha256: string;
  readonly computedBytes: number;
  /**
   * What the request stated, or null where the statement is not in the shape this member declares.
   * A digest that is not sixty-four lowercase hex characters, a length that is not a whole number a
   * JSON reader reproduces, a length of nothing, and a media type that is not text or is empty cannot
   * agree with a recomputation and are reported as the disagreement they are rather than as an
   * absence: the claim was made, and it was made in a shape no verifier can weigh.
   */
  readonly claimedSha256: string | null;
  readonly claimedBytes: number | null;
}

/** The ways a request carries no claim to weigh, kept apart because a reader quotes them. */
export type FileAnchorAbsence =
  /** The body is not one JSON object, so it states no member of any namespace. */
  | 'body-is-not-a-json-object'
  /** The object holds no member under this namespace at all. */
  | 'no-member'
  /** The member is there and holds no file claim beside it. */
  | 'no-claim';

export interface FileAnchorAbsent {
  readonly status: 'absent';
  readonly reason: FileAnchorAbsence;
}

export type FileAnchorVerdict = FileAnchorMatch | FileAnchorMismatch | FileAnchorAbsent;

/** The bytes a request body arrived as: the text the client wrote, or its encoding. */
export type FileAnchorRequestBody = Uint8Array | string;

const DIGEST = /^[0-9a-f]{64}$/u;

function textOf(body: FileAnchorRequestBody): string {
  return typeof body === 'string' ? body : new TextDecoder().decode(body);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The file claim inside this namespace's member, in the shape a verifier can weigh, or null when what
 * the body states is not such a statement. Nothing is assumed from a claim to save a comparison: a
 * digest that is not lowercase hex of sixty-four characters, a length spelled as a fraction, a length
 * of nothing or a number past what a JSON reader reproduces exactly, and a media type that is not
 * text or declares nothing all answer null, which is a claim that cannot agree with a recomputation
 * and so a disagreement, not an absence.
 *
 * The two refusals that are not about spelling refuse the same claims the client's own writer refuses,
 * and the pair is witnessed on both sides in `packages/sdk/test/file-anchor.test.ts`: a reader that
 * weighed a claim no writer can state would report a `match` on a member no client ever sent, and a
 * verifier's answer would then be about a document that cannot exist.
 */
function weighableClaim(member: unknown): FileAnchorClaim | null {
  if (!isObject(member)) return null;
  const file = member[FILE_ANCHOR_CLAIM_MEMBER_NAME];
  if (!isObject(file)) return null;
  const sha256 = file['sha256'];
  const bytes = file['bytes'];
  const mediaType = file['media_type'];
  if (typeof sha256 !== 'string' || !DIGEST.test(sha256)) return null;
  if (typeof bytes !== 'number' || !Number.isSafeInteger(bytes) || bytes <= 0) return null;
  if (typeof mediaType !== 'string' || mediaType.length === 0) return null;
  const name = file['name'];
  return typeof name === 'string' ? { sha256, bytes, media_type: mediaType, name } : { sha256, bytes, media_type: mediaType };
}

/** The claim a namespace member states, or undefined when it states none and there is nothing to weigh. */
function statedClaim(member: unknown): unknown {
  return isObject(member) ? member[FILE_ANCHOR_CLAIM_MEMBER_NAME] : undefined;
}

/**
 * Weigh the file anchor of one request body against the bytes a verifier was given.
 *
 * The body handed here has to be the body whose digest the receipt carries in `req`, and that binding
 * is the caller's own check: this function reads a claim and compares digests, and says nothing about
 * whether the body in hand is the one a gateway signed. A verifier that skips that step is comparing
 * a claim somebody typed rather than a claim the receipt stands behind, and the answer it prints
 * cannot tell the two apart.
 *
 * The comparison is exact and case-sensitive on the digest, and the byte count has to agree too: a
 * claim that names the right sixty-four characters and the wrong length is a claim about two
 * different files, and calling that a match would be the one reading this field must not support.
 */
export function verifyFileAnchor(body: FileAnchorRequestBody, file: Uint8Array): FileAnchorVerdict {
  const text = textOf(body);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    return { status: 'absent', reason: 'body-is-not-a-json-object' };
  }
  if (!isObject(parsed)) {
    return { status: 'absent', reason: 'body-is-not-a-json-object' };
  }
  const member = parsed[FILE_ANCHOR_MEMBER_NAME];
  if (member === undefined) {
    return { status: 'absent', reason: 'no-member' };
  }
  const claim = statedClaim(member);
  if (claim === undefined) {
    return { status: 'absent', reason: 'no-claim' };
  }
  // A body that names this member twice is read the way any JSON reader reads it, as the entry that
  // came last. That is not a choice between two claims left standing here: two bodies that differ by
  // one member hash to two digests, so a verifier that weighed `req` first has already been told
  // which body a gateway signed, and a verifier that did not is reading a claim nothing stands behind.
  const computedSha256 = sha256Hex(file);
  const computedBytes = file.byteLength;
  const weighed = weighableClaim(member);
  if (weighed === null) {
    // The claim is there and says something this reader cannot weigh. Its own text is not carried
    // into the answer: a body is caller-chosen, and a verdict that quotes it quotes whatever the
    // body held into whatever prints the verdict.
    return { status: 'mismatch', computedSha256, computedBytes, claimedSha256: null, claimedBytes: null };
  }
  if (weighed.sha256 === computedSha256 && weighed.bytes === computedBytes) {
    return { status: 'match', sha256: computedSha256, bytes: computedBytes };
  }
  return {
    status: 'mismatch',
    computedSha256,
    computedBytes,
    claimedSha256: weighed.sha256,
    claimedBytes: weighed.bytes,
  };
}
