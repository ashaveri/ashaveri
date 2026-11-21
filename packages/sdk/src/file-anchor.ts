import { sha256Hex, type FileAnchorMember } from '@ashaveri/receipt';

/**
 * The client's half of a file anchor, and the only half that decides what the evidence can later be
 * read as.
 *
 * Nothing here sends anything. The value produced is written into the caller's own request body,
 * which is what lets one claim cover two sorts of file: one that travels inside that body, and one
 * that travelled out of band to a provider's upload endpoint and came back as an identifier. For the
 * out-of-band file, no byte of it passes through anybody's gateway, and the claim inside the signed
 * request is all the evidence says about it. For the file inside the body, the bytes do pass through
 * the gateway, and what the claim buys is narrower: that the caller digested these bytes before it
 * wrote the request, and that the digest it stated is fixed by the signature over the body. It is
 * not proof of what those bytes are, and a verifier holding the file is still the one that compares.
 *
 * The digest is the SHA-256 this estate already computes, taken from the package that will recompute
 * it for a verifier. Two implementations of one hash agree until one of them is reached by another
 * runtime, and a claim that stops agreeing with its own verification is a claim that stops meaning
 * anything.
 */

export interface FileAnchorOptions {
  /**
   * A filename, disclosed only where the client chooses to disclose one. Absent by default, because a
   * name is personal data about whoever saved the file, and a parameter a caller has to fill is a
   * parameter that gets filled.
   */
  readonly name?: string;
}

/**
 * The claim one file makes on a request: its digest, its length, and what the client says it is.
 *
 * Refused here is the input that cannot state a claim at all, no bytes, and the two declarations
 * that would state an empty one, a media type of nothing and a name of nothing. The length needs no
 * guard: `byteLength` is a whole count of the bytes in hand, so no call that reaches this function
 * with a `Uint8Array` can bring a length a JSON reader would not reproduce. A call that brings
 * something shaped like one is refused by the digest itself, which takes bytes and nothing else.
 * What is not refused is anything about the file: its name is the caller's to disclose, its media
 * type is the caller's to declare, and its bytes never need to reach this process again.
 */
export function fileAnchor(file: Uint8Array, mediaType: string, options: FileAnchorOptions = {}): FileAnchorMember {
  const byteCount = file.byteLength;
  if (byteCount === 0) {
    throw new TypeError('a file anchor claims the digest of a file, and these are no bytes at all');
  }
  if (mediaType.length === 0) {
    throw new TypeError('a file anchor states the media type the client declares for these bytes, and none is declared');
  }
  const claim: FileAnchorMember['file'] = { sha256: sha256Hex(file), bytes: byteCount, media_type: mediaType };
  if (options.name === undefined) {
    return { file: claim };
  }
  if (options.name.length === 0) {
    throw new TypeError('a disclosed filename is text about a file, or it discloses nothing and is not given');
  }
  return { file: { ...claim, name: options.name } };
}
