import { sha256Hex, type FileAnchorMember } from '@ashaveri/receipt';

/**
 * The client's half of a file anchor, and the only half that decides what the evidence can later be
 * read as.
 *
 * Nothing here sends anything. The value produced is written into the caller's own request body,
 * which is what lets one claim cover a file that travels inside that body and a file that travelled
 * out of band to a provider's upload endpoint and came back as an identifier: in both cases the body
 * is what the gateway digests, so in both cases the claim arrives inside the signed evidence without
 * a byte of the file passing through anybody's gateway.
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
 * Refused here are the two inputs that cannot state a claim at all, no bytes and a length no JSON
 * reader reproduces exactly, and the two declarations that would state an empty one. What is not
 * refused is anything about the file: its name is the caller's to disclose, its media type is the
 * caller's to declare, and its bytes never need to reach this process again.
 */
export function fileAnchor(file: Uint8Array, mediaType: string, options: FileAnchorOptions = {}): FileAnchorMember {
  const byteCount = file.byteLength;
  if (!Number.isSafeInteger(byteCount)) {
    throw new TypeError(`a file anchor states its length as a whole number a JSON reader reproduces, got ${String(byteCount)}`);
  }
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
