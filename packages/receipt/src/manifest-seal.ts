import { ed25519 } from '@noble/curves/ed25519';
import { Tag } from 'cbor2';
import { decodeCanonical, decodeClosedDocument, decodedMap, encodeCanonical } from './cbor.js';
import {
  ALG_EDDSA,
  COSE_HEADER_ALG,
  COSE_HEADER_CONTENT_TYPE,
  COSE_HEADER_KID,
  COSE_SIGN1_TAG,
  buildProtectedHeader,
  keyId,
  equalBytes,
  sealCoseSign1,
  type ProtectedHeader,
  type SigningKey,
} from './cose.js';
import { ReceiptError } from './errors.js';

/**
 * The signed deployment manifest: the same JSON document a gateway has always served at
 * `/deployment-manifest`, inside a COSE_Sign1 whose protected content type names it.
 *
 * This module owns the envelope and nothing else. It never reads the document inside it, because
 * what the manifest means is the SDK's question and what these bytes are is the format's; a reader
 * that had to understand issuers and key epochs in order to check a signature could not be run by
 * anybody who only wanted to know whether the bytes were whole. `manifest.cddl` is the normative
 * statement of this layout and `schemas/manifest-v1.schema.json` its JSON twin.
 *
 * The envelope is the receipt's, unchanged but for the content type, and that is the reason this
 * file exists next to `cose.ts` rather than inside it. A deployment signs receipts with one key and
 * manifests with another, and both documents are COSE_Sign1 over four elements, so the field that
 * tells them apart is the protected `typ`. `parseProtectedHeader` in `cose.ts` refuses every content
 * type but the receipt's for exactly that reason, and a reader that took a manifest for a receipt
 * would verify a signature over a deployment's claims and report it as an attestation about one
 * response. Both documents pass and only one of them means what it was read as.
 */

/** The protected content type that names this document, in the family `ashaveri/receipt` starts. */
export const DEPLOYMENT_MANIFEST_CONTENT_TYPE = 'ashaveri/deployment-manifest';

/**
 * The labels `manifest.cddl` declares for this document's protected header. The same three integers
 * the receipt declares, because they are the COSE registry's rather than this format's, restated here
 * because which of them a reader of *this* envelope expects is this file's answer.
 */
const DECLARED_LABELS: readonly number[] = [COSE_HEADER_ALG, COSE_HEADER_CONTENT_TYPE, COSE_HEADER_KID];

/** One CBOR tag byte, and the whole of the sniff: major type 6 with initial value 18 is tag 18. */
const COSE_SIGN1_FIRST_BYTE = 0xd2;

/** The decoded envelope, with the payload left as the bytes that were signed. */
export interface ManifestSeal {
  readonly protectedBytes: Uint8Array;
  readonly header: ProtectedHeader;
  /** The deployment manifest document, byte for byte as the issuer signed it. */
  readonly payloadBytes: Uint8Array;
  readonly signature: Uint8Array;
}

/**
 * Whether these bytes are a sealed manifest rather than the plain JSON document.
 *
 * One byte decides it, and the decision is safe in both directions: a JSON document cannot begin with
 * `0xd2`, because the first non-whitespace byte of any JSON text is one of `{ [ " -` or a digit and
 * whitespace is all below `0x21`, while every COSE_Sign1 written by `sealDeploymentManifest` begins
 * with the tag. A reader that asked the question this way cannot be talked into the wrong branch by a
 * `content-type` header the sender chose, which matters because the offline verifier reads these bytes
 * out of a file that names no content type at all.
 */
export function isSealedDeploymentManifest(bytes: Uint8Array): boolean {
  return bytes.length > 0 && bytes[0] === COSE_SIGN1_FIRST_BYTE;
}

/**
 * The `Sig_structure` of RFC 9052 section 4.4, built exactly as `cose.ts` builds it for a receipt:
 * the context string, the protected bstr as the issuer wrote it, the external AAD, and the payload
 * bstr. Reproduced rather than imported because the function in `cose.ts` is private and the two
 * documents are signed over the same structure by design; a divergence here would be a format
 * defect, and `manifest-seal.test.ts` in the SDK holds this against the receipt's own builder.
 */
function sigStructure(protectedBytes: Uint8Array, externalAad: Uint8Array, payloadBytes: Uint8Array): Uint8Array {
  return encodeCanonical(['Signature1', protectedBytes, externalAad, payloadBytes]);
}

/**
 * The protected header, which is the receipt's own three labels with this document's name in label 3.
 * `manifest.cddl` says so in as many words, and the SDK's seal test holds the bytes against what
 * `signCoseSign1` writes rather than against a list of labels, so the shared builder is the honest
 * source: the one field this format owns is the content type.
 */
function protectedHeaderFor(kid: Uint8Array): Uint8Array {
  return buildProtectedHeader(kid, DEPLOYMENT_MANIFEST_CONTENT_TYPE);
}

/**
 * Wrap the manifest document in a COSE_Sign1 and sign it.
 *
 * `manifestBytes` are signed as handed over: no re-encode, no key sorting, no whitespace decision. A
 * gateway serves the JSON it writes, and the only way a client's verdict means anything about the
 * bytes it read is for the signature to cover those bytes rather than a canonical rendering of them.
 * That is also why a deployment that reformats its own document has to reseal it, which is the
 * behaviour an operator can check by hand.
 */
export function sealDeploymentManifest(
  manifestBytes: Uint8Array,
  key: SigningKey,
  externalAad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  if (key.kid.length !== 32 || key.privateKey.length !== 32 || key.publicKey.length !== 32) {
    throw new ReceiptError('BAD_SIGNING_KEY', 'a manifest signing key is a 32-byte Ed25519 key and a 32-byte kid');
  }
  if (!equalBytes(keyId(key.publicKey), key.kid)) {
    throw new ReceiptError('BAD_SIGNING_KEY', 'the kid of a manifest signing key is sha256 of its public key');
  }
  const protectedBytes = protectedHeaderFor(key.kid);
  const toSign = sigStructure(protectedBytes, externalAad, manifestBytes);
  const signature = ed25519.sign(toSign, key.privateKey);
  // The shared framing, with its empty `unprotected` map: `manifest.cddl` declares that map as one a
  // writer may fill, and this writer has nothing to put in it, since a claim about a deployment belongs
  // inside the signed payload and not beside it.
  return sealCoseSign1(protectedBytes, manifestBytes, signature);
}

function parseHeader(bytes: Uint8Array): ProtectedHeader {
  const raw = decodedMap(decodeClosedDocument(bytes, 'BAD_PROTECTED_HEADER'));
  if (raw === null) throw new ReceiptError('BAD_PROTECTED_HEADER', 'not a map');
  // Closed, and for the receipt's reason plus one true only here: these bytes are inside the
  // signature, so a label this format does not name is an authenticated parameter and a reader that
  // walked past it would be holding a different document from the one the deployment signed.
  for (const label of raw.keys()) {
    if (!(DECLARED_LABELS as readonly unknown[]).includes(label)) {
      throw new ReceiptError('BAD_PROTECTED_HEADER', `it carries a label the format does not define: ${String(label)}`);
    }
  }
  const alg = raw.get(COSE_HEADER_ALG);
  if (typeof alg !== 'number') throw new ReceiptError('UNSUPPORTED_ALG', `alg must be an integer label, got ${typeof alg}`);
  if (alg !== ALG_EDDSA) throw new ReceiptError('UNSUPPORTED_ALG', `alg=${alg}`);
  const kid = raw.get(COSE_HEADER_KID);
  if (!(kid instanceof Uint8Array) || kid.length !== 32) {
    throw new ReceiptError('BAD_PROTECTED_HEADER', 'kid must be a 32-byte bstr');
  }
  const contentType = raw.get(COSE_HEADER_CONTENT_TYPE);
  if (typeof contentType !== 'string') {
    throw new ReceiptError('BAD_PROTECTED_HEADER', `typ must be a tstr, got ${typeof contentType}`);
  }
  if (contentType !== DEPLOYMENT_MANIFEST_CONTENT_TYPE) {
    throw new ReceiptError('BAD_PROTECTED_HEADER', `typ=${contentType}`);
  }
  return { alg: ALG_EDDSA, kid, contentType };
}

/**
 * Read the envelope without deciding anything about the key.
 *
 * The refusal of a document that is not a sealed manifest is the format's: `NOT_COSE_SIGN1` for
 * anything that is not tag 18 over four elements, and `BAD_PROTECTED_HEADER` once it is, including
 * the case that matters most, a valid receipt or pack handed to this reader. `verifyCoseSign1` refuses
 * a manifest for the same reason in the other direction, so the two documents cannot be confused by a
 * reader that reaches for either one.
 */
export function decodeSealedDeploymentManifest(bytes: Uint8Array): ManifestSeal {
  const top = decodeCanonical(bytes, 'MALFORMED_CBOR');
  if (!(top instanceof Tag) || top.tag !== COSE_SIGN1_TAG) {
    throw new ReceiptError('NOT_COSE_SIGN1', 'a sealed manifest is not CBOR tag 18');
  }
  const arr = top.contents;
  if (!Array.isArray(arr) || arr.length !== 4) throw new ReceiptError('NOT_COSE_SIGN1', 'not a 4-element array');
  const [protectedBytes, unprotectedMap, payloadBytes, signature] = arr as unknown[];
  if (!(protectedBytes instanceof Uint8Array)) throw new ReceiptError('NOT_COSE_SIGN1', 'protected is not a bstr');
  if (decodedMap(unprotectedMap) === null) throw new ReceiptError('NOT_COSE_SIGN1', 'unprotected is not a map');
  if (!(payloadBytes instanceof Uint8Array)) throw new ReceiptError('NOT_COSE_SIGN1', 'payload is not a bstr');
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new ReceiptError('NOT_COSE_SIGN1', 'signature is not a 64-byte bstr');
  }
  return { protectedBytes, header: parseHeader(protectedBytes), payloadBytes, signature };
}

/**
 * Decode and verify, and hand back the document bytes the signature covers.
 *
 * The key comes from the caller, which is the whole of the trust question and why it is not asked
 * here: a sealed manifest names no public key for itself, because a document that vouched for its own
 * signer would vouch for anything. `kid` is still checked against the key handed in, and the check is
 * the strict RFC 8032 rule `cose.ts` keeps to for the same reason, that the key an operator pasted
 * into a policy is untrusted input until the signature says otherwise.
 */
export function verifySealedDeploymentManifest(
  bytes: Uint8Array,
  publicKey: Uint8Array,
  externalAad: Uint8Array = new Uint8Array(0),
): ManifestSeal {
  const seal = decodeSealedDeploymentManifest(bytes);
  if (!equalBytes(seal.header.kid, keyId(publicKey))) throw new ReceiptError('KID_MISMATCH');
  const toSign = sigStructure(seal.protectedBytes, externalAad, seal.payloadBytes);
  if (!ed25519.verify(seal.signature, toSign, publicKey, { zip215: false })) {
    throw new ReceiptError('INVALID_SIGNATURE');
  }
  return seal;
}
