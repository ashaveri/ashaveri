import { p384 } from '@noble/curves/nist.js';
import { sha256, sha384 } from '@noble/hashes/sha2.js';
import { equalBytes, type ParsedCertificate } from '@ashaveri/attest-core';
import { fromBase64, sha256Hex, toHex } from './bytes.js';
import { collateralRefusal, quoteOrDigest, type CollateralRefusal } from './errors.js';
import { hasReader, isRimDeclaration, type OriginDeclaration } from './intel-origin.js';
import { decodeText, parseCertificates, parsePinned } from './read.js';
import {
  attributeOf,
  canonicalizeDocument,
  canonicalizeSubtree,
  childElements,
  collectElements,
  elementText,
  readXml,
  type XmlElement,
} from './xml.js';
import type { CollateralQuery, RimManifest } from './types.js';

/**
 * What a RIM answer states about itself, and the refusal that says how much of it was weighed.
 *
 * A `CORIM` or `GENERIC` answer still carries both halves when it parses: the wrapper is read, and the manifest
 * inside it is not weighed. A `TCG` manifest that holds is read alone, because there is nothing left to refuse:
 * the digest, the signature and the chain to a root the caller pinned were all established before a word of the
 * document was believed.
 */
export type RimReadOutcome =
  | { readonly read: RimManifest }
  | { readonly read: RimManifest; readonly refusal: CollateralRefusal }
  | { readonly refusal: CollateralRefusal };

/** The three formats NVIDIA's reference names for the member, stated apart so a refusal can quote the one met. */
const FORMATS = ['TCG', 'CORIM', 'GENERIC'];

/**
 * The profile this package weighs a `TCG` manifest against, in the identifiers that form is written in.
 *
 * The set is this path's own rule, stated here rather than read off a body, and it says what this reader accepts
 * and nothing about any vendor's posture or compliance: a manifest outside the set is refused as an unsupported
 * status naming the identifier met rather than distrusted silently, and a manifest inside it is still historical
 * knowledge about a reference document rather than a measurement match. Canonical XML 1.1 is the form the `TCG`
 * shape is written in, and that is why this profile names it: a reader written for the exclusive form refuses
 * every GPU manifest the route answers with, because a signed element that inherits its namespace declarations
 * has to render them at its own top, and the two spellings of one document then hash apart.
 */
export const RIM_TCG_PROFILE = {
  /** The canonicalization both the signed element and the transformed document are read under. */
  canonicalization: 'http://www.w3.org/2006/12/xml-c14n11',
  /** The suite the signature is written in, which is also the width of the key that writes it. */
  signatureMethod: 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
  /** The digest a whole-document reference is weighed with. */
  digestMethod: 'http://www.w3.org/2001/04/xmldsig-more#sha384',
  /** The transform chain a reference states, in the order it must be applied. */
  transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2006/12/xml-c14n11'],
  /** The namespace the signature's own elements are in. */
  signatureNamespace: 'http://www.w3.org/2000/09/xmldsig#',
  /** The namespace a document element has to be in for its tag identity to be read. */
  swidNamespace: 'http://standards.iso.org/iso/19770/-2/2015/schema.xsd',
  identityElement: 'SoftwareIdentity',
  identityAttribute: 'tagId',
  /** Bytes a SHA-384 writes, which is the only digest width this profile reads. */
  digestBytes: 48,
  /** The `r` and `s` of a 384-bit curve, each 48 bytes, which is how the served manifests write their value. */
  signatureBytes: 96,
  /** How many certificates one `KeyInfo` may present: the chain the served documents present is four deep. */
  maxChain: 4,
} as const;

/**
 * Reads the JSON wrapper a RIM route answers in, and weighs the `TCG` manifest it carries.
 *
 * The wrapper's members are the ones cited beside the declaration in `intel-origin.ts`: `id`, `last_updated`,
 * `rim`, `rim_format` and `sha256`. What this path establishes about them is only what the wrapper states about
 * itself: that the bytes in `rim` decode as base64 and hash to the digest the same body names, and that the id
 * the answer carries is the one the question asked for. A digest is not a signature: it says these are the bytes
 * the service meant to send, and nothing about who signed them or what the manifest stands for.
 *
 * The `TCG` form is then read as what it is: SWID XML signed in the form the profile above names. The manifest's
 * own certificates are read from inside the document, walked to a root the caller pinned, weighed at the instant
 * the question names, and the signature is taken over bytes built by the canonicalization the document states.
 * The `CORIM` form is served too, as CBOR carrying a COSE `Sign1`, and this path states no rule for weighing one,
 * so it keeps answering with the wrapper read beside the refusal, naming the format. `GENERIC` names a shape this
 * path has no rule for either.
 *
 * The `rim` member is read as the standard base64 text its reference spells it as, and no other spelling is
 * stripped rather than refused: a `data:` prefix or a line-wrapped body is an answer this path has not seen. The
 * values *inside* a manifest are read differently, because the served profile writes them in lines: the digest,
 * the signature and each certificate are base64 with line feeds between, and those feeds are part of the signed
 * content and not part of the value.
 */
export function readRimManifest(body: Uint8Array, query: CollateralQuery, declaration: OriginDeclaration): RimReadOutcome {
  const wrong = envelopeRefusal(declaration);
  if (wrong !== null) {
    return { refusal: wrong };
  }
  if (body.byteLength === 0) {
    return { refusal: unreadable(declaration, 'the answer is empty') };
  }
  if (body.byteLength > declaration.maxResponseBytes) {
    return {
      refusal: unreadable(
        declaration,
        `the answer is ${String(body.byteLength)} bytes, over the ${String(declaration.maxResponseBytes)} this path reads`,
      ),
    };
  }
  const text = decodeText(body, declaration);
  if (typeof text !== 'string') {
    return { refusal: text.refusal };
  }
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    return { refusal: unreadable(declaration, 'the answer is not a JSON object') };
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    return { refusal: unreadable(declaration, 'the answer is not a JSON object') };
  }
  const stated = payload as Record<string, unknown>;
  const id = stringMember(stated, 'id', declaration);
  if ('refusal' in id) {
    return { refusal: id.refusal };
  }
  const format = stringMember(stated, 'rim_format', declaration);
  if ('refusal' in format) {
    return { refusal: format.refusal };
  }
  const lastUpdated = stringMember(stated, 'last_updated', declaration);
  if ('refusal' in lastUpdated) {
    return { refusal: lastUpdated.refusal };
  }
  const encoded = stringMember(stated, 'rim', declaration);
  if ('refusal' in encoded) {
    return { refusal: encoded.refusal };
  }
  const statedDigest = stringMember(stated, 'sha256', declaration);
  if ('refusal' in statedDigest) {
    return { refusal: statedDigest.refusal };
  }
  if (!FORMATS.includes(format.value)) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.statusUnknown,
        `the wrapper names the manifest format ${quoteOrDigest(format.value)}, which is none of ${FORMATS.join(', ')}`,
      ),
    };
  }
  if (query.rimId !== null && query.rimId !== undefined && query.rimId !== id.value) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.identity,
        `the answer carries the manifest ${quoteOrDigest(id.value)} and the question asked for ${quoteOrDigest(query.rimId)}`,
        ['rimId'],
      ),
    };
  }
  const digest = digestOf(statedDigest.value, declaration);
  if ('refusal' in digest) {
    return { refusal: digest.refusal };
  }
  const manifest = fromBase64(encoded.value);
  if (manifest === null) {
    return { refusal: unreadable(declaration, 'the rim member is not standard base64 text') };
  }
  const actual = toHex(sha256(manifest));
  if (actual !== digest.value) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.identity,
        `the manifest the wrapper carries hashes to ${actual} and the wrapper states ${digest.value}`,
        [],
      ),
    };
  }
  const read = { id: id.value, format: format.value, lastUpdated: lastUpdated.value, rim: manifest, digest: actual, tagId: null, anchorDigest: null, blobs: [body] };
  if (format.value !== 'TCG') {
    return {
      read,
      refusal: collateralRefusal(
        declaration.refusals.signature,
        `the wrapper is read and its own digest holds, and the ${format.value} manifest inside it is signed in a shape this path states no rule for weighing`,
      ),
    };
  }
  return weighManifest(read, manifest, query, declaration);
}

/**
 * Weighs a `TCG` manifest: reads the document, believes it, and only then reads what it states.
 *
 * The order is the one every signed answer in this package is read in. Structure and identifiers are settled
 * before any byte is canonicalized, because a reader that parsed what it did not yet trust takes instructions
 * from the answer; the digest is settled before the chain, and the chain before the signature, because the leaf
 * the signature is checked under is only established by the walk. Nothing here compares the tag identity the
 * document states with the id the question asked about: the second is the handle the route is addressed by and
 * the first is a name the publisher gives the document itself, and this format binds neither to the other. The
 * read hands both back, so a caller sees the tag identity beside the id it asked for.
 */
function weighManifest(
  read: RimManifest,
  manifest: Uint8Array,
  query: CollateralQuery,
  declaration: OriginDeclaration,
): RimReadOutcome {
  const appraisalAt = query.appraisalAt;
  if (appraisalAt === null) {
    return {
      refusal: collateralRefusal(
        'COLLATERAL_INPUT_MISSING',
        'a manifest is weighed at the instant a caller names, and this question states none',
        ['appraisalAt'],
      ),
    };
  }
  const text = decodeText(manifest, declaration);
  if (typeof text !== 'string') {
    return { refusal: text.refusal };
  }
  const document = readXml(text);
  if ('why' in document) {
    return { refusal: unreadable(declaration, `the manifest is not XML this path reads: ${document.why}`) };
  }
  const elements = collectElements(document.document);
  const signatures = elements.filter((element) => isDs(element, 'Signature'));
  if (signatures.length !== 1) {
    return {
      refusal: unreadable(
        declaration,
        `the manifest carries ${String(signatures.length)} ds:Signature elements and this path reads exactly one`,
      ),
    };
  }
  const signature = signatures[0] as XmlElement;
  const identity = document.document.root;
  if (identity.localName !== RIM_TCG_PROFILE.identityElement || identity.namespace !== RIM_TCG_PROFILE.swidNamespace) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.statusUnknown,
        `the manifest is rooted at ${quoteOrDigest(`${identity.prefix}:${identity.localName}`)} in ${quoteOrDigest(identity.namespace)}, which is not the SWID namespace this profile reads`,
      ),
    };
  }
  const repeated = coveredElements(document.document.root, signature).filter(
    (element) => element !== identity && element.localName === RIM_TCG_PROFILE.identityElement && element.namespace === RIM_TCG_PROFILE.swidNamespace,
  );
  if (repeated.length > 0) {
    return {
      refusal: unreadable(
        declaration,
        `the manifest carries the ${RIM_TCG_PROFILE.identityElement} element twice: the identity is read from the document element alone`,
      ),
    };
  }
  const tagId = attributeOf(identity, RIM_TCG_PROFILE.identityAttribute);
  if (tagId === null || tagId.length === 0) {
    return { refusal: unreadable(declaration, `the document element carries no ${RIM_TCG_PROFILE.identityAttribute}`) };
  }
  const signedInfo = childElements(signature, RIM_TCG_PROFILE.signatureNamespace, 'SignedInfo');
  const first = elementChildren(signature)[0];
  if (signedInfo.length !== 1 || first === undefined || first !== signedInfo[0]) {
    return { refusal: unreadable(declaration, 'the Signature element carries no SignedInfo as its first child') };
  }
  const values = childElements(signature, RIM_TCG_PROFILE.signatureNamespace, 'SignatureValue');
  if (values.length !== 1) {
    return { refusal: unreadable(declaration, `the Signature element carries ${String(values.length)} SignatureValue elements`) };
  }
  const stated = readSignedInfo(signedInfo[0], declaration);
  if ('refusal' in stated) {
    return { refusal: stated.refusal };
  }
  const signatureValue = valueBytes(values[0] as XmlElement, declaration, RIM_TCG_PROFILE.signatureBytes, 'SignatureValue');
  if ('refusal' in signatureValue) {
    return { refusal: signatureValue.refusal };
  }
  const canonical = canonicalizeDocument(document.document, signature);
  if ('why' in canonical) {
    return { refusal: unreadable(declaration, `the document could not be canonicalized: ${canonical.why}`) };
  }
  const computed = sha384(canonical.bytes);
  if (!equalBytes(computed, stated.digest)) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.signature,
        `the manifest canonicalizes to a document whose digest is ${toHex(computed)} and the signed DigestValue states ${toHex(stated.digest)}`,
      ),
    };
  }
  const signed = canonicalizeSubtree(signedInfo[0]);
  if ('why' in signed) {
    return { refusal: unreadable(declaration, `the SignedInfo element could not be canonicalized: ${signed.why}`) };
  }
  const presented = keyInfoCertificates(signature, declaration);
  if ('refusal' in presented) {
    return { refusal: presented.refusal };
  }
  const certificates: ParsedCertificate[] = [];
  for (const der of presented.certificates) {
    const parsed = parseCertificates(der);
    if (parsed === null || parsed.length !== 1) {
      return { refusal: unreadable(declaration, 'a certificate the manifest presents does not parse as one X.509 certificate') };
    }
    certificates.push(parsed[0] as ParsedCertificate);
  }
  const suite = suiteRefusal(certificates, declaration);
  if (suite !== null) {
    return { refusal: suite };
  }
  const pinned = parsePinned(query.roots, declaration);
  if ('refusal' in pinned) {
    return { refusal: pinned.refusal };
  }
  if (query.roots.length === 0) {
    return { refusal: collateralRefusal(declaration.refusals.anchor, 'the question pinned none, so no chain of this manifest reaches a root') };
  }
  const anchor = walkToPinnedRoot(certificates, pinned, appraisalAt, declaration);
  if ('refusal' in anchor) {
    return { refusal: anchor.refusal };
  }
  const leaf = certificates[0] as ParsedCertificate;
  if (!signedUnder(leaf.publicKey, signed.bytes, signatureValue)) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.signature,
        'the signature of this manifest does not hold over the canonicalized SignedInfo under the certificate at the foot of the chain',
      ),
    };
  }
  return {
    read: {
      ...read,
      tagId,
      anchorDigest: anchor.digest,
      blobs: [...read.blobs, ...presented.certificates],
    },
  };
}

/**
 * The signed element, read as the profile names it and refused as the shape it does not.
 *
 * Every identifier is compared with the constant rather than with a list of near neighbours, and the refusal
 * quotes the identifier met: a reader that sorted `xml-exc-c14n#` into the canonicalization it wanted would
 * accept a manifest whose bytes it had mis-canonicalized, and the digest would still match, because both sides
 * of the comparison were computed by the same wrong rule.
 */
function readSignedInfo(
  signedInfo: XmlElement,
  declaration: OriginDeclaration,
): { readonly digest: Uint8Array } | { readonly refusal: CollateralRefusal } {
  const ds = RIM_TCG_PROFILE.signatureNamespace;
  const methods = childElements(signedInfo, ds, 'CanonicalizationMethod');
  const signatureMethods = childElements(signedInfo, ds, 'SignatureMethod');
  const references = childElements(signedInfo, ds, 'Reference');
  const children = elementChildren(signedInfo);
  if (methods.length !== 1 || signatureMethods.length !== 1 || references.length !== 1) {
    return {
      refusal: unreadable(
        declaration,
        `the SignedInfo element carries ${String(methods.length)} CanonicalizationMethod, ${String(signatureMethods.length)} SignatureMethod and ${String(references.length)} Reference elements`,
      ),
    };
  }
  if (children[0] !== methods[0] || children[1] !== signatureMethods[0] || children[2] !== references[0] || children.length !== 3) {
    return { refusal: unreadable(declaration, 'the SignedInfo element carries children other than the method pair and the one reference') };
  }
  const canonicalization = algorithmOf(methods[0] as XmlElement);
  if (canonicalization !== RIM_TCG_PROFILE.canonicalization) {
    return { refusal: outsideProfile(declaration, 'CanonicalizationMethod', canonicalization) };
  }
  const signatureMethod = algorithmOf(signatureMethods[0] as XmlElement);
  if (signatureMethod !== RIM_TCG_PROFILE.signatureMethod) {
    return { refusal: outsideProfile(declaration, 'SignatureMethod', signatureMethod) };
  }
  const reference = references[0] as XmlElement;
  const uri = attributeOf(reference, 'URI');
  if (reference.attributes.length !== 1 || uri !== '') {
    return {
      refusal: collateralRefusal(
        declaration.refusals.statusUnknown,
        `the Reference element states URI ${quoteOrDigest(uri ?? 'nothing')}, and this profile reads a same-document Reference whose only attribute is URI=""`,
      ),
    };
  }
  const referenceChildren = elementChildren(reference);
  const transformsList = childElements(reference, ds, 'Transforms');
  const digestMethods = childElements(reference, ds, 'DigestMethod');
  const digestValues = childElements(reference, ds, 'DigestValue');
  if (transformsList.length !== 1 || digestMethods.length !== 1 || digestValues.length !== 1 || referenceChildren.length !== 3) {
    return { refusal: unreadable(declaration, 'the Reference element does not carry one Transforms, DigestMethod and DigestValue') };
  }
  const transformRefusal = readTransforms(transformsList[0] as XmlElement, declaration);
  if (transformRefusal !== null) {
    return { refusal: transformRefusal };
  }
  const digestMethod = algorithmOf(digestMethods[0] as XmlElement);
  if (digestMethod !== RIM_TCG_PROFILE.digestMethod) {
    return { refusal: outsideProfile(declaration, 'DigestMethod', digestMethod) };
  }
  const digest = valueBytes(digestValues[0] as XmlElement, declaration, RIM_TCG_PROFILE.digestBytes, 'DigestValue');
  if ('refusal' in digest) {
    return { refusal: digest.refusal };
  }
  return { digest };
}

/** The transform chain a reference states, against the two the profile states, in that order and bare. */
function readTransforms(transforms: XmlElement, declaration: OriginDeclaration): CollateralRefusal | null {
  const ds = RIM_TCG_PROFILE.signatureNamespace;
  const met = childElements(transforms, ds, 'Transform');
  if (met.length !== elementChildren(transforms).length) {
    return unreadable(declaration, 'the Transforms element carries children other than Transform elements');
  }
  for (const [index, transform] of met.entries()) {
    const algorithm = algorithmOf(transform);
    const named = RIM_TCG_PROFILE.transforms[index];
    if (named === undefined || algorithm !== named || transform.attributes.length !== 1 || elementChildren(transform).length > 0) {
      return outsideProfile(declaration, 'Transform', algorithm);
    }
  }
  if (met.length !== RIM_TCG_PROFILE.transforms.length) {
    return collateralRefusal(
      declaration.refusals.statusUnknown,
      `the Reference states ${String(met.length)} of the two transforms this profile reads, ${RIM_TCG_PROFILE.transforms.join(' then ')}`,
    );
  }
  return null;
}

/**
 * The certificates a `KeyInfo` presents, leaf first.
 *
 * They are read from inside the signed document rather than from a response header, which is what material that
 * travels in a pack can offer. The names the served chain answers under, and nothing else: a `RetrievalMethod`
 * points at a certificate the reader has not fetched and a `KeyValue` states a key the chain did not issue, and
 * both are refused as shapes the profile names no rule for rather than skipped.
 */
function keyInfoCertificates(
  signature: XmlElement,
  declaration: OriginDeclaration,
): { readonly certificates: readonly Uint8Array[] } | { readonly refusal: CollateralRefusal } {
  const ds = RIM_TCG_PROFILE.signatureNamespace;
  const keyInfo = childElements(signature, ds, 'KeyInfo');
  if (keyInfo.length !== 1) {
    return { refusal: unreadable(declaration, `the Signature element carries ${String(keyInfo.length)} KeyInfo elements`) };
  }
  const containers = [keyInfo[0] as XmlElement, ...childElements(keyInfo[0] as XmlElement, ds, 'X509Data')];
  for (const container of containers) {
    for (const child of elementChildren(container)) {
      if (!readableKeyInfoChild(ds, child)) {
        return {
          refusal: collateralRefusal(
            declaration.refusals.statusUnknown,
            `the KeyInfo carries ${quoteOrDigest(child.name)}, which this profile reads no rule for`,
          ),
        };
      }
    }
  }
  const elements = containers.flatMap((container) => childElements(container, ds, 'X509Certificate'));
  if (elements.length === 0) {
    return { refusal: unreadable(declaration, 'the KeyInfo of this manifest presents no certificate') };
  }
  if (elements.length > RIM_TCG_PROFILE.maxChain) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.statusUnknown,
        `the KeyInfo presents ${String(elements.length)} certificates, more than the ${String(RIM_TCG_PROFILE.maxChain)} this profile reads`,
      ),
    };
  }
  const certificates: Uint8Array[] = [];
  for (const element of elements) {
    const value = valueBytes(element, declaration, null, 'X509Certificate');
    if ('refusal' in value) {
      return { refusal: value.refusal };
    }
    certificates.push(value);
  }
  return { certificates };
}

/** The elements a `KeyInfo` may carry: the certificates themselves, the wrapper they arrive in, and the three
 * members that name a certificate rather than present one. */
function readableKeyInfoChild(ds: string, child: XmlElement): boolean {
  const naming = ['X509IssuerSerial', 'X509SubjectName', 'X509SKI', 'X509Certificate', 'X509Data'];
  return child.namespace === ds && naming.includes(child.localName);
}

/**
 * Walks the presented chain to a certificate the caller pinned.
 *
 * The chain a manifest of this profile presents is four deep and leaf-first, so the depth comes from the document
 * rather than from what the Intel and AMD answers happen to present. Every link above the foot is an authority,
 * every link is signed by the one above it, and every one of them stands at the instant the question names: a
 * manifest's leaf can stand at one instant and have stopped standing at the next, which is what makes the
 * appraisal instant the live case rather than a theoretical one. The walk ends at a self-signed certificate whose
 * subject a pinned root carries, and that certificate is checked against the *pinned* copy's key, so a chain
 * cannot borrow a trusted name.
 */
function walkToPinnedRoot(
  presented: readonly ParsedCertificate[],
  pinned: readonly ParsedCertificate[],
  appraisalAt: number,
  declaration: OriginDeclaration,
): { readonly digest: string } | { readonly refusal: CollateralRefusal } {
  const at = appraisalAt * 1000;
  for (const [hop, cert] of presented.entries()) {
    if (cert.notBefore > at || cert.notAfter < at) {
      return {
        refusal: collateralRefusal(
          declaration.refusals.signature,
          `certificate ${String(hop)} of the chain is outside its own validity at the instant being appraised`,
        ),
      };
    }
    const terminal = equalBytes(cert.subject, cert.issuer);
    if (terminal) {
      if (hop !== presented.length - 1) {
        return { refusal: collateralRefusal(declaration.refusals.signature, `certificate ${String(hop)} of the chain is self-signed and still has a link above it`) };
      }
      const anchor = pinned.find((root) => equalBytes(root.subject, cert.subject));
      if (anchor === undefined) {
        return { refusal: collateralRefusal(declaration.refusals.anchor, 'the chain reaches a self-signed certificate the caller pinned nothing for') };
      }
      if (!issuedUnder(anchor.publicKey, cert.tbs, cert.signature)) {
        return {
          refusal: collateralRefusal(
            declaration.refusals.signature,
            'the chain reaches a name the caller pinned, but the certificate wearing it is not signed by that pinned copy',
          ),
        };
      }
      return { digest: sha256Hex(anchor.raw) };
    }
    if (hop === presented.length - 1) {
      return { refusal: collateralRefusal(declaration.refusals.anchor, 'the chain stops short of any pinned root') };
    }
    const issuer = presented[hop + 1] as ParsedCertificate;
    if (!equalBytes(issuer.subject, cert.issuer) || issuer.isCa !== true) {
      return {
        refusal: collateralRefusal(
          declaration.refusals.signature,
          `certificate ${String(hop)} of the chain was not issued by the one presented above it, or that one is no authority`,
        ),
      };
    }
    if (!issuedUnder(issuer.publicKey, cert.tbs, cert.signature)) {
      return {
        refusal: collateralRefusal(
          declaration.refusals.signature,
          `certificate ${String(hop)} of the chain was not signed by the one above it`,
        ),
      };
    }
  }
  return { refusal: collateralRefusal(declaration.refusals.anchor, 'the chain presents no certificate at all') };
}

/** Every certificate of the chain is the suite and the key the profile names, or the answer says which was met. */
function suiteRefusal(certificates: readonly ParsedCertificate[], declaration: OriginDeclaration): CollateralRefusal | null {
  for (const [hop, cert] of certificates.entries()) {
    if (cert.signatureAlgorithm.kind === 'ecdsa-sha384' && cert.publicKey.kind === 'ec-p384') {
      continue;
    }
    return collateralRefusal(
      declaration.refusals.signature,
      `certificate ${String(hop)} of the chain states ${cert.signatureAlgorithm.kind} over ${cert.publicKey.kind}, and this profile reads ecdsa-sha384 over ec-p384`,
    );
  }
  return null;
}

/**
 * A certificate's own signature, read as DER over the TBSCertificate, under the key of the one that issued it.
 *
 * The two spellings an ECDSA signature arrives in are kept apart on purpose: a certificate writes its value in
 * DER, as X.509 states it, and the manifest signature this profile reads is the fixed-width pair of r and s.
 * Verifying one form as the other is a refusal that reads like a broken chain, so each has its own reader.
 */
function issuedUnder(key: ParsedCertificate['publicKey'], tbs: Uint8Array, signature: Uint8Array): boolean {
  if (key.kind !== 'ec-p384') {
    return false;
  }
  try {
    return p384.verify(signature, sha384(tbs), key.point, { format: 'der' });
  } catch {
    return false;
  }
}

/** The manifest's signature, read in the width the profile names, over the canonicalized signed element. */
function signedUnder(key: ParsedCertificate['publicKey'], message: Uint8Array, signature: Uint8Array): boolean {
  if (key.kind !== 'ec-p384') {
    return false;
  }
  try {
    return p384.verify(signature, sha384(message), key.point, { format: 'compact' });
  } catch {
    return false;
  }
}

/** The elements below the document element that a whole-document reference covers: all of them but the signature. */
function coveredElements(root: XmlElement, excluded: XmlElement): readonly XmlElement[] {
  const found: XmlElement[] = [];
  const walk = (element: XmlElement): void => {
    for (const child of element.children) {
      if (child.kind !== 'element' || child === excluded) {
        continue;
      }
      found.push(child);
      walk(child);
    }
  };
  found.push(root);
  walk(root);
  return found;
}

function elementChildren(element: XmlElement): readonly XmlElement[] {
  return element.children.filter((child): child is XmlElement => child.kind === 'element');
}

function isDs(element: XmlElement, localName: string): boolean {
  return element.namespace === RIM_TCG_PROFILE.signatureNamespace && element.localName === localName;
}

function algorithmOf(element: XmlElement): string {
  const stated = attributeOf(element, 'Algorithm');
  return stated === null ? 'no Algorithm attribute' : stated;
}

/**
 * The value of a signature member, as the bytes it names.
 *
 * The text is read with its line feeds removed, which is how the served profile writes these values, and then
 * decoded as standard base64. Where the profile names a width, a value of another length is refused rather than
 * compared: a 64-byte digest is not a shorter SHA-384, and a 71-byte signature is not some other spelling of a
 * 96-byte one that this path would then have to guess at.
 */
function valueBytes(
  element: XmlElement,
  declaration: OriginDeclaration,
  width: number | null,
  name: string,
): Uint8Array | { readonly refusal: CollateralRefusal } {
  const text = elementText(element);
  if (text === null) {
    return { refusal: unreadable(declaration, `the ${name} member holds more than character data`) };
  }
  const bytes = text.length === 0 ? null : fromBase64(text.replace(/\s+/gu, ''));
  if (bytes === null) {
    return { refusal: unreadable(declaration, `the ${name} member is not standard base64 text`) };
  }
  if (width !== null && bytes.byteLength !== width) {
    return {
      refusal: unreadable(
        declaration,
        `the ${name} member carries ${String(bytes.byteLength)} bytes and this profile reads ${String(width)}`,
      ),
    };
  }
  return bytes;
}

/**
 * How this path names an identifier it met and does not read.
 *
 * The full URI is longer than the printable token the refusal quotes, and quoting it raw would let a string that
 * arrived off the network carry characters that end or reorder the log line it is printed on. So the refusal
 * carries the last segment of the identifier, which is the part that tells one suite from another, beside the
 * length of the whole text, and the reader never sorts an identifier it cannot name into one it can.
 */
function identifierName(met: string): string {
  const named = met.slice(met.lastIndexOf('/') + 1).replace(/#/gu, '');
  return `${quoteOrDigest(named)}, ${String(met.length)} characters`;
}

function outsideProfile(declaration: OriginDeclaration, member: string, met: string): CollateralRefusal {
  return collateralRefusal(
    declaration.refusals.statusUnknown,
    `the manifest states ${member} ${identifierName(met)}, which is outside the profile this path declared and weighs`,
  );
}

function unreadable(declaration: OriginDeclaration, why: string): CollateralRefusal {
  return collateralRefusal(declaration.refusals.envelope, why);
}

/** The one refusal shape this reader can hand for a declaration it has no arm for. */
function envelopeRefusal(declaration: OriginDeclaration): CollateralRefusal | null {
  if (isRimDeclaration(declaration)) {
    return null;
  }
  return collateralRefusal(
    hasReader(declaration) ? 'COLLATERAL_BLOB_UNREADABLE' : 'COLLATERAL_ORIGIN_UNSUPPORTED',
    `${declaration.name} answers as ${declaration.answer} and this reader weighs a RIM wrapper alone`,
  );
}

function stringMember(
  owner: Record<string, unknown>,
  member: string,
  declaration: OriginDeclaration,
): { readonly value: string } | { readonly refusal: CollateralRefusal } {
  const value = owner[member];
  if (typeof value !== 'string' || value.length === 0) {
    return { refusal: unreadable(declaration, `the wrapper carries no ${member} text`) };
  }
  return { value };
}

/** A digest the wrapper states, as the hex it means rather than as the case it was typed in. */
function digestOf(
  text: string,
  declaration: OriginDeclaration,
): { readonly value: string } | { readonly refusal: CollateralRefusal } {
  if (!/^[0-9a-fA-F]{64}$/u.test(text)) {
    return { refusal: unreadable(declaration, 'the sha256 member is not 64 hex characters') };
  }
  return { value: text.toLowerCase() };
}

