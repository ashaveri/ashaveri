import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519';
import {
  DESTRUCTION_COPY_CLASSES,
  DESTRUCTION_OBJECT_KINDS,
  DESTRUCTION_REACH_NOT_REACHED,
  DESTRUCTION_REACH_REACHED,
  DESTRUCTION_RECEIPT_CONTENT_TYPE,
  DESTRUCTION_RECEIPT_ENTRY_MEMBERS,
  DESTRUCTION_RECEIPT_MANIFEST_MEMBERS,
  DESTRUCTION_UNREACHABLE_COPY_CLASSES,
  ReceiptError,
  decodeCanonical,
  decodeDestructionReceipt,
  destructionObjectDigest,
  destructionReceiptSigStructure,
  encodeCanonical,
  encodeDestructionReceiptManifest,
  encodeDestructionReceiptProtectedHeader,
  sealDestructionReceipt,
  signDestructionReceipt,
  signRedaction,
  signingKeyFromSeed,
  toBase64Url,
  toHex,
  verifyDestructionReceipt,
  type DestructionCopyClass,
  type DestructionReceiptManifest,
  type DestructionReachEntry,
  type RedactionManifest,
  type SigningKey,
} from '@ashaveri/receipt';
import { labeled } from './seed.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

/**
 * The destruction receipt vectors: whole receipts, the verdict each of the two shipped doors owes them, and
 * the designated bytes beside the rows that ask the optional half.
 *
 * Two verdicts are published per row because the reader has two entry points answering different questions.
 * `structural` is what `decodeDestructionReceipt` says about the bytes with no key in hand, and `expected` is
 * what `verifyDestructionReceipt` says against the key the header names. A port that merged them would report
 * a receipt as proven on the strength of its shape, which is the mistake the pair exists to prevent.
 *
 * Honest documents come from `signDestructionReceipt`; a refused one is that writer's own payload with one
 * position of the manifest map replaced, re-sealed under the key its header names. The keys are derived from
 * the labels this file publishes, so a port produces every signature here from nothing unstated, and the only
 * bytes of a key any row carries are the 32-byte kid the format itself names.
 */

const SIGNER_LABEL = 'ashaveri-fixtures/destruction-receipt-signer/v1';
const DESTROYED_LABEL = 'ashaveri-fixtures/destruction-receipt-destroyed/v1';
const OTHER_LABEL = 'ashaveri-fixtures/destruction-receipt-other/v1';
const EPOCH_ONE_LABEL = 'ashaveri-fixtures/destruction-receipt-epoch-one/v1';
const SIGNER: SigningKey = signingKeyFromSeed(labeled(SIGNER_LABEL));
const DESTROYED: SigningKey = signingKeyFromSeed(labeled(DESTROYED_LABEL));
const OTHER: SigningKey = signingKeyFromSeed(labeled(OTHER_LABEL));
const EPOCH_ONE: SigningKey = signingKeyFromSeed(labeled(EPOCH_ONE_LABEL));
const AT = 1_766_016_000;
const STATES = 'one receipt and the key that encrypted its body, erased from the copies this deployment holds';

/** A document of a kind the registry names, so a designation can be checked against real signed bytes. */
const OBJECT_BYTES = signRedaction(
  {
    v: 1,
    at: AT,
    pack: new Uint8Array(32).fill(7),
    removed: ['receipt-1'],
    reduced: new Uint8Array(32).fill(8),
    states: 'one record lifted out of a closed pack',
  } satisfies RedactionManifest,
  SIGNER,
);

/** Bytes that are no signed document, for the row that asks what a kind claim is worth. */
const OPAQUE_BYTES = new TextEncoder().encode('bytes that are no signed document at all');

function reachTable(over: Partial<Record<DestructionCopyClass, number>> = {}): DestructionReachEntry[] {
  return DESTRUCTION_COPY_CLASSES.map((name) => ({
    class: name,
    outcome: (over[name] ?? DESTRUCTION_REACH_NOT_REACHED) as DestructionReachEntry['outcome'],
  }));
}

function baseManifest(over: Partial<DestructionReceiptManifest> = {}): DestructionReceiptManifest {
  return {
    v: 1,
    at: AT,
    object: destructionObjectDigest(OBJECT_BYTES),
    kind: 'ashaveri/redaction',
    key: DESTROYED.kid,
    reach: reachTable({ store: DESTRUCTION_REACH_REACHED, pack: DESTRUCTION_REACH_REACHED }),
    states: STATES,
    ...over,
  };
}

const HONEST = signDestructionReceipt(baseManifest(), SIGNER);

function payloadOf(bytes: Uint8Array): Map<unknown, unknown> {
  const tagged = decodeCanonical(bytes) as unknown as { contents: unknown[] };
  return decodeCanonical((tagged.contents as Uint8Array[])[2]!) as Map<unknown, unknown>;
}

/** Re-seal a payload under a key, so a refusal row stays the one position it names and nothing else. */
function resealed(payloadBytes: Uint8Array, signer: SigningKey, headerBytes?: Uint8Array): Uint8Array {
  const header = headerBytes ?? encodeDestructionReceiptProtectedHeader(signer.kid);
  const signature = ed25519.sign(destructionReceiptSigStructure(header, payloadBytes), signer.privateKey);
  return sealDestructionReceipt(header, payloadBytes, signature);
}

/** A signed header as the CBOR the envelope carries, for the rows that edit the header rather than the map. */
function headerMap(extra: Array<[number, unknown]> = [], contentType = DESTRUCTION_RECEIPT_CONTENT_TYPE): Uint8Array {
  const map = new Map<number, unknown>([[1, -8], [3, contentType], [4, SIGNER.kid]]);
  for (const [label, value] of extra) map.set(label, value);
  return encodeCanonical(map);
}

function mutant(edit: (root: Map<unknown, unknown>) => void, signer: SigningKey = SIGNER): Uint8Array {
  const root = payloadOf(HONEST);
  edit(root);
  return resealed(encodeCanonical(root), signer);
}

function reachMaps(entries: readonly DestructionReachEntry[]): Map<string, unknown>[] {
  return entries.map((one) => new Map<string, unknown>([['class', one.class], ['outcome', one.outcome]]));
}

function codeOf(run: () => unknown): string {
  try {
    run();
    return 'verify-ok';
  } catch (reason) {
    return reason instanceof ReceiptError ? reason.code : `UNCODED ${String(reason)}`;
  }
}

interface Case {
  readonly name: string;
  readonly note: string;
  readonly document: Uint8Array;
  readonly arm: 'accept' | 'refuse';
  readonly edited?: { at: string; states: string };
  readonly objectBytes?: Uint8Array;
  readonly handedKey?: Uint8Array;
  /** Ask the verifying door with no key designation at all, which is a fault in the call and not in bytes. */
  readonly noKey?: boolean;
  /** A refusal the writer gave rather than a document the reader was handed, for the two rows that publish none. */
  readonly writer?: () => unknown;
}

interface Row extends Case {
  readonly structural: string;
  readonly expected: string;
}

function build(one: Case): Row {
  const structural = one.document.length === 0 ? 'not-a-document' : codeOf(() => decodeDestructionReceipt(one.document));
  const expected =
    one.writer !== undefined
      ? codeOf(one.writer)
      : one.noKey === true
        ? codeOf(() => verifyDestructionReceipt(one.document, {}))
        : codeOf(() =>
            verifyDestructionReceipt(one.document, {
              publicKey: one.handedKey ?? SIGNER.publicKey,
              ...(one.objectBytes === undefined ? {} : { objectBytes: one.objectBytes }),
            }),
          );
  return { ...one, structural, expected };
}

const CASES: Case[] = [
  {
    name: 'reached-the-copies-held',
    arm: 'accept',
    note: 'Reached the deployment store and one sealed pack; did not reach the export, the backup media, or the ' +
      "copy that left the deployment's hands. The class beyond reach is stated not-reached, which is the honest " +
      'half of the statement and not a defect of it. The designated bytes are handed, so the reader recomputes ' +
      'the digest and reads the type claim out of the object of its own header.',
    document: HONEST,
    objectBytes: OBJECT_BYTES,
  },
  {
    name: 'reached-nothing-but-the-store',
    arm: 'accept',
    note: 'Every class not-reached but the store. A receipt that reached the least it can is still a whole ' +
      'statement, and a reader is owed all five answers either way.',
    document: signDestructionReceipt(baseManifest({ reach: reachTable({ store: DESTRUCTION_REACH_REACHED }) }), SIGNER),
  },
  {
    name: 'designated-bytes-not-handed',
    arm: 'accept',
    note: "The first row's document, read by a caller holding nothing but these bytes. The designation is no " +
      'precondition: the object is what a destruction took, and a reader that had to produce it could only ever ' +
      'verify a receipt whose statement was false.',
    document: HONEST,
  },
  {
    name: 'reached-with-a-retired-key-named',
    arm: 'accept',
    note: 'The destroyed key is a kid from an earlier epoch and the signer is the key that followed it. That ' +
      'pair is what the format requires of every receipt: the attestation arrives from a key still in hand.',
    document: signDestructionReceipt(baseManifest({ key: EPOCH_ONE.kid }), SIGNER),
  },
  {
    name: 'class-left-unstated',
    arm: 'refuse',
    note: 'Four entries and no class named for the backup media. The document is complete-looking, and that is ' +
      'the fault: a receipt silent about one class reads as a receipt that reached everything it named.',
    document: mutant((root) => root.set('reach', reachMaps(reachTable().slice(0, 4)))),
    edited: { at: 'reach', states: 'one of the five copy classes carries no statement' },
  },
  {
    name: 'handout-claimed-reached',
    arm: 'refuse',
    note: "A reach claimed over the copy that left the deployment's hands. The bytes are well-formed and the " +
      'claim is one this format will not carry, so the refusal names the claim rather than the shape.',
    document: mutant((root) => root.set('reach', reachMaps(reachTable({ handout: DESTRUCTION_REACH_REACHED })))),
    edited: { at: 'reach[4].outcome', states: 'reached at a class the format declares out of reach' },
  },
  {
    name: 'sealed-by-the-destroyed-key',
    arm: 'refuse',
    note: 'The receipt names as destroyed the very kid its own protected header seals it with. A document sealed ' +
      'by a key proves the holder of that key signed it, so the statement refutes itself whoever signed it, and ' +
      'the refusal arrives before any caller key set is consulted.',
    document: resealed(encodeDestructionReceiptManifest(baseManifest({ key: DESTROYED.kid })), DESTROYED),
    handedKey: DESTROYED.publicKey,
    edited: { at: 'key against header label 4', states: 'the signer and the destroyed key are one key' },
  },
  {
    name: 'unknown-member-carrying-material',
    arm: 'refuse',
    note: 'A member the layout does not define, named for the thing a writer might reach for: sixty-four bytes ' +
      'of key. The closed map is what makes the sentence about key material a check rather than an intention.',
    document: mutant((root) => root.set('material', new Uint8Array(64))),
    edited: { at: 'manifest', states: 'a member no version of this layout defines' },
  },
  {
    name: 'entry-member-carrying-material',
    arm: 'refuse',
    note: 'The same sixty-four bytes offered at a position inside one reach entry, which the entry closes as the ' +
      'manifest does.',
    document: mutant((root) => {
      (root.get('reach') as Map<unknown, unknown>[])[0]!.set('material', new Uint8Array(64));
    }),
    edited: { at: 'reach[0]', states: 'a member the entry does not define' },
  },
  {
    name: 'key-of-another-width',
    arm: 'refuse',
    note: 'A sixty-four-byte value where the format writes a digest width. An Ed25519 public key and a secret ' +
      'seed are both this size and neither has a position here: the width rule does the work, not a rule about ' +
      'what a member is called.',
    document: mutant((root) => root.set('key', new Uint8Array(64))),
    edited: { at: 'key', states: 'a bstr of a width the format never writes' },
  },
  {
    name: 'designation-of-another-width',
    arm: 'refuse',
    note: 'The object position shortened to sixteen bytes.',
    document: mutant((root) => root.set('object', new Uint8Array(16))),
    edited: { at: 'object', states: 'a bstr of a width the format never writes' },
  },
  {
    name: 'kind-outside-the-registry',
    arm: 'refuse',
    note: 'A document kind this estate signs with but this container does not enumerate. Widening the registry ' +
      'is a decision about the format and not a value a writer picks.',
    document: mutant((root) => root.set('kind', 'ashaveri/deployment-manifest')),
    edited: { at: 'kind', states: 'a label outside the closed registry' },
  },
  {
    name: 'class-outside-the-registry',
    arm: 'refuse',
    note: 'A sixth copy class named in a reach entry. An unknown name is the opposite fault from a missing one, ' +
      'and it answers the shape refusal rather than the completeness one.',
    document: mutant((root) => {
      (root.get('reach') as Map<unknown, unknown>[])[0]!.set('class', 'inbox');
    }),
    edited: { at: 'reach[0].class', states: 'a label outside the closed registry' },
  },
  {
    name: 'class-named-twice',
    arm: 'refuse',
    note: 'Two entries state one class, so the count of statements disagrees with the set of copies they name.',
    document: mutant((root) => {
      const entries = root.get('reach') as Map<unknown, unknown>[];
      entries[1]!.set('class', entries[0]!.get('class'));
    }),
    edited: { at: 'reach[1].class', states: 'a class the list already stated' },
  },
  {
    name: 'outcome-that-is-neither',
    arm: 'refuse',
    note: 'An outcome of zero, which is neither reached nor not-reached. There is no third value, no default and ' +
      'nothing falsy to fall into.',
    document: mutant((root) => {
      (root.get('reach') as Map<unknown, unknown>[])[0]!.set('outcome', 0);
    }),
    edited: { at: 'reach[0].outcome', states: 'a value the format does not declare' },
  },
  {
    name: 'reach-not-a-list',
    arm: 'refuse',
    note: 'The reach member carrying a map in place of a list of entries.',
    document: mutant((root) => root.set('reach', new Map<string, unknown>([['store', true]]))),
    edited: { at: 'reach', states: 'a value of another type' },
  },
  {
    name: 'member-absent',
    arm: 'refuse',
    note: 'The sentence removed. Every member of this layout is required, because an optional member is a ' +
      'silence a reader has to guess at.',
    document: mutant((root) => root.delete('states')),
    edited: { at: 'states', states: 'a required member absent' },
  },
  {
    name: 'stamp-before-the-epoch',
    arm: 'refuse',
    note: 'A destruction stated before there were instants to state it at.',
    document: mutant((root) => root.set('at', -1)),
    edited: { at: 'at', states: 'a stamp earlier than the epoch' },
  },
  {
    name: 'sentence-that-forges-a-line',
    arm: 'refuse',
    note: "The writer's sentence carrying a right-to-left override, which would make the printed row a reader " +
      'sees stop being the bytes the receipt carries. This is the one position of the layout that is opaque text, ' +
      'and it is read under the printed-line class the rest of the estate holds its text to.',
    document: mutant((root) => root.set('states', 'erased \u202E entirely')),
    edited: { at: 'states', states: 'a character that reorders the line it is printed on' },
  },
  {
    name: 'version-two',
    arm: 'refuse',
    note: 'A second version of a format that has never had a first one in another shape. The number moves when ' +
      'bytes in the older shape exist, and none do, so this is refused as a version before one member of it is ' +
      'read.',
    document: mutant((root) => root.set('v', 2)),
    edited: { at: 'v', states: 'a version no layout this package reads defines' },
  },
  {
    name: 'another-content-type',
    arm: 'refuse',
    note: 'These very bytes under the content type of a pack. One deployment key seals six documents, each of ' +
      'which passes its own checks, and the field that says which claim a reader is holding is answered before ' +
      'a key is consulted.',
    document: resealed(encodeCanonical(payloadOf(HONEST)), SIGNER, headerMap([], 'ashaveri/pack')),
    edited: { at: 'protected header label 3', states: 'a content type other than this formats own' },
  },
  {
    name: 'header-carrying-a-fourth-label',
    arm: 'refuse',
    note: 'A header parameter the format does not declare. Its bytes are hashed into the signature, so a reader ' +
      'that took three labels out of a header carrying a fourth would hand on a document other than the one the ' +
      'issuer signed.',
    document: resealed(encodeCanonical(payloadOf(HONEST)), SIGNER, headerMap([[9, 1]])),
    edited: { at: 'protected header', states: 'a label the format does not define' },
  },
  {
    name: 'a-pack-handed-as-a-receipt',
    arm: 'refuse',
    note: 'A document of another family, offered whole. The refusal is the content type at the header and not a ' +
      'manifest fault, because none of these bytes is a member of this layout.',
    document: OBJECT_BYTES,
    edited: { at: 'the whole document', states: 'a redaction manifest read where a destruction receipt was expected' },
  },
  {
    name: 'whole-bytes-no-key-handed',
    arm: 'refuse',
    note: 'The honest receipt, handed to the verifying door with no key designation of any kind. The document is ' +
      'whole and the reader is simply not in a position to prove it, which is a different finding from a ' +
      'malformed manifest and is refused as its own code.',
    document: HONEST,
    noKey: true,
    edited: { at: 'the call', states: 'neither a public key nor a resolver handed to the reader' },
  },
  {
    name: 'key-of-another-caller',
    arm: 'refuse',
    note: 'Whole bytes verified against a key the reader was configured with and the receipt does not name. A ' +
      'wrong key and an edited document send an operator to two places, so they are refused separately.',
    document: HONEST,
    handedKey: OTHER.publicKey,
    edited: { at: 'the call', states: 'a public key other than the kid the header carries' },
  },
  {
    name: 'other-bytes-than-the-designation',
    arm: 'refuse',
    note: 'The designated digest and a document that is not the one it designates, both handed over. Either half ' +
      'may be whole; what is refused is reading this receipt against those bytes.',
    document: HONEST,
    objectBytes: signRedaction(
      { v: 1, at: AT, pack: new Uint8Array(32).fill(7), removed: ['receipt-2'], reduced: new Uint8Array(32).fill(9), states: 'a second removal' },
      SIGNER,
    ),
    edited: { at: 'the call', states: 'bytes hashing elsewhere than the object the manifest carries' },
  },
  {
    name: 'designated-bytes-of-another-kind',
    arm: 'refuse',
    note: 'The digest matches and the kind does not: the bytes are a redaction and the receipt calls them a ' +
      'pack. This is what the pair is required for, and no keyword and no other refusal in this family reports it.',
    document: signDestructionReceipt(baseManifest({ kind: 'ashaveri/pack' }), SIGNER),
    objectBytes: OBJECT_BYTES,
    edited: { at: 'kind against the designated bytes own header', states: 'a document type the designation does not carry' },
  },
  {
    name: 'designated-bytes-not-a-signed-document',
    arm: 'refuse',
    note: 'The digest matches and the bytes are not a signed document of any kind. The only question asked of ' +
      'them here is whether they are the document the receipt names, and one answer covers both ways it fails.',
    document: signDestructionReceipt(baseManifest({ object: destructionObjectDigest(OPAQUE_BYTES) }), SIGNER),
    objectBytes: OPAQUE_BYTES,
    edited: { at: 'kind against the designated bytes', states: 'bytes no envelope reader opens' },
  },
  {
    name: 'writer-refuses-to-sign-overreach',
    arm: 'refuse',
    note: 'Not a document. The encoder is asked to produce the first refusal row with the beyond-reach class ' +
      'stated reached, and it refuses at the point the map is written, so a deployment cannot file bytes only a ' +
      'reader would reject.',
    document: new Uint8Array(0),
    writer: () => signDestructionReceipt(baseManifest({ reach: reachTable({ handout: DESTRUCTION_REACH_REACHED }) }), SIGNER),
    edited: { at: 'signDestructionReceipt', states: 'the writer refusing the reach the format will not carry' },
  },
  {
    name: 'writer-refuses-its-own-refusal',
    arm: 'refuse',
    note: 'Again not a document. The encoder is asked to sign a receipt that leaves one copy class unstated and ' +
      'runs its own reader over the bytes before it signs them, so the refusal arrives where the bytes are made.',
    document: new Uint8Array(0),
    writer: () => signDestructionReceipt(baseManifest({ reach: reachTable().slice(0, 4) }), SIGNER),
    edited: { at: 'signDestructionReceipt', states: 'the writer running its own reader before signing' },
  },
];

function published(one: Row): Record<string, unknown> {
  return {
    name: one.name,
    note: one.note,
    arm: one.arm,
    structural: one.structural,
    expected: one.expected,
    ...(one.edited === undefined ? {} : { edit: one.edited }),
    ...(one.document.length === 0
      ? {}
      : { documentBase64Url: toBase64Url(one.document), documentByteLength: one.document.length }),
    ...(one.objectBytes === undefined
      ? {}
      : { objectBase64Url: toBase64Url(one.objectBytes), objectByteLength: one.objectBytes.length }),
  };
}

function main(): void {
  const rows = CASES.map(build);
  // The two rows that publish no document carry the refusal the writer gave, and nothing else about them is a
  // byte string, so the acceptance guard has to be told they are not acceptances by construction.
  for (const name of ['writer-refuses-to-sign-overreach', 'writer-refuses-its-own-refusal']) {
    const one = rows.find((each) => each.name === name);
    if (one === undefined || one.expected === 'verify-ok') {
      throw new Error(`${name} publishes no writer refusal`);
    }
  }

  const observed = new Set<string>();
  for (const one of rows) {
    observed.add(one.expected);
    if (one.document.length > 0) observed.add(one.structural);
    if (one.arm === 'accept') {
      expectAccepted(one);
    } else if (one.expected === 'verify-ok') {
      throw new Error(`${one.name} states a refusal and the reader accepted it`);
    }
  }

  writeFileSync(
    join(DATA, 'destruction-receipt-v1.json'),
    JSON.stringify(
      {
        version: 1,
        description:
          'Conformance vectors for the destruction receipt: what one destruction reached, copy class by copy ' +
          'class, beside the one object and the one key it took.',
        layout: {
          document: DESTRUCTION_RECEIPT_CONTENT_TYPE,
          versions: [1],
          manifestMembers: [...DESTRUCTION_RECEIPT_MANIFEST_MEMBERS],
          entryMembers: [...DESTRUCTION_RECEIPT_ENTRY_MEMBERS],
          copyClasses: [...DESTRUCTION_COPY_CLASSES],
          unreachableClasses: [...DESTRUCTION_UNREACHABLE_COPY_CLASSES],
          objectKinds: [...DESTRUCTION_OBJECT_KINDS],
          reachOutcomes: { reached: DESTRUCTION_REACH_REACHED, notReached: DESTRUCTION_REACH_NOT_REACHED },
          rule:
            'Every copy class the format enumerates carries exactly one statement, and the class whose copies ' +
            'have left the deployment hands may only ever be stated not-reached. The destroyed key is named by ' +
            'its kid and never by its material, and the receipt is sealed by a key other than the one it names.',
          writerRule:
            'signDestructionReceipt encodes the manifest, runs it back through the whole reader, and refuses ' +
            'before it signs a reach the format will not carry or a statement sealed by the key it destroys.',
          signingKeys: [
            { role: 'signer', label: SIGNER_LABEL, kid: toHex(SIGNER.kid) },
            { role: 'destroyed', label: DESTROYED_LABEL, kid: toHex(DESTROYED.kid) },
            { role: 'another-callers-key', label: OTHER_LABEL, kid: toHex(OTHER.kid) },
            { role: 'an-earlier-epoch', label: EPOCH_ONE_LABEL, kid: toHex(EPOCH_ONE.kid) },
          ],
          keyNote:
            'Test-only, and no secret is published: each key is signingKeyFromSeed over sha256 of the label ' +
            'beside it, so a port reproduces every signature here from the label alone. What the suite carries ' +
            'of a key is the kid, which is the public label the format itself names.',
        },
        vectors: rows.map(published),
      },
      null,
      2,
    ) + '\n',
  );

  for (const one of rows) console.log(`${one.name}: ${one.structural} -> ${one.expected}`);
}

/** An accepted row has to be accepted by both doors, or the suite is publishing a refusal it calls honest. */
function expectAccepted(one: Row): void {
  if (one.structural !== 'verify-ok' || one.expected !== 'verify-ok') {
    throw new Error(`${one.name} is published as an acceptance and the reader answered ${one.expected}`);
  }
}

main();
