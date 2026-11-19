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
import type { DestructionReceiptKeyRole, DestructionReceiptVector } from '../src/index.js';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

/**
 * The destruction receipt vectors: whole receipts, the verdict each of the two shipped doors owes them, and
 * the designated bytes beside the rows that ask the optional half.
 *
 * Two verdicts are published per row because the reader has two entry points answering different questions.
 * `structural` is what `decodeDestructionReceipt` says about the bytes with no key in hand, and `expected` is
 * what `verifyDestructionReceipt` says against the published verification input. A port that merged them would report
 * a receipt as proven on the strength of its shape, which is the mistake the pair exists to prevent.
 *
 * Accepted documents come from `signDestructionReceipt`. Manifest mutants are re-signed; separate rows
 * truncate CBOR or corrupt a signature without re-signing. Each document row publishes its key selector
 * and optional object bytes independently of its verdict. Test keys are reproducible from published labels.
 */

const SIGNER_LABEL = 'ashaveri-fixtures/destruction-receipt-signer/v1';
const DESTROYED_LABEL = 'ashaveri-fixtures/destruction-receipt-destroyed/v1';
const OTHER_LABEL = 'ashaveri-fixtures/destruction-receipt-other/v1';
const EPOCH_ONE_LABEL = 'ashaveri-fixtures/destruction-receipt-epoch-one/v1';
const SIGNER: SigningKey = signingKeyFromSeed(labeled(SIGNER_LABEL));
const DESTROYED: SigningKey = signingKeyFromSeed(labeled(DESTROYED_LABEL));
const OTHER: SigningKey = signingKeyFromSeed(labeled(OTHER_LABEL));
const EPOCH_ONE: SigningKey = signingKeyFromSeed(labeled(EPOCH_ONE_LABEL));
const KEYS: Record<DestructionReceiptKeyRole, SigningKey> = {
  signer: SIGNER,
  destroyed: DESTROYED,
  'another-callers-key': OTHER,
  'an-earlier-epoch': EPOCH_ONE,
};
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
const honestEnvelope = decodeDestructionReceipt(HONEST).envelope;
const corruptedSignature = honestEnvelope.signature.slice();
corruptedSignature[0] = corruptedSignature[0]! ^ 1;
const CORRUPTED_SIGNATURE = sealDestructionReceipt(
  honestEnvelope.protectedBytes, honestEnvelope.payloadBytes, corruptedSignature,
);

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
  readonly verification: {
    readonly key: DestructionReceiptKeyRole | null;
    readonly objectBytes: Uint8Array | null;
  } | null;
  /** A refusal the writer gave rather than a document the reader was handed, for the two rows that publish none. */
  readonly writer?: () => unknown;
}

interface Row extends Case {
  readonly structural: string;
  readonly expected: string;
}

function build(one: Case): Row {
  const structural = one.document.length === 0 ? 'not-a-document' : codeOf(() => decodeDestructionReceipt(one.document));
  const input = one.verification;
  if ((input === null) !== (one.writer !== undefined)) throw new Error(`${one.name}: verification input must be null only for writer rows`);
  const expected = input === null
    ? codeOf(one.writer!)
    : codeOf(() => verifyDestructionReceipt(one.document, {
        ...(input.key === null ? {} : { publicKey: KEYS[input.key].publicKey }),
        ...(input.objectBytes === null ? {} : { objectBytes: input.objectBytes }),
      }));
  return { ...one, structural, expected };
}

const CASES: Case[] = [
  {
    name: 'reached-the-copies-held',
    arm: 'accept',
    verification: { key: 'signer', objectBytes: OBJECT_BYTES },
    note: 'Reached the deployment store and one sealed pack; did not reach the export, the backup media, or the ' +
      "copy that left the deployment's hands. The class beyond reach is stated not-reached, which is the honest " +
      'half of the statement and not a defect of it. The designated bytes are handed, so the reader recomputes ' +
      'the digest and reads the type claim out of the object of its own header.',
    document: HONEST,
  },
  {
    name: 'reached-nothing-but-the-store',
    arm: 'accept',
    verification: { key: 'signer', objectBytes: null },
    note: 'Every class not-reached but the store. A receipt that reached the least it can is still a whole ' +
      'statement, and a reader is owed all five answers either way.',
    document: signDestructionReceipt(baseManifest({ reach: reachTable({ store: DESTRUCTION_REACH_REACHED }) }), SIGNER),
  },
  {
    name: 'designated-bytes-not-handed',
    arm: 'accept',
    verification: { key: 'signer', objectBytes: null },
    note: 'The first receipt verified without object bytes. Digest and kind comparisons are absent. A retained handout could supply those bytes even when a store copy was destroyed.',
    document: HONEST,
  },
  {
    name: 'reached-with-a-retired-key-named',
    arm: 'accept',
    verification: { key: 'signer', objectBytes: null },
    note: 'The fixture names an earlier-epoch kid and uses a different signer. The format requires distinct keys, not proof of their chronology.',
    document: signDestructionReceipt(baseManifest({ key: EPOCH_ONE.kid }), SIGNER),
  },
  {
    name: 'class-left-unstated',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
    note: 'Four entries and no class named for the backup media. The document is complete-looking, and that is ' +
      'the fault: a receipt silent about one class reads as a receipt that reached everything it named.',
    document: mutant((root) => root.set('reach', reachMaps(reachTable().filter((one) => one.class !== 'backup')))),
    edited: { at: 'reach', states: 'one of the five copy classes carries no statement' },
  },
  {
    name: 'handout-claimed-reached',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
    note: "A reach claimed over the copy that left the deployment's hands. The bytes are well-formed and the " +
      'claim is one this format will not carry, so the refusal names the claim rather than the shape.',
    document: mutant((root) => root.set('reach', reachMaps(reachTable({ handout: DESTRUCTION_REACH_REACHED })))),
    edited: { at: 'reach[4].outcome', states: 'reached at a class the format declares out of reach' },
  },
  {
    name: 'sealed-by-the-destroyed-key',
    arm: 'refuse',
    verification: { key: 'destroyed', objectBytes: null },
    note: 'The named destroyed key equals the protected header kid. This violates the distinct-signer format rule and is refused structurally, without establishing when signing occurred.',
    document: resealed(encodeDestructionReceiptManifest(baseManifest({ key: DESTROYED.kid })), DESTROYED),
    edited: { at: 'key against header label 4', states: 'the signer and the destroyed key are one key' },
  },
  {
    name: 'unknown-member-carrying-material',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
    note: 'An undeclared member carrying sixty-four zero bytes. Closure rejects the member, not the origin or meaning of its value.',
    document: mutant((root) => root.set('material', new Uint8Array(64))),
    edited: { at: 'manifest', states: 'a member no version of this layout defines' },
  },
  {
    name: 'entry-member-carrying-material',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
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
    verification: { key: 'signer', objectBytes: null },
    note: 'A sixty-four-byte value where the format requires 32 bytes. This is a width refusal, not secret detection: Ed25519 seeds and public keys are 32 bytes and pass the width check.',
    document: mutant((root) => root.set('key', new Uint8Array(64))),
    edited: { at: 'key', states: 'a bstr of a width the format never writes' },
  },
  {
    name: 'designation-of-another-width',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
    note: 'The object position shortened to sixteen bytes.',
    document: mutant((root) => root.set('object', new Uint8Array(16))),
    edited: { at: 'object', states: 'a bstr of a width the format never writes' },
  },
  {
    name: 'kind-outside-the-registry',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
    note: 'A document kind this estate signs with but this container does not enumerate. Widening the registry ' +
      'is a decision about the format and not a value a writer picks.',
    document: mutant((root) => root.set('kind', 'ashaveri/deployment-manifest')),
    edited: { at: 'kind', states: 'a label outside the closed registry' },
  },
  {
    name: 'class-outside-the-registry',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
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
    verification: { key: 'signer', objectBytes: null },
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
    verification: { key: 'signer', objectBytes: null },
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
    verification: { key: 'signer', objectBytes: null },
    note: 'The reach member carrying a map in place of a list of entries.',
    document: mutant((root) => root.set('reach', new Map<string, unknown>([['store', true]]))),
    edited: { at: 'reach', states: 'a value of another type' },
  },
  {
    name: 'member-absent',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
    note: 'The sentence removed. Every member of this layout is required, because an optional member is a ' +
      'silence a reader has to guess at.',
    document: mutant((root) => root.delete('states')),
    edited: { at: 'states', states: 'a required member absent' },
  },
  {
    name: 'stamp-before-the-epoch',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
    note: 'A destruction stated before there were instants to state it at.',
    document: mutant((root) => root.set('at', -1)),
    edited: { at: 'at', states: 'a stamp earlier than the epoch' },
  },
  {
    name: 'malformed-cbor',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
    note: 'The honest receipt truncated inside its protected header, before any manifest can be read.',
    document: HONEST.slice(0, 20),
    edited: { at: 'CBOR envelope', states: 'truncated byte string' },
  },
  {
    name: 'empty-states',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
    note: 'An empty sentence, below the one-byte floor.',
    document: mutant((root) => root.set('states', '')),
    edited: { at: 'states', states: 'zero UTF-8 bytes' },
  },
  {
    name: 'states-over-byte-limit',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
    note: '683 three-byte characters: 2049 UTF-8 bytes, above the 2048-byte ceiling despite the smaller character count.',
    document: mutant((root) => root.set('states', '\u754c'.repeat(683))),
    edited: { at: 'states', states: '2049 UTF-8 bytes' },
  },
  {
    name: 'sentence-that-forges-a-line',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
    note: "The writer's sentence carrying a right-to-left override, which would make the printed row a reader " +
      'sees stop being the bytes the receipt carries. This is the one position of the layout that is opaque text, ' +
      'and it is read under the printed-line class the rest of the estate holds its text to.',
    document: mutant((root) => root.set('states', 'erased \u202E entirely')),
    edited: { at: 'states', states: 'a character that reorders the line it is printed on' },
  },
  {
    name: 'version-two',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
    note: 'A second version of a format that has never had a first one in another shape. The number moves when ' +
      'bytes in the older shape exist, and none do, so this is refused as a version before one member of it is ' +
      'read.',
    document: mutant((root) => root.set('v', 2)),
    edited: { at: 'v', states: 'a version no layout this package reads defines' },
  },
  {
    name: 'another-content-type',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
    note: 'These very bytes under the content type of a pack. One deployment key seals six documents, each of ' +
      'which passes its own checks, and the field that says which claim a reader is holding is answered before ' +
      'a key is consulted.',
    document: resealed(encodeCanonical(payloadOf(HONEST)), SIGNER, headerMap([], 'ashaveri/pack')),
    edited: { at: 'protected header label 3', states: 'a content type other than this formats own' },
  },
  {
    name: 'header-carrying-a-fourth-label',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
    note: 'A header parameter the format does not declare. Its bytes are hashed into the signature, so a reader ' +
      'that took three labels out of a header carrying a fourth would hand on a document other than the one the ' +
      'issuer signed.',
    document: resealed(encodeCanonical(payloadOf(HONEST)), SIGNER, headerMap([[9, 1]])),
    edited: { at: 'protected header', states: 'a label the format does not define' },
  },
  {
    name: 'a-pack-handed-as-a-receipt',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
    note: 'A document of another family, offered whole. The refusal is the content type at the header and not a ' +
      'manifest fault, because none of these bytes is a member of this layout.',
    document: OBJECT_BYTES,
    edited: { at: 'the whole document', states: 'a redaction manifest read where a destruction receipt was expected' },
  },
  {
    name: 'signature-corrupted',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: null },
    note: 'The honest header and payload with one signature bit flipped. The structure is valid; verification under the correct key refuses the signature.',
    document: CORRUPTED_SIGNATURE,
    edited: { at: 'signature', states: 'one bit changed without re-signing' },
  },
  {
    name: 'whole-bytes-no-key-handed',
    arm: 'refuse',
    verification: { key: null, objectBytes: null },
    note: 'The honest receipt, handed to the verifying door with no key designation of any kind. The document is ' +
      'whole and the reader is simply not in a position to prove it, which is a different finding from a ' +
      'malformed manifest and is refused as its own code.',
    document: HONEST,
    edited: { at: 'the call', states: 'neither a public key nor a resolver handed to the reader' },
  },
  {
    name: 'key-of-another-caller',
    arm: 'refuse',
    verification: { key: 'another-callers-key', objectBytes: null },
    note: 'Whole bytes verified against a key the reader was configured with and the receipt does not name. A ' +
      'wrong key and an edited document send an operator to two places, so they are refused separately.',
    document: HONEST,
    edited: { at: 'the call', states: 'a public key other than the kid the header carries' },
  },
  {
    name: 'other-bytes-than-the-designation',
    arm: 'refuse',
    verification: {
      key: 'signer',
      objectBytes: signRedaction(
        { v: 1, at: AT, pack: new Uint8Array(32).fill(7), removed: ['receipt-2'], reduced: new Uint8Array(32).fill(9), states: 'a second removal' },
        SIGNER,
      ),
    },
    note: 'The designated digest and a document that is not the one it designates, both handed over. Either half ' +
      'may be whole; what is refused is reading this receipt against those bytes.',
    document: HONEST,
    edited: { at: 'the call', states: 'bytes hashing elsewhere than the object the manifest carries' },
  },
  {
    name: 'designated-bytes-of-another-kind',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: OBJECT_BYTES },
    note: 'The digest matches and the kind does not: the bytes are a redaction and the receipt calls them a ' +
      'pack. This is what the pair is required for, and no keyword and no other refusal in this family reports it.',
    document: signDestructionReceipt(baseManifest({ kind: 'ashaveri/pack' }), SIGNER),
    edited: { at: 'kind against the designated bytes own header', states: 'a document type the designation does not carry' },
  },
  {
    name: 'designated-bytes-not-a-signed-document',
    arm: 'refuse',
    verification: { key: 'signer', objectBytes: OPAQUE_BYTES },
    note: 'The digest matches and the bytes are not a signed document of any kind. The only question asked of ' +
      'them here is whether they are the document the receipt names, and one answer covers both ways it fails.',
    document: signDestructionReceipt(baseManifest({ object: destructionObjectDigest(OPAQUE_BYTES) }), SIGNER),
    edited: { at: 'kind against the designated bytes', states: 'bytes no envelope reader opens' },
  },
  {
    name: 'writer-refuses-to-sign-overreach',
    arm: 'refuse',
    verification: null,
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
    verification: null,
    note: 'Again not a document. The encoder is asked to sign a receipt that leaves one copy class unstated and ' +
      'runs its own reader over the bytes before it signs them, so the refusal arrives where the bytes are made.',
    document: new Uint8Array(0),
    writer: () => signDestructionReceipt(baseManifest({ reach: reachTable().slice(0, 4) }), SIGNER),
    edited: { at: 'signDestructionReceipt', states: 'the writer running its own reader before signing' },
  },
];

function published(one: Row): DestructionReceiptVector {
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
    verification: one.verification === null ? null : {
      key: one.verification.key,
      objectBase64Url: one.verification.objectBytes === null ? null : toBase64Url(one.verification.objectBytes),
    },
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
            'its kid by semantic contract; width validation cannot detect key material. The receipt requires a distinct signer, not proof of signing chronology.',
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
            'Test-only keys, fully reproducible with signingKeyFromSeed over sha256 of each published label. ' +
            'These labels reveal the test seeds by construction and must never be used for production keys.',
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
