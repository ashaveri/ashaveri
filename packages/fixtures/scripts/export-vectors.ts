import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  decodeCanonical,
  encodeCanonical,
  encodeExportManifest,
  encodeExportProtectedHeader,
  exportRecordDigest,
  exportSigStructure,
  fromBase64Url,
  sealExport,
  signCoseSign1,
  signingKeyFromSeed,
  toBase64Url,
  toHex,
  verifyExport,
  type ExportAnchoredCollection,
  type ExportChainedItem,
  type ExportCollection,
  type ExportItem,
  type ExportManifest,
  type SigningKey,
} from '@ashaveri/receipt';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

/**
 * The technical export vectors: whole documents, the arguments a reader is handed beside them, and the
 * verdict each document owes.
 *
 * Every case is written twice on purpose. `expected` is data stated by whoever chose the case, and the run
 * at the bottom asks the published reader the same question and stops the generation when the two answers
 * disagree. That is what keeps a committed file from lying about itself while keeping its verdicts
 * independent of the reader at the moment they are asserted: the reader is the thing under test there, and
 * here it is only a witness.
 *
 * A document that is meant to be refused is assembled from the container's own published pieces,
 * `encodeExportProtectedHeader`, `encodeExportManifest`, `exportSigStructure` and `sealExport`.
 * `signExport` is deliberately unused: it will not produce bytes its reader rejects, and a fault case is
 * exactly that. Where a case edits a whole
 * document, one position of the manifest map changes and the bytes are re-sealed under the same key, so
 * the only thing wrong with them is the edit. An honest document whose chain is broken by construction is
 * sealed the same way, with the chain recomputed over the records it carries.
 */

/** One Ed25519 seed for the whole suite, published beside the file that uses it and test-only. */
const KEY: SigningKey = signingKeyFromSeed(new Uint8Array(32).fill(23));
const CLOCK = 1_772_000_000;

const encoded = (text: string): Uint8Array => new TextEncoder().encode(text);
const digest = (bytes: Uint8Array): Uint8Array => sha256(bytes);
const ZEROS = new Uint8Array(32);

/** The originals the documents below are built from, as the writer of an export would have them. */
const RECEIPTS = ['first receipt', 'second receipt', 'third receipt'].map((text) => encoded(text));
const CONTRACT = encoded('the contract, as it was filed');
const SCREENSHOT = encoded('a ticket image, in bytes');

/** The companion names this suite uses, and the content of the file travelling under each. */
const COMPANION_FILES: ReadonlyMap<string, Uint8Array> = new Map([
  ['contract.pdf', CONTRACT],
  ['ticket.png', SCREENSHOT],
]);

interface ItemSpec {
  readonly id: string;
  readonly iat: number;
  /** The original inside the document, when the item carries one. */
  readonly bytes?: Uint8Array;
  /** The name beside the document, when the item references one. */
  readonly companion?: string;
}

function inlineItem(one: ItemSpec): ExportItem {
  const bytes = one.bytes ?? encoded('');
  return { id: one.id, iat: one.iat, d: digest(bytes), orig: { k: 'inline', bytes } };
}

function companionItem(one: ItemSpec): ExportItem {
  const name = one.companion ?? '';
  // A name this file has no content for still gets a digest, which is what a case about the name itself
  // needs: the reader refuses `../outside` before it ever asks what the file holds.
  const bytes = COMPANION_FILES.get(name) ?? encoded(name);
  return { id: one.id, iat: one.iat, d: digest(bytes), orig: { k: 'companion', name } };
}

function itemOf(one: ItemSpec): ExportItem {
  return one.bytes === undefined ? companionItem(one) : inlineItem(one);
}

function chainedItem(one: ItemSpec, prev: Uint8Array): ExportChainedItem {
  const bytes = one.bytes ?? encoded('');
  return { id: one.id, iat: one.iat, d: digest(bytes), p: prev, orig: { k: 'inline', bytes } };
}

/** The records of a run, chained in the order given from an anchor of thirty-two zero bytes. */
function run(items: readonly ItemSpec[]): { collection: ExportAnchoredCollection; head: Uint8Array } {
  let prev: Uint8Array = ZEROS;
  const records = items.map((one) => {
    const next = chainedItem(one, prev);
    // The frame hashes the original the item carries, which for a chained item is the one inside the
    // document: the spec this record was built from is where those bytes were named.
    const bytes = one.bytes ?? encoded('');
    prev = exportRecordDigest({ id: next.id, iat: next.iat, p: next.p, bytes });
    return next;
  });
  return { collection: { k: 'anchored', anchor: ZEROS, head: prev, items: records }, head: prev };
}

function plain(items: readonly ItemSpec[]): ExportCollection {
  return { k: 'plain', items: items.map(itemOf) };
}

function voided(states = 'the store held nothing for the period asked for'): ExportCollection {
  return { k: 'void', states };
}

function manifestFor(collection: ExportCollection, over: Partial<ExportManifest> = {}): ExportManifest {
  return {
    v: 1,
    at: CLOCK,
    assessment: { k: 'none', states: 'no legal assessment was made of this material' },
    collection,
    claim: { made: CLOCK - 120, by: 'Amir, records office', kind: 'provenance', states: 'copied by hand from one store on one machine' },
    ...over,
  };
}

/** The ordinary path: a whole document, assembled and signed with the key this suite publishes. */
function honest(collection: ExportCollection): Uint8Array {
  return underContentType(EXPORT_TYPE, encodeExportManifest(manifestFor(collection)));
}

const EXPORT_TYPE = 'ashaveri/export';

/** The same manifest under another content type, which is how two containers share one key. */
function underContentType(contentType: string, payload: Uint8Array): Uint8Array {
  const header = encodeExportProtectedHeader(KEY.kid, contentType);
  return sealExport(header, payload, ed25519.sign(exportSigStructure(header, payload), KEY.privateKey));
}

/** One position of a whole manifest changed, and the document re-sealed under the same key. */
function mutant(collection: ExportCollection, edit: (root: Map<unknown, unknown>) => void): Uint8Array {
  const root = asMap(encodeExportManifest(manifestFor(collection)));
  edit(root);
  return underContentType(EXPORT_TYPE, encodeCanonical(root));
}

function asMap(payload: Uint8Array): Map<unknown, unknown> {
  const decoded = decodeCanonical(payload);
  if (!(decoded instanceof Map)) throw new Error('a manifest this file encoded did not come back as a map');
  return decoded;
}

function elementsOf(bytes: Uint8Array): unknown[] {
  const contents = (decodeCanonical(bytes) as { contents?: unknown }).contents;
  if (!Array.isArray(contents)) throw new Error('a document this file sealed is not a four-element envelope');
  return contents;
}

function collectionOf(root: Map<unknown, unknown>): Map<unknown, unknown> {
  const collection = root.get('collection');
  if (!(collection instanceof Map)) throw new Error('a manifest this file encoded carries no collection map');
  return collection;
}

function firstItem(root: Map<unknown, unknown>): Map<unknown, unknown> {
  const items = collectionOf(root).get('items');
  if (!Array.isArray(items) || !(items[0] instanceof Map)) throw new Error('this case builds a collection with an item in it');
  return items[0];
}

function blockOf(root: Map<unknown, unknown>, member: string): Map<unknown, unknown> {
  const value = root.get(member);
  if (!(value instanceof Map)) throw new Error(`this case builds a manifest with a ${member} block`);
  return value;
}

/** The envelope of a whole document with one byte of its payload flipped and the old signature kept. */
function withPayloadFlipped(bytes: Uint8Array, at: number): Uint8Array {
  const [header, , payload, signature] = elementsOf(bytes);
  const edited = new Uint8Array(payload as Uint8Array);
  edited[at] = (edited[at] ?? 0) ^ 0x01;
  return sealExport(header as Uint8Array, edited, signature as Uint8Array);
}

/** A pack v1 manifest, member for member as `pack.cddl` names them, over the same key. */
function packManifest(): Uint8Array {
  const receipt = signCoseSign1(encodeCanonical(new Map<string, unknown>([['v', 1], ['iss', 'ashaveri-pack-fixture']])), KEY);
  return encodeCanonical(
    new Map<string, unknown>([
      ['v', 1],
      ['at', CLOCK],
      ['span', new Map<string, unknown>([['from', CLOCK - 600], ['to', CLOCK]])],
      ['chain', new Map<string, unknown>([['anchor', ZEROS], ['head', digest(receipt)]])],
      [
        'duty',
        new Map<string, unknown>([
          ['art', '19(1)'],
          ['rev', CLOCK - 30],
          ['required', 15_897_600],
          ['held', 15_897_600],
        ]),
      ],
      [
        'items',
        [
          new Map<string, unknown>([
            ['id', 'receipt-0'],
            ['iat', CLOCK - 300],
            ['prev', ZEROS],
            ['receipt', receipt],
          ]),
        ],
      ],
    ]),
  );
}

/** What a reader is handed beside the bytes: companions it was given, endpoints it holds, the key it uses. */
interface Handed {
  readonly companions?: Array<{ name: string; bytesBase64Url: string }>;
  readonly expectedAnchorHex?: string;
  readonly expectedHeadHex?: string;
  readonly keySeed?: number;
}

function companionList(items: readonly ItemSpec[]): Array<{ name: string; bytesBase64Url: string }> {
  return items
    .filter((one): one is ItemSpec & { companion: string } => one.companion !== undefined)
    .map((one) => ({ name: one.companion, bytesBase64Url: toBase64Url(COMPANION_FILES.get(one.companion) ?? encoded('')) }));
}

function companionMap(handed?: Handed): Map<string, Uint8Array> | undefined {
  if (handed?.companions === undefined) return undefined;
  return new Map(handed.companions.map((one) => [one.name, fromBase64Url(one.bytesBase64Url)]));
}

function fromHex(text: string): Uint8Array {
  const bytes = new Uint8Array(text.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}

/** One case: the document, the read it is given, and the verdict a conforming reader owes it. */
interface Case {
  readonly name: string;
  readonly note: string;
  readonly bytes: Uint8Array;
  readonly handed?: Handed;
  readonly expected: string;
  /** The item a refusal names, where the code reports by naming one. */
  readonly item?: string;
  /** Which arm a passing read reports, so the outcome is pinned rather than merely accepted. */
  readonly outcome?: 'anchored' | 'plain' | 'void';
  /** The order a passing walk reaches, which is not the order of the array. */
  readonly walk?: readonly string[];
  /** The one position a fault case moved, published so a port can find it without a diff. */
  readonly edited?: string;
}

const THREE: readonly ItemSpec[] = [
  { id: 'r-0', iat: CLOCK, bytes: RECEIPTS[0] },
  { id: 'r-1', iat: CLOCK + 1, bytes: RECEIPTS[1] },
  { id: 'r-2', iat: CLOCK + 2, bytes: RECEIPTS[2] },
];

const HONEST_RUN = run(THREE);
const SHORTER_RUN = run([THREE[0]!, THREE[2]!]);
const COLLIDED = run([THREE[0]!, { id: 'r-0', iat: CLOCK + 1, bytes: RECEIPTS[1] }, THREE[2]!]);
const CONTRACT_ITEM: readonly ItemSpec[] = [{ id: 'contract', iat: CLOCK - 60, bytes: CONTRACT }];
const CONTRACT_FILE: readonly ItemSpec[] = [{ id: 'contract', iat: CLOCK - 60, companion: 'contract.pdf' }];

/** The honest run of three, with a different array of records and endpoint beside it. */
function anchoredWith(items: readonly ExportChainedItem[], head: Uint8Array): ExportAnchoredCollection {
  return { k: 'anchored', anchor: ZEROS, head, items };
}

const THREE_ITEMS = HONEST_RUN.collection.items;
const RIVAL = chainedItem({ id: 'r-x', iat: CLOCK, bytes: encoded('a rival first record') }, ZEROS);
const PARKED = chainedItem({ id: 'parked', iat: CLOCK + 9, bytes: encoded('a record from another chain') }, digest(encoded('a predecessor nobody here names')));

const CASES: readonly Case[] = [
  {
    name: 'well-formed-void',
    note: 'An export that carries nothing and says so. The collection is the void arm and states its outcome, so a reader reports the emptiness and is given no items to count and no walk to have completed.',
    bytes: honest(voided()),
    expected: 'verify-ok',
    outcome: 'void',
  },
  {
    name: 'well-formed-plain',
    note: 'One original inside the document, no chain claimed about it and no endpoints stated, which is the shape a contract a customer asked for travels in.',
    bytes: honest(plain(CONTRACT_ITEM)),
    expected: 'verify-ok',
    outcome: 'plain',
  },
  {
    name: 'well-formed-anchored',
    note: 'Three receipts chained from an anchor of thirty-two zero bytes to a signed head, read by a reader that pins both endpoints. The walk follows the links, so the order of the array is none of its business.',
    bytes: honest(HONEST_RUN.collection),
    handed: { expectedAnchorHex: toHex(ZEROS), expectedHeadHex: toHex(HONEST_RUN.head) },
    expected: 'verify-ok',
    outcome: 'anchored',
    walk: ['r-0', 'r-1', 'r-2'],
  },
  {
    name: 'companion-handed-and-checked',
    note: 'One original travelling beside the document under a name, and the file handed to the reader: the item digest is checked against those bytes and the export passes.',
    bytes: honest(plain(CONTRACT_FILE)),
    handed: { companions: companionList(CONTRACT_FILE) },
    expected: 'verify-ok',
    outcome: 'plain',
  },
  {
    name: 'companion-not-handed',
    note: 'The same document read without the file beside it. The item is whole and the document is not at fault: the reader says which name it was not given rather than reporting a set of material it never looked at.',
    bytes: honest(plain(CONTRACT_FILE)),
    expected: 'EXPORT_ORIGINAL_UNAVAILABLE',
    item: 'contract',
  },
  {
    name: 'companion-substituted',
    note: 'A companion file handed under the right name whose bytes are not the ones the item digests, which is the swap a handover carried through a folder of loose files meets.',
    bytes: honest(plain(CONTRACT_FILE)),
    handed: { companions: [{ name: 'contract.pdf', bytesBase64Url: toBase64Url(encoded('a different contract entirely')) }] },
    expected: 'EXPORT_DIGEST_MISMATCH',
    item: 'contract',
  },
  {
    name: 'original-bytes-edited',
    note: 'The bytes of one item edited after assembly, with the digest beside them left as it was and the manifest re-sealed so the signature is good. This is the handover that was changed between the deployment and the reading, and it is the item digest that notices.',
    bytes: mutant(plain(CONTRACT_ITEM), (root) => {
      blockOf(firstItem(root), 'orig').set('bytes', encoded('the contract, with one clause removed'));
    }),
    expected: 'EXPORT_DIGEST_MISMATCH',
    item: 'contract',
    edited: 'the bytes of the inline original of item contract',
  },
  {
    name: 'payload-byte-changed',
    note: 'One byte of a signed manifest flipped after the fact with the old signature left in place. The structure still reads and the signature is what refuses it, which is the order a reader has to keep.',
    bytes: withPayloadFlipped(honest(HONEST_RUN.collection), 5),
    expected: 'INVALID_SIGNATURE',
    edited: 'the sixth byte of the payload, under the signature that was made for it',
  },
  {
    name: 'empty-collection-unstated',
    note: 'The anchored arm with an empty array, which is the shape this format does not allow: emptiness belongs to the void arm, where it is stated. A walk over no items would close vacuously and read as evidence.',
    bytes: mutant(HONEST_RUN.collection, (root) => {
      collectionOf(root).set('items', []);
    }),
    expected: 'EXPORT_BAD_MANIFEST',
    edited: 'collection.items to the empty array',
  },
  {
    name: 'unknown-manifest-member',
    note: 'A member the closed manifest does not define. It is refused rather than dropped, because a member a reader ignores is a claim inside the signature that nobody looked at.',
    bytes: mutant(HONEST_RUN.collection, (root) => {
      root.set('retention', 'nine hundred days');
    }),
    expected: 'EXPORT_BAD_MANIFEST',
    edited: "a member named 'retention' added to the manifest",
  },
  {
    name: 'unknown-item-member',
    note: 'The same rule one map down: an item carrying a member the item rule does not name, which is where a second claim about an original would arrive.',
    bytes: mutant(HONEST_RUN.collection, (root) => {
      firstItem(root).set('label', 'requested by the customer');
    }),
    expected: 'EXPORT_BAD_MANIFEST',
    edited: "a member named 'label' added to the first item",
  },
  {
    name: 'unknown-assessment-member',
    note: 'And beside the assessment block, whose two members are the whole of what this version states about assessment.',
    bytes: mutant(HONEST_RUN.collection, (root) => {
      blockOf(root, 'assessment').set('basis', 'advice of counsel');
    }),
    expected: 'EXPORT_BAD_MANIFEST',
    edited: "a member named 'basis' added to the assessment",
  },
  {
    name: 'wrong-content-type',
    note: 'An export manifest inside a receipt envelope. One key signs both containers, and a reader that took this for an export would report a handover as an attestation about one response.',
    bytes: underContentType('ashaveri/receipt', encodeExportManifest(manifestFor(HONEST_RUN.collection))),
    expected: 'EXPORT_BAD_HEADER',
  },
  {
    name: 'pack-read-as-export',
    note: 'A pack v1 document, signed by the same key and handed to this reader. Its typ is the pack and its manifest names six members this format does not, so it is refused at the header before one member is read.',
    bytes: underContentType('ashaveri/pack', packManifest()),
    expected: 'EXPORT_BAD_HEADER',
  },
  {
    name: 'manifest-version-unknown',
    note: 'A manifest declaring a version no format has used. The answer is about the reach of the reader and not about the bytes being broken.',
    bytes: mutant(HONEST_RUN.collection, (root) => {
      root.set('v', 2);
    }),
    expected: 'EXPORT_UNSUPPORTED_VERSION',
    edited: 'v to 2',
  },
  {
    name: 'assessment-label-of-another-version',
    note: 'An assessment block carrying a label this version defines no reading for. Guessing which statement the writer meant would be this container answering the question it states it did not answer.',
    bytes: mutant(HONEST_RUN.collection, (root) => {
      blockOf(root, 'assessment').set('k', 'assessed');
    }),
    expected: 'EXPORT_UNSUPPORTED_LABEL',
    edited: "assessment.k to 'assessed'",
  },
  {
    name: 'collection-arm-unknown',
    note: 'A collection whose label names a shape this version does not define, beside the three it does.',
    bytes: mutant(HONEST_RUN.collection, (root) => {
      collectionOf(root).set('k', 'sealed');
    }),
    expected: 'EXPORT_UNSUPPORTED_LABEL',
    edited: "collection.k to 'sealed'",
  },
  {
    name: 'claim-kind-unknown',
    note: 'A claim whose kind is neither provenance nor custody, which are the two labels this version can mean.',
    bytes: mutant(HONEST_RUN.collection, (root) => {
      blockOf(root, 'claim').set('kind', 'notarised');
    }),
    expected: 'EXPORT_UNSUPPORTED_LABEL',
    edited: "claim.kind to 'notarised'",
  },
  {
    name: 'claim-after-assembly',
    note: 'A claim stamped after the assembly instant of the document carrying it: two signed members contradicting each other, which is a malformed export and not a deployment that misremembered.',
    bytes: mutant(HONEST_RUN.collection, (root) => {
      blockOf(root, 'claim').set('made', CLOCK + 1);
    }),
    expected: 'EXPORT_BAD_MANIFEST',
    edited: 'claim.made to one second after at',
  },
  {
    name: 'companion-name-is-a-path',
    note: 'A companion whose name climbs out of the directory the export arrived in. This reader opens nothing, so the refusal is the format rule about the member rather than a guard of its own.',
    bytes: honest(plain([{ id: 'contract', iat: CLOCK - 60, companion: '../outside' }])),
    expected: 'EXPORT_BAD_MANIFEST',
  },
  {
    name: 'duplicate-item-id',
    note: 'Two items answering to one name, chained honestly over the records as given so that every link is right: the name sits inside the hash and both spellings of it hash perfectly, so nothing about a link reports the collision, and a refusal that names an item would mean whichever of the two the reader met first.',
    bytes: honest(COLLIDED.collection),
    expected: 'EXPORT_DUPLICATE_ID',
    item: 'r-0',
  },
  {
    name: 'walk-short-of-head',
    note: 'The middle record of a run lifted out and nothing else touched, so the successor still names the predecessor it had and the head is the one the whole run hashed to. What remains is whole by its own digest and the walk stops at a hole, which is the deletion an endpoint exists to make visible.',
    bytes: honest(anchoredWith([THREE_ITEMS[0]!, THREE_ITEMS[2]!], HONEST_RUN.head)),
    expected: 'EXPORT_CHAIN_BROKEN',
  },
  {
    name: 'walk-forked-at-the-anchor',
    note: 'Two items claiming the anchor as their predecessor, the rest of the run untouched. The walk would take whichever it met first and report the other as missing, so the fork is refused rather than resolved by arrival order.',
    bytes: honest(anchoredWith([RIVAL, ...THREE_ITEMS], HONEST_RUN.head)),
    expected: 'EXPORT_CHAIN_BROKEN',
  },
  {
    name: 'rechained-to-a-shorter-head',
    note: 'The same omission with the hole closed by re-chaining and the head the writer would have signed for that shorter run. The links are perfect, so what reaches the deletion is the endpoint the reader brought rather than the one the document chose.',
    bytes: honest(SHORTER_RUN.collection),
    handed: { expectedHeadHex: toHex(HONEST_RUN.head) },
    expected: 'EXPORT_ENDPOINT_MISMATCH',
  },
  {
    name: 'hole-closed-without-a-pin',
    note: 'That same shorter run read by a reader that brought no endpoint: every check the container supports passes, and the deletion is invisible. This is the bound section 5.2 states from the other side, and it is published so no port mistakes a closing walk for a complete store.',
    bytes: honest(SHORTER_RUN.collection),
    expected: 'verify-ok',
    outcome: 'anchored',
    walk: ['r-0', 'r-2'],
  },
  {
    name: 'item-parked-beside-the-run',
    note: 'A record handed over beside a run it is not part of, naming a predecessor nobody here carries. The walk reaches the signed head and never had to visit it, so the count of what the walk reached against the array is the half of the rule with eyes for it.',
    bytes: honest(anchoredWith([...THREE_ITEMS, PARKED], HONEST_RUN.head)),
    expected: 'EXPORT_ITEM_UNREACHED',
    item: 'parked',
  },
  {
    name: 'record-stamp-moved-after-chaining',
    note: 'One item of a signed run restamped after its record was hashed, so the digest the next item names no longer comes out. The original still hashes to its own digest, which is why a reader that checked digests alone would pass it.',
    bytes: honest({
      ...HONEST_RUN.collection,
      items: THREE_ITEMS.map((one, index) => (index === 1 ? { ...one, iat: one.iat + 1 } : one)),
    }),
    expected: 'EXPORT_CHAIN_BROKEN',
  },
  {
    name: 'endpoint-head-disagrees',
    note: 'A whole, self-consistent run read by a reader coming holding a different head. Nothing about the document is wrong and the two are not the same run, which is the only finding a signed endpoint on its own can support.',
    bytes: honest(HONEST_RUN.collection),
    handed: { expectedHeadHex: toHex(digest(encoded('the head of another handover'))) },
    expected: 'EXPORT_ENDPOINT_MISMATCH',
  },
  {
    name: 'endpoint-pinned-on-a-collection-that-claims-none',
    note: 'The same reader and the same pin, against a plain collection. A pin is never left unused: a collection stating no endpoints cannot be the run the reader was told to expect.',
    bytes: honest(plain(CONTRACT_ITEM)),
    handed: { expectedHeadHex: toHex(HONEST_RUN.head) },
    expected: 'EXPORT_ENDPOINT_MISMATCH',
  },
  {
    name: 'wrong-key-offered',
    note: 'The document read against another key: the header kid and the key in the reader hand disagree, which is an answer about configuration and not about tampering.',
    bytes: honest(HONEST_RUN.collection),
    handed: { keySeed: 29 },
    expected: 'EXPORT_KID_MISMATCH',
  },
  {
    name: 'untagged-envelope',
    note: 'The four elements of a COSE_Sign1 with the tag around them missing, which is the one structural fact a reader cannot recover by being tolerant.',
    bytes: encodeCanonical(elementsOf(honest(HONEST_RUN.collection))),
    expected: 'NOT_COSE_SIGN1',
  },
  {
    name: 'truncated-document',
    note: 'The first forty bytes of a whole document, so the envelope itself does not decode and nothing about a manifest is ever reached.',
    bytes: honest(HONEST_RUN.collection).slice(0, 40),
    expected: 'EXPORT_MALFORMED_CBOR',
  },
];

/** What the published reader answers, which the case above states as data and `main` checks. */
function verdictOf(one: Case): string {
  const key = one.handed?.keySeed === undefined ? KEY : signingKeyFromSeed(new Uint8Array(32).fill(one.handed.keySeed));
  try {
    const verified = verifyExport(one.bytes, key.publicKey, {
      companions: companionMap(one.handed),
      expectedAnchor: one.handed?.expectedAnchorHex === undefined ? undefined : fromHex(one.handed.expectedAnchorHex),
      expectedHead: one.handed?.expectedHeadHex === undefined ? undefined : fromHex(one.handed.expectedHeadHex),
    });
    if (one.outcome !== undefined && verified.outcome.kind !== one.outcome) {
      throw new Error(`${one.name}: the reader reported the ${verified.outcome.kind} arm, which this file says is ${one.outcome}`);
    }
    if (one.walk !== undefined) {
      if (verified.outcome.kind !== 'anchored') throw new Error(`${one.name}: a walk was promised on a ${verified.outcome.kind} collection`);
      const order = verified.outcome.walked.map((each) => each.id);
      if (order.join(' ') !== one.walk.join(' ')) {
        throw new Error(`${one.name}: the walk reached ${order.join(', ')}, which this file says is ${one.walk.join(', ')}`);
      }
    }
    return 'verify-ok';
  } catch (err) {
    if (err instanceof Error && 'code' in err && typeof err.code === 'string') {
      if (one.item !== undefined && !err.message.includes(one.item)) {
        throw new Error(`${one.name}: ${err.code} did not name the item this file says it names (${one.item})`);
      }
      return err.code;
    }
    throw new Error(`${one.name}: the reader raised something with no code (${String(err)})`);
  }
}

function published(one: Case): Record<string, unknown> {
  return {
    name: one.name,
    note: one.note,
    documentBase64Url: toBase64Url(one.bytes),
    documentByteLength: one.bytes.length,
    read: one.handed ?? {},
    verdict: one.expected,
    ...(one.item === undefined ? {} : { item: one.item }),
    ...(one.outcome === undefined ? {} : { outcome: one.outcome }),
    ...(one.walk === undefined ? {} : { walk: one.walk }),
    ...(one.edited === undefined ? {} : { edited: one.edited }),
  };
}

/**
 * The one member a chained item has and an unchained item has not, projected only when the item carries
 * one, and in the position the format puts it: between the digest of the original and the original.
 */
function chained(one: ExportItem | ExportChainedItem): Record<string, unknown> {
  return 'p' in one ? { p: toHex(one.p) } : {};
}

/** The JSON projection of one manifest, in the shape its twin describes: lowercase hex for bytes. */
function projectedExport(manifest: ExportManifest): Record<string, unknown> {
  const orig = (item: ExportItem): Record<string, unknown> =>
    item.orig.k === 'inline' ? { k: 'inline', bytes: toHex(item.orig.bytes) } : { k: 'companion', name: item.orig.name };
  const item = (one: ExportItem | ExportChainedItem): Record<string, unknown> => ({
    id: one.id,
    iat: one.iat,
    d: toHex(one.d),
    ...chained(one),
    orig: orig(one),
  });
  const collection = manifest.collection;
  return {
    protectedHeader: { alg: 'EdDSA', kid: toHex(KEY.kid), typ: EXPORT_TYPE },
    payload: {
      v: manifest.v,
      at: manifest.at,
      assessment: { k: manifest.assessment.k, states: manifest.assessment.states },
      collection:
        collection.k === 'void'
          ? { k: 'void', states: collection.states }
          : {
              ...(collection.k === 'anchored' ? { k: 'anchored', anchor: toHex(collection.anchor), head: toHex(collection.head) } : { k: 'plain' }),
              items: [...collection.items].map(item),
            },
      claim: { made: manifest.claim.made, by: manifest.claim.by, kind: manifest.claim.kind, states: manifest.claim.states },
    },
  };
}

function main() {
  for (const one of CASES) {
    const observed = verdictOf(one);
    if (observed !== one.expected) {
      throw new Error(`${one.name}: the reader this file is measured by answers ${observed}, not the ${one.expected} it states`);
    }
  }
  const names = CASES.map((one) => one.name);
  if (new Set(names).size !== names.length) throw new Error('two cases of this suite share a name');
  const verdicts = new Set(CASES.map((one) => one.expected));
  const keyHex = toHex(KEY.publicKey);

  writeFileSync(
    join(DATA, 'export-v1.json'),
    JSON.stringify(
      {
        version: 1,
        description:
          'Technical export documents, the arguments a reader is handed beside them, and the verdict each one owes: three well-formed shapes, and one refusal for every fault the format names.',
        layout: {
          format: 'packages/receipt/export.cddl',
          twin: 'packages/receipt/schemas/export-v1.schema.json',
          document: 'docs/export-v1.md',
          reader: 'verifyExport and decodeExport in @ashaveri/receipt',
          contentType: EXPORT_TYPE,
          headerLabels: { alg: 1, typ: 3, kid: 4 },
          framing: 'docs/receipt-spec.md section 5.2',
          recordDigest: 'sha256 over 0x00 || p || iat as eight big-endian bytes || the byte length of id as two big-endian bytes || id || the original bytes',
          itemDigest: 'sha256 of the exact original bytes, held in the item field d',
          manifestFields: ['v', 'at', 'assessment', 'collection', 'claim'],
          collectionArms: ['anchored', 'plain', 'void'],
          originalArms: ['inline', 'companion'],
          encodings: 'documents and byte strings unpadded base64url, digests and fixed widths lowercase hex',
          anchor: 'thirty-two zero bytes, which is the head of an empty chain',
          key: { publicKeyHex: keyHex, seed: 'thirty-two bytes of 23', note: 'test-only, published so a port can produce these signatures itself, and protecting nothing' },
          assembled: 'every document here is built from encodeExportManifest, exportSigStructure and sealExport. A fault case edits one position of the manifest map and re-seals under the same key, so the only thing wrong with the bytes is the edit; the signature failures either flip a byte of a payload under the signature made for it or read a document under another key.',
          verdictFields: ['verdict', 'item', 'outcome', 'walk', 'edited'],
          codes: [...verdicts].sort(),
        },
        vectors: CASES.map(published),
        crossReading: {
          note: 'Two containers, two contracts, and a reader of one refusing the other is the property that keeps them separate. Each direction is published with the document that arrives and the answer it gets, and neither answer depends on which key signed it.',
          cases: [
            {
              name: 'export-as-pack',
              note: 'A whole export manifest, projected to JSON as its own twin describes it, given to the pack projection: the pack map is closed at six members and names none of the three an export states, so a pack reader of any shape refuses it before it looks at an item.',
              manifest: projectedExport(manifestFor(HONEST_RUN.collection)),
              expected: 'refused',
            },
            {
              name: 'pack-as-export',
              note: 'A pack v1 document signed by the same key, given to the export reader: the content type answers it before a member of the manifest is read.',
              documentBase64Url: toBase64Url(underContentType('ashaveri/pack', packManifest())),
              expected: 'EXPORT_BAD_HEADER',
            },
          ],
        },
      },
      null,
      2,
    ) + '\n',
  );

  for (const one of CASES) console.log(`${one.name}: ${one.expected}`);
}

main();
