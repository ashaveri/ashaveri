import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  MODEL_INVENTORY_ASSERTED_MODEL_FIELDS,
  MODEL_INVENTORY_BOUND_MODEL_FIELDS,
  MODEL_INVENTORY_LIMITS,
  MODEL_INVENTORY_POINTERS,
  MODEL_INVENTORY_POINTER_CITATIONS,
  ReceiptError,
  decodeSealedDeploymentManifest,
  encodeModelInventory,
  equalBytes,
  fromBase64Url,
  modelInventoryBytes,
  parseModelInventory,
  sealDeploymentManifest,
  signExport,
  signingKeyFromSeed,
  toBase64Url,
  toHex,
  verifyExport,
  verifyModelInventory,
  type ExportManifest,
  type ModelInventoryRecord,
} from '@ashaveri/receipt';
import { loadSealedManifestVectors } from '@ashaveri/fixtures';
import { labeled } from './seed.ts';
import { FIXED_IAT, fixtureKey } from './receipt-envelope.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

const encoded = (text: string): Uint8Array => new TextEncoder().encode(text);
const decoded = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

/**
 * The fixture deployment is the one the published receipt family came from: the manifest row
 * `paired-with-the-published-receipt-family` of `manifest-v1.json` states that deployment's issuer,
 * instance and single model, and its seal is made by the key that suite publishes as signing the
 * manifests a reader designates. The record's bound fields are copied out of that row's own payload
 * rather than typed beside it, so the designation, the bound values and the manifest a reader is handed
 * are one document's facts. The asserted fields are the fixture deployer's statements, labeled fixture
 * by the record's own `prov`, and nothing here describes a live deployment.
 */
const MANIFEST_FAMILY = loadSealedManifestVectors();
const PAIRED_ROW = MANIFEST_FAMILY.vectors.find((one) => one.name === 'paired-with-the-published-receipt-family');
if (PAIRED_ROW === undefined) throw new Error('manifest-v1.json publishes no paired-with-the-published-receipt-family row');
const SEALED_MANIFEST = fromBase64Url(PAIRED_ROW.documentBase64Url);
const MANIFEST_PAYLOAD = decodeSealedDeploymentManifest(SEALED_MANIFEST).payloadBytes;
const MANIFEST_DOCUMENT = JSON.parse(decoded(MANIFEST_PAYLOAD)) as {
  iss: string;
  ins: string;
  models: Array<{ id: string; wts: string }>;
};
const [MANIFEST_MODEL] = MANIFEST_DOCUMENT.models;
if (MANIFEST_MODEL === undefined) throw new Error('the paired manifest row declares no model to bind an inventory to');
function manifestDesignation() {
  const found = MANIFEST_FAMILY.layout.keyMaterial.find((one) => one.id === '8ee9681e');
  if (found === undefined) throw new Error('manifest-v1.json publishes no manifest signing key under the id 8ee9681e');
  return found;
}
const DESIGNATED_KEY = manifestDesignation();
const MANIFEST_SIGNER = signingKeyFromSeed(labeled('ashaveri-fixtures/manifest-v1/signer-a'));
if (toHex(MANIFEST_SIGNER.kid) !== DESIGNATED_KEY.kidHex) {
  throw new Error('the derived manifest signer is not the key the manifest family publishes under 8ee9681e');
}

const RECORD: ModelInventoryRecord = {
  v: 1,
  prov: 'fixture',
  at: FIXED_IAT,
  scope:
    'Fixture extract over the deployment the published receipt family came from, stated by the manifest row paired-with-the-published-receipt-family; no live deployment is described.',
  manifest: {
    sha256: toHex(sha256(SEALED_MANIFEST)),
    iss: MANIFEST_DOCUMENT.iss,
    ins: MANIFEST_DOCUMENT.ins,
  },
  models: [
    {
      bound: { id: MANIFEST_MODEL.id, wts: MANIFEST_MODEL.wts },
      asserted: {
        version: 'fixture-1',
        purpose: 'Demonstrating the model inventory layout over the published fixture material.',
        risk: 'fixture',
        reviews: [{ at: FIXED_IAT, by: 'the fixture deployer' }],
      },
    },
  ],
  pointers: [...MODEL_INVENTORY_POINTERS],
  limits: MODEL_INVENTORY_LIMITS,
};

const RECORD_BYTES = modelInventoryBytes(RECORD);

/**
 * One edit to the writer's own bytes, every other byte left as the writer wrote it, which is how the
 * refusal rows are made: the writer refuses a malformed record, so a refusal row cannot come from it
 * directly, and a row assembled out of junk would test nothing. The writer's format is `JSON.stringify`
 * at two spaces with a trailing newline, so parsing that text, moving one position and writing it back
 * in the same format reproduces the writer's bytes everywhere except the edit.
 */
function editedRecord(base: ModelInventoryRecord, mutate: (document: Record<string, unknown>) => void): Uint8Array {
  const document = JSON.parse(decoded(encodeModelInventory(base))) as Record<string, unknown>;
  mutate(document);
  return encoded(`${JSON.stringify(document, null, 2)}\n`);
}

interface Row {
  readonly name: string;
  readonly note: string;
  readonly expected: string;
  readonly bytes: Uint8Array;
  readonly fault?: { readonly at: string; readonly states: string };
}

const ROWS: readonly Row[] = [
  {
    name: 'inventory-fixture-v1',
    note: 'A whole record over the fixture deployment: the bound model id and weights digest copied from the paired manifest row, the asserted version, purpose, risk category and review stated by the fixture deployer, the three counsel pointers, and the format\'s limits sentence verbatim. The provenance is fixture, so the record labels itself as describing fixture material.',
    expected: 'verify-ok',
    bytes: RECORD_BYTES,
  },
  {
    name: 'inventory-unknown-member-v1',
    note: 'A well-formed record carrying one member the top level does not define. The layout closes every map it declares, so an unknown member is a malformed document rather than a member a reader agreed to forget.',
    expected: 'MODEL_INVENTORY_BAD_DOCUMENT',
    bytes: editedRecord(RECORD, (document) => {
      document['future'] = 'a member no version names';
    }),
    fault: { at: 'record', states: 'a top-level member the layout does not define' },
  },
  {
    name: 'inventory-unknown-model-member-v1',
    note: 'A well-formed record whose model entry carries a member the entry does not define, beside the six it does. The closure rule reaches the maps inside the list, so a weights path no member of this layout holds is refused at the entry that carries it.',
    expected: 'MODEL_INVENTORY_BAD_DOCUMENT',
    bytes: editedRecord(RECORD, (document) => {
      const [model] = document['models'] as Array<Record<string, unknown>>;
      model!['weightsFile'] = 'a path no member of this layout holds';
    }),
    fault: { at: 'models[0]', states: 'a model member the layout does not define' },
  },
  {
    name: 'inventory-limits-reworded-v1',
    note: 'A record wording its own limits. The limits are the format\'s sentence, verbatim, and a record widening or narrowing them is a document of a shape the layout does not define: the one thing a reader must not have to weigh is whether the record\'s own account of its limits is true.',
    expected: 'MODEL_INVENTORY_BAD_DOCUMENT',
    bytes: editedRecord(RECORD, (document) => {
      document['limits'] = 'This record has no limits.';
    }),
    fault: { at: 'limits', states: 'a limits sentence the format does not own' },
  },
  {
    name: 'inventory-unknown-pointer-v1',
    note: 'A well-formed record whose pointers name a provision outside the registry: a near miss of the OSFI appendix pointer rather than a label no instrument resembles. The document is whole and it is the provision it names that this reader has no pointer for, which is the refusal MODEL_INVENTORY_UNKNOWN_POINTER exists for, apart from a malformed document.',
    expected: 'MODEL_INVENTORY_UNKNOWN_POINTER',
    bytes: editedRecord(RECORD, (document) => {
      document['pointers'] = ['osfi-e23-app-2'];
    }),
    fault: { at: 'pointers[0]', states: 'a label the pointer registry does not hold' },
  },
  {
    name: 'inventory-empty-models-v1',
    note: 'A record whose models list is empty. An inventory of no models states nothing about what ran, the same refusal the pack arrives at for an empty items array: a document whose own figures are vacuous reads as evidence while attesting nothing.',
    expected: 'MODEL_INVENTORY_BAD_DOCUMENT',
    bytes: editedRecord(RECORD, (document) => {
      document['models'] = [];
    }),
    fault: { at: 'models', states: 'the non-empty list the layout requires, emptied' },
  },
  {
    name: 'inventory-review-after-assembly-v1',
    note: 'A record whose single review is stamped one second after the extract\'s own assembly stamp. Both instants are inside one record, so a review postdating the extract that carries it is another document\'s review, the same rule the export\'s claim states beside the assembly stamp.',
    expected: 'MODEL_INVENTORY_BAD_DOCUMENT',
    bytes: editedRecord(RECORD, (document) => {
      const [model] = document['models'] as Array<Record<string, unknown>>;
      const [review] = model!['reviews'] as Array<Record<string, unknown>>;
      review!['at'] = FIXED_IAT + 1;
    }),
    fault: { at: 'models[0].reviews[0].at', states: 'a review stamp after the extract that carries it' },
  },
  {
    name: 'inventory-duplicate-model-v1',
    note: 'A record naming one model twice. Two entries answering to one id make a refusal name whichever of the two a reader happened to meet first, and every statement the record makes about a model is made once per model the deployment ran.',
    expected: 'MODEL_INVENTORY_BAD_DOCUMENT',
    bytes: editedRecord(RECORD, (document) => {
      const models = document['models'] as Array<Record<string, unknown>>;
      models.push({ ...models[0] });
    }),
    fault: { at: 'models[1]', states: 'the model id models[0] already names' },
  },
  {
    name: 'inventory-version-two-v1',
    note: 'A record declaring a version nothing has published. The version is asked before any member is read, because which member list applies is the one question a wrong version cannot be talked out of.',
    expected: 'MODEL_INVENTORY_UNSUPPORTED_VERSION',
    bytes: editedRecord(RECORD, (document) => {
      document['v'] = 2;
    }),
    fault: { at: 'v', states: 'a version no layout this package reads defines' },
  },
  {
    name: 'inventory-member-named-twice-v1',
    note: 'The writer\'s bytes with the version member written a second time, the two spellings identical. JSON.parse would keep the last and say nothing while the bytes carry both, so the strict reading refuses the document while the characters are still distinguishable.',
    expected: 'MODEL_INVENTORY_BAD_DOCUMENT',
    bytes: encoded(decoded(RECORD_BYTES).replace('"v": 1,', '"v": 1,\n  "v": 1,')),
    fault: { at: 'record', states: 'the member name v, stated twice in the file\'s own text' },
  },
  {
    name: 'inventory-float-stamp-v1',
    note: 'The assembly stamp written as a fraction that equals the integer it imitates. By the time a field check could ask which spelling the writer chose the two are one JavaScript number, so the reading refuses the spelling rather than the value.',
    expected: 'MODEL_INVENTORY_BAD_DOCUMENT',
    bytes: encoded(decoded(RECORD_BYTES).replace(`"at": ${FIXED_IAT}`, `"at": ${FIXED_IAT}.0`)),
    fault: { at: 'at', states: 'a number written as a fraction where the layout holds an integer' },
  },
];

/** What the shipped reader answers for each parse row, so the file cannot lie about itself. */
function verdictOf(bytes: Uint8Array): string {
  try {
    parseModelInventory(bytes);
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
}

interface BoundCase {
  readonly name: string;
  readonly note: string;
  readonly expected: string;
  readonly recordBytes: Uint8Array;
  readonly manifestBytes: Uint8Array;
  readonly publicKey?: Uint8Array;
  readonly sealed?: boolean;
  readonly authenticated?: boolean;
}

const PLAIN_MANIFEST = MANIFEST_PAYLOAD;
const RECORD_DESIGNATING_PLAIN: ModelInventoryRecord = {
  ...RECORD,
  manifest: { ...RECORD.manifest, sha256: toHex(sha256(PLAIN_MANIFEST)) },
};

const OTHER_MANIFEST_ROW = MANIFEST_FAMILY.vectors.find((one) => one.name === 'sealed-under-designated-key');
if (OTHER_MANIFEST_ROW === undefined) throw new Error('manifest-v1.json publishes no sealed-under-designated-key row');
const OTHER_MANIFEST = fromBase64Url(OTHER_MANIFEST_ROW.documentBase64Url);

const { models: _models, ...DOCUMENT_WITHOUT_MODELS } = MANIFEST_DOCUMENT;
const SEALED_WITHOUT_MODELS = sealDeploymentManifest(encoded(JSON.stringify(DOCUMENT_WITHOUT_MODELS)), MANIFEST_SIGNER);
const RECORD_DESIGNATING_UNREADABLE: ModelInventoryRecord = {
  ...RECORD,
  manifest: { ...RECORD.manifest, sha256: toHex(sha256(SEALED_WITHOUT_MODELS)) },
};

const BOUND_CASES: readonly BoundCase[] = [
  {
    name: 'bound-honest-sealed-authenticated',
    note: 'The honest record verified against the sealed manifest it designates, under the key the manifest family publishes for that purpose. The bound fields agree with the manifest\'s own declaration and the outcome reports the seal authenticated.',
    expected: 'verify-ok',
    recordBytes: RECORD_BYTES,
    manifestBytes: SEALED_MANIFEST,
    publicKey: fromBase64Url(DESIGNATED_KEY.publicKeyBase64Url),
    sealed: true,
    authenticated: true,
  },
  {
    name: 'bound-honest-sealed-unauthenticated',
    note: 'The same pair with no key designated. The digest and the bound fields are still checked, and the outcome reports the authentication the reader did not do rather than implying one: a sealed manifest read without a key is a document whose signer nobody vouched for.',
    expected: 'verify-ok',
    recordBytes: RECORD_BYTES,
    manifestBytes: SEALED_MANIFEST,
    sealed: true,
    authenticated: false,
  },
  {
    name: 'bound-honest-plain',
    note: 'A record designating the plain payload bytes rather than the seal, verified against those bytes. The designation is over the exact bytes handed over, so the two shapes a deployment serves are two designations and not one shape preferred.',
    expected: 'verify-ok',
    recordBytes: modelInventoryBytes(RECORD_DESIGNATING_PLAIN),
    manifestBytes: PLAIN_MANIFEST,
    sealed: false,
    authenticated: false,
  },
  {
    name: 'bound-plain-under-designated-key',
    note: 'The plain document beside a designated manifest signing key. The caller stated a demand about who may sign the manifest and an unsigned document does not meet it, which is a refusal about the designation rather than about bytes that may be a whole manifest.',
    expected: 'MODEL_INVENTORY_MANIFEST_UNSEALED',
    recordBytes: modelInventoryBytes(RECORD_DESIGNATING_PLAIN),
    manifestBytes: PLAIN_MANIFEST,
    publicKey: fromBase64Url(DESIGNATED_KEY.publicKeyBase64Url),
  },
  {
    name: 'bound-other-manifest',
    note: 'The honest record beside the manifest family\'s other deployment, sealed and whole. The digest refuses before a bound field is read: these are not the bytes the record designates, and comparing against them would be comparing the record against a document it never named.',
    expected: 'MODEL_INVENTORY_MANIFEST_MISMATCH',
    recordBytes: RECORD_BYTES,
    manifestBytes: OTHER_MANIFEST,
  },
  {
    name: 'bound-mutated-model-id',
    note: 'The honest record with one bound field moved: the model id names a model the designated manifest does not declare. The refusal names the position and the value, and the record\'s asserted fields are untouched, which is the difference between the two blocks.',
    expected: 'MODEL_INVENTORY_BOUND_DISAGREES',
    recordBytes: editedRecord(RECORD, (document) => {
      const [model] = document['models'] as Array<Record<string, unknown>>;
      model!['id'] = 'meta-llama/Llama-3.1-8B-Instruct-tampered';
    }),
    manifestBytes: SEALED_MANIFEST,
  },
  {
    name: 'bound-mutated-weights',
    note: 'The honest record with the bound weights digest moved to another digest of the same width. The manifest binds one digest per model, and a record stating another is contradicting the document it designates.',
    expected: 'MODEL_INVENTORY_BOUND_DISAGREES',
    recordBytes: editedRecord(RECORD, (document) => {
      const [model] = document['models'] as Array<Record<string, unknown>>;
      model!['wts'] = toHex(sha256(encoded('other weights')));
    }),
    manifestBytes: SEALED_MANIFEST,
  },
  {
    name: 'bound-mutated-issuer',
    note: 'The honest record with the bound issuer moved. The provider is what the manifest signs about itself, and a record naming another issuer beside that manifest\'s digest is the pair disagreeing about who the deployment is.',
    expected: 'MODEL_INVENTORY_BOUND_DISAGREES',
    recordBytes: editedRecord(RECORD, (document) => {
      const manifest = document['manifest'] as Record<string, unknown>;
      manifest['iss'] = 'dpl-someone-else';
    }),
    manifestBytes: SEALED_MANIFEST,
  },
  {
    name: 'bound-asserted-mutation-accepted',
    note: 'The honest record with one asserted field moved: the purpose is another statement the deployment could make. Nothing signed covers the purpose, so the verifying door reads it and reports it asserted, while the bound fields still agree with the manifest. This row and the three above are the split\'s witness: a bound mutation is refused and an asserted mutation is read.',
    expected: 'verify-ok',
    recordBytes: editedRecord(RECORD, (document) => {
      const [model] = document['models'] as Array<Record<string, unknown>>;
      model!['purpose'] = 'A purpose the fixture deployer stated after assembly.';
    }),
    manifestBytes: SEALED_MANIFEST,
    publicKey: fromBase64Url(DESIGNATED_KEY.publicKeyBase64Url),
    sealed: true,
    authenticated: true,
  },
  {
    name: 'bound-manifest-without-models',
    note: 'A record designating a manifest sealed by the same key over a payload with the models member removed. The seal is whole and the digest agrees, and the extraction finds no models to bind against, which is the unreadable refusal rather than a bound disagreement: there is nothing to compare the bound fields to.',
    expected: 'MODEL_INVENTORY_MANIFEST_UNREADABLE',
    recordBytes: modelInventoryBytes(RECORD_DESIGNATING_UNREADABLE),
    manifestBytes: SEALED_WITHOUT_MODELS,
  },
];

function boundVerdictOf(one: BoundCase): string {
  try {
    const verified = verifyModelInventory(one.recordBytes, {
      manifestBytes: one.manifestBytes,
      ...(one.publicKey === undefined ? {} : { manifestPublicKey: one.publicKey }),
    });
    if (one.sealed !== undefined && verified.manifest.sealed !== one.sealed) {
      throw new Error(`${one.name}: the reader reports sealed=${String(verified.manifest.sealed)}, not ${String(one.sealed)}`);
    }
    if (one.authenticated !== undefined && verified.manifest.authenticated !== one.authenticated) {
      throw new Error(`${one.name}: the reader reports authenticated=${String(verified.manifest.authenticated)}, not ${String(one.authenticated)}`);
    }
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
}

/**
 * The export ride: the record's bytes as one inline item of the published export container, signed by
 * the fixture receipt key. No export member moves for the inventory; the record is material the export
 * carries, and the ride is witnessed by verifying the export, reading the item's original bytes back
 * through both inventory doors, and holding them to the record the family publishes.
 */
const EXPORT_ITEM_ID = 'model-inventory-fixture-v1';
const EXPORT_KEY = fixtureKey();
const EXPORT_MANIFEST: ExportManifest = {
  v: 1,
  at: FIXED_IAT,
  assessment: { k: 'none', states: 'No assessment is stated by this fixture export.' },
  collection: {
    k: 'plain',
    prov: 'fixture',
    items: [
      {
        id: EXPORT_ITEM_ID,
        iat: FIXED_IAT,
        prov: 'fixture',
        d: sha256(RECORD_BYTES),
        orig: { k: 'inline', bytes: RECORD_BYTES },
      },
    ],
  },
  claim: {
    made: FIXED_IAT,
    by: 'the fixture deployer',
    kind: 'provenance',
    states: 'Fixture model inventory extract riding the published export contract.',
  },
};
const EXPORT_BYTES = signExport(EXPORT_MANIFEST, EXPORT_KEY);

function witnessTheRide(): void {
  const verified = verifyExport(EXPORT_BYTES, EXPORT_KEY.publicKey);
  if (verified.outcome.kind !== 'plain') throw new Error('the fixture export is not the plain arm it was assembled as');
  const item = verified.outcome.items.find((one) => one.id === EXPORT_ITEM_ID);
  if (item === undefined || item.orig.k !== 'inline') throw new Error('the fixture export carries no inline inventory item');
  if (!equalBytes(item.orig.bytes, RECORD_BYTES)) throw new Error('the export item is not the record bytes');
  const parsed = parseModelInventory(item.orig.bytes);
  if (JSON.stringify(parsed) !== JSON.stringify(RECORD)) throw new Error('the ridden record does not parse to the published record');
  verifyModelInventory(item.orig.bytes, {
    manifestBytes: SEALED_MANIFEST,
    manifestPublicKey: fromBase64Url(DESIGNATED_KEY.publicKeyBase64Url),
  });
}

function main(): void {
  for (const one of ROWS) {
    const observed = verdictOf(one.bytes);
    if (observed !== one.expected) {
      throw new Error(`${one.name}: the reader answers ${observed}, not the ${one.expected} this row states`);
    }
  }
  for (const one of BOUND_CASES) {
    const observed = boundVerdictOf(one);
    if (observed !== one.expected) {
      throw new Error(`${one.name}: the verifying door answers ${observed}, not the ${one.expected} this case states`);
    }
  }
  witnessTheRide();

  const vectors = ROWS.map((one) => ({
    name: one.name,
    note: one.note,
    expected: one.expected,
    recordBase64Url: toBase64Url(one.bytes),
    recordByteLength: one.bytes.length,
    ...(one.fault === undefined ? {} : { fault: one.fault }),
  }));

  const boundCases = BOUND_CASES.map((one) => ({
    name: one.name,
    note: one.note,
    expected: one.expected,
    recordBase64Url: toBase64Url(one.recordBytes),
    manifestBase64Url: toBase64Url(one.manifestBytes),
    ...(one.publicKey === undefined ? {} : { publicKeyBase64Url: toBase64Url(one.publicKey) }),
    ...(one.sealed === undefined ? {} : { sealed: one.sealed }),
    ...(one.authenticated === undefined ? {} : { authenticated: one.authenticated }),
  }));

  writeFileSync(
    join(DATA, 'model-inventory-v1.json'),
    JSON.stringify(
      {
        version: 1,
        description:
          'The model inventory record beside the receipts and the signed deployment manifest: the layout its strict reader reads, the bound and asserted fields the layout keeps apart, the pointer registry it enumerates, and the limits sentence every record states verbatim. The fixture deployment is the one the published receipt family came from, stated by the manifest row paired-with-the-published-receipt-family; the bound fields are copied from that row\'s payload and the asserted fields are the fixture deployer\'s statements, so the extract is labeled fixture and describes no live deployment. The parse rows carry the record bytes the shipped writer made, or one edit of them at the position the fault names; the bound cases carry the record beside the manifest bytes it designates and the verdict the verifying door owes the pair, including the mutation pair that witnesses the split: a bound mutation refused and an asserted mutation read. The export ride publishes the record as one inline item of the published export container, which no member of that contract moves for.',
        rule: {
          registry: 'docs/receipt-spec.md section 4.9',
          reader: 'parseModelInventory in @ashaveri/receipt',
          verifier: 'verifyModelInventory in @ashaveri/receipt',
          writer: 'modelInventoryBytes in @ashaveri/receipt',
          pointers: [...MODEL_INVENTORY_POINTERS],
          pointerCitations: { ...MODEL_INVENTORY_POINTER_CITATIONS },
          limits: MODEL_INVENTORY_LIMITS,
          boundModelFields: [...MODEL_INVENTORY_BOUND_MODEL_FIELDS],
          assertedModelFields: [...MODEL_INVENTORY_ASSERTED_MODEL_FIELDS],
          manifest: {
            row: 'manifest-v1.json#paired-with-the-published-receipt-family',
            documentBase64Url: toBase64Url(SEALED_MANIFEST),
            publicKeyBase64Url: DESIGNATED_KEY.publicKeyBase64Url,
            note: 'The sealed manifest the honest record designates, byte for byte the row the manifest family publishes, beside the key that family publishes as signing the manifests a reader designates. A bound case carries its own manifest bytes, so a port replays each pair without reaching into another family.',
          },
          exportRide: {
            exportBase64Url: toBase64Url(EXPORT_BYTES),
            publicKeyBase64Url: toBase64Url(EXPORT_KEY.publicKey),
            itemId: EXPORT_ITEM_ID,
            note: 'The record as one inline item of a plain export signed by the fixture receipt key. verifyExport checks the item\'s digest; the item\'s original bytes are the record bytes, read back through both inventory doors. The export contract moves no member for the inventory.',
          },
          encodings: 'byte strings unpadded base64url, digests lowercase hex, instants unix seconds',
        },
        vectors,
        boundCases,
      },
      null,
      2,
    ) + '\n',
  );

  for (const one of vectors) console.log(`${one.name}: ${one.expected}`);
  for (const one of boundCases) console.log(`${one.name}: ${one.expected}`);
}

main();