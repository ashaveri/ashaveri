import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import type { SigningKey, ReceiptJson } from '@ashaveri/receipt';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');

/** One item of a receipt's `itm`, as its row states it: the instant, the digest, and the bytes. */
export interface ReceiptItemColumn {
  t: number;
  d: string;
  bytesBase64Url: string;
  byteLength: number;
}

/** One slot of an anchor, in the spelling the row states it in: a label, then a digest or a reason. */
export interface ReceiptAnchorSlotColumn {
  p: string;
  d?: string;
  r?: string;
}

/** The position a refusal row states, the member it quotes where the reader quotes one, and the claim. */
export interface ReceiptFaultColumn {
  at: string;
  member?: string;
  states: string;
}

/**
 * One published receipt and everything its row states about it.
 *
 * The columns past `expected` are stated on a row exactly where the document carries what they describe,
 * which is why a row can state no `items`: the payload it publishes names no item list. `expected` is the
 * verdict the key-bearing reader owes the bytes and `keyless` the verdict the reader with no key in hand
 * owes them, which are two answers a port has to get right separately.
 */
export interface ReceiptFixtureRow {
  name: string;
  path: string;
  digestSha256: string;
  expected: string;
  keyless?: string;
  v?: 1 | 2 | 3;
  marking?: string;
  contentType?: string;
  response?: string;
  assembledFrom?: string[];
  responseBase64Url?: string;
  responseByteLength?: number;
  items?: ReceiptItemColumn[];
  sd?: { name: string; unc?: number | null };
  cva?: { col: ReceiptAnchorSlotColumn; val: ReceiptAnchorSlotColumn };
  /**
   * The verdict the shipped client path gives this document under each posture the policy field
   * `minAnchorSlotsHeld` can take, stated in the order `null`, `1`, `2`: no demand named, a demand of one
   * held slot, a demand of both. Present on a row exactly where the client reaches the anchor its document
   * carries, which is every row this suite publishes an accepted answer for.
   */
  handover?: { minAnchorSlotsHeld: number | null; verdict: string }[];
  fault?: ReceiptFaultColumn;
  note?: string;
}

/** What the suite says its own columns mean, published beside the rows rather than only in prose. */
export interface ReceiptFixtureLayout {
  verdictFields: string[];
  readers: { keyless: string; keyBearing: string };
  columns: Record<string, string>;
  encodings: string;
}

export interface FixtureManifest {
  version: number;
  generatedBy: string;
  cddl: string;
  fixtures: ReceiptFixtureRow[];
  layout?: ReceiptFixtureLayout;
}

export interface ReceiptFixture {
  name: string;
  bytes: Uint8Array;
  digest: Uint8Array;
  json: ReceiptJson | null;
}

export function loadManifest(): FixtureManifest {
  return JSON.parse(readFileSync(join(DATA, 'manifest.json'), 'utf8')) as FixtureManifest;
}

export function loadReceiptFixture(name: string): ReceiptFixture {
  const manifest = loadManifest();
  const entry = manifest.fixtures.find((f) => f.name === name);
  if (!entry) throw new Error(`unknown fixture: ${name}`);
  const bytes = new Uint8Array(readFileSync(join(DATA, entry.path)));
  const digest = sha256(bytes);
  const expected = Buffer.from(entry.digestSha256, 'hex');
  if (!Buffer.from(digest).equals(expected)) {
    throw new Error(`fixture ${name} does not match its manifest digest (regenerate with pnpm generate)`);
  }
  let json: ReceiptJson | null = null;
  const jsonPath = join(DATA, entry.path.replace(/\.cbor$/, '.json'));
  try {
    json = JSON.parse(readFileSync(jsonPath, 'utf8')) as ReceiptJson;
  } catch {
    json = null;
  }
  return { name, bytes, digest, json };
}

export interface FixtureKeyFile {
  description: string;
  privateKey: string;
  publicKey: string;
  kid: string;
}

export function loadFixtureKey(): SigningKey {
  const parsed = JSON.parse(readFileSync(join(DATA, 'keys', 'receipt-key-v1.json'), 'utf8')) as FixtureKeyFile;
  return {
    privateKey: new Uint8Array(Buffer.from(parsed.privateKey, 'hex')),
    publicKey: new Uint8Array(Buffer.from(parsed.publicKey, 'hex')),
    kid: new Uint8Array(Buffer.from(parsed.kid, 'hex')),
  };
}

export { DATA };

export interface PopVector {
  name: string;
  note: string;
  fields: {
    ts: number;
    nonce: string;
    method: string;
    target: string;
    bodyBase64Url: string;
    bodyDigestHex: string;
  };
  signingString: string;
  authorization: string;
}

export interface PopVectorFile {
  version: 1;
  description: string;
  scheme: string;
  separator: string;
  emptyBodySha256Hex: string;
  key: { id: string; privateKeyHex: string; publicKeyHex: string };
  vectors: PopVector[];
}

export function loadPopVectors(): PopVectorFile {
  return JSON.parse(readFileSync(join(DATA, 'pop-v1.json'), 'utf8')) as PopVectorFile;
}

/** What a digest vector states about the digest it publishes, and the bytes it is taken over. */
export interface DigestRule {
  receiptField: string;
  algorithm: string;
  input: string;
  encoding: string;
  computedBefore: string;
}

export interface RequestVector {
  name: string;
  note: string;
  bodyBase64Url: string;
  bodyByteLength: number;
  reqHex: string;
}

export interface RequestVectorFile {
  version: number;
  description: string;
  rule: DigestRule;
  vectors: RequestVector[];
}

/** The request-body digests a receipt claims in `req`. */
export function loadReqVectors(): RequestVectorFile {
  return JSON.parse(readFileSync(join(DATA, 'req-v1.json'), 'utf8')) as RequestVectorFile;
}

export interface ResponseVector {
  name: string;
  note: string;
  contentType: string;
  /** The name of the entry in `req-v1.json` carrying the request these bytes answered. */
  request: string;
  requestBase64Url: string;
  /** The response as it was written, piece by piece, which for a stream is not one piece. */
  chunksBase64Url: string[];
  responseBase64Url: string;
  responseByteLength: number;
  resHex: string;
}

export interface ResponseVectorFile {
  version: number;
  description: string;
  rule: DigestRule;
  framing: {
    contentType: string;
    fieldPrefix: string;
    frameSeparator: string;
    terminator: string;
    note: string;
  };
  vectors: ResponseVector[];
}

/** The response-body digests a receipt claims in `res`, framed bytes included. */
export function loadResVectors(): ResponseVectorFile {
  return JSON.parse(readFileSync(join(DATA, 'res-v1.json'), 'utf8')) as ResponseVectorFile;
}

/** What one retirement recorded, in the two places the record layout keeps it. */
export interface ChainTrimPayload {
  seamHex: string;
  byAge: number;
  byCount: number;
  maxAgeSeconds: number;
  maxCount: number;
}

/** One record of a store file, field by field, with its own bytes beside it. */
export interface ChainRecord {
  /** Where the frame starts in the file image, in bytes from the file's first byte. */
  offset: number;
  kind: number;
  length: number;
  frameByteLength: number;
  prevHex: string;
  iat: number;
  id: string;
  payloadBase64Url: string;
  digestHex: string;
  frameBase64Url: string;
  trim?: ChainTrimPayload;
}

export interface ChainPut {
  id: string;
  iat: number;
  payloadBase64Url: string;
}

export interface ChainTrimEvent {
  at: number;
  byAge: number;
  byCount: number;
  under: { maxAgeSeconds?: number; maxCount?: number };
}

/** What a reader reports about a store file, beside the bytes the file holds. */
export interface ChainStateVector {
  anchorHex: string;
  retired: { byAge: number; byCount: number; trims: ChainTrimEvent[] };
}

export interface ChainScenario {
  name: string;
  note: string;
  retention?: { maxAgeSeconds?: number; maxCount?: number };
  clockSeconds: number;
  puts: ChainPut[];
  fileBase64Url: string;
  fileByteLength: number;
  records: ChainRecord[];
  headHex: string;
  window: { from: number; to: number; count: number };
  served: Record<string, string>;
  chainState: ChainStateVector;
}

/** A file image no store wrote, and the refusal the reader answers it with. */
export interface ChainRefusal {
  name: string;
  note: string;
  tamper: Record<string, unknown>;
  imageBase64Url: string;
  imageByteLength: number;
  /**
   * The receipt kind the opening that gives this refusal writes. Absent means the receipt kind, which is
   * the layout every other image in this file is read under, and which no row states twice: a refusal
   * between a file and a configuration is only reproducible with the configuration named.
   */
  openedWith?: { kind: 'receipt' } | { kind: 'bounded'; boundSeconds: number };
  code: string;
  message: string;
}

/** Two records with an interrupted append at the tail, and what a reader makes of them. */
export interface ChainTail {
  name: string;
  note: string;
  /** The scenario whose image was cut, and how many bytes came off its end. */
  of: string;
  cutBytes: number;
  imageBase64Url: string;
  headHex: string;
  repairedImageBase64Url: string;
  served: Record<string, string>;
  unserved: string[];
  next: ChainPut;
  imageAfterNextBase64Url: string;
  recordsAfterNext: ChainRecord[];
}

export interface ChainVectorFile {
  version: number;
  description: string;
  layout: {
    file: string;
    record: string;
    lengthCovers: string;
    digestInput: string;
    digest: string;
    integers: string;
    kinds: { receipt: number; trim: number; bounded: number };
    receiptPayload: string;
    boundedPayload: string;
    trimPayload: string;
    notes: string[];
  };
  scenarios: ChainScenario[];
  tails: ChainTail[];
  refusals: ChainRefusal[];
}

/** The receipt store record format, as file images and the state a reader derives from them. */
export function loadChainVectors(): ChainVectorFile {
  return JSON.parse(readFileSync(join(DATA, 'chain-v1.json'), 'utf8')) as ChainVectorFile;
}

/** One marking case: the bytes a reader holds, the span its receipt attests, and the verdict. */
export interface MarkingVector {
  name: string;
  note: string;
  shape: 'buffered' | 'streamed';
  sch: string;
  responseBase64Url: string;
  responseByteLength: number;
  /** The span whose digest the receipt carries in `mk.d`. The empty string is the region of `none`. */
  attestedRegionBase64Url: string;
  attestedRegionByteLength: number;
  /** What the published rule locates, or null where it locates no single region. */
  foundRegionBase64Url: string | null;
  foundRegionByteLength: number | null;
  dHex: string;
  expected: string;
}

export interface MarkingVectorFile {
  version: number;
  description: string;
  rule: {
    registry: string;
    executable: string;
    schemes: string[];
    digestField: string;
    algorithm: string;
    input: string;
    candidates: string;
    member: { name: string; sch: string; gen: string; at: number; note: string };
    encodings: string;
    note: string;
  };
  vectors: MarkingVector[];
}

/** The marked region a receipt digests in `mk.d`, for both response shapes, and its refusals. */
export function loadMarkingVectors(): MarkingVectorFile {
  return JSON.parse(readFileSync(join(DATA, 'marking-v1.json'), 'utf8')) as MarkingVectorFile;
}

/** What a reader is handed beside an export document: companion files, endpoints, and the key it uses. */
export interface ExportReadArguments {
  companions?: Array<{ name: string; bytesBase64Url: string }>;
  expectedAnchorHex?: string;
  expectedHeadHex?: string;
  keySeed?: number;
}

/** One export document, the arguments for reading it, and the verdict a conforming reader owes it. */
export interface ExportVector {
  name: string;
  note: string;
  /** The whole COSE_Sign1, sealed, unpadded base64url. */
  documentBase64Url: string;
  documentByteLength: number;
  read: ExportReadArguments;
  /** `verify-ok`, or the code the refusal answers with. */
  verdict: string;
  /** The item a refusal names, where the code reports by naming one. */
  item?: string;
  /** Which arm of the collection a passing read reports. */
  outcome?: 'anchored' | 'plain' | 'void';
  /** The order a passing walk reaches, which is the links and not the array. */
  walk?: string[];
  /** The one position a fault case moved. */
  edited?: string;
}

export interface ExportCrossReadingCase {
  name: string;
  note: string;
  /** The export manifest projected as its own twin describes it, for the pack side of the pair. */
  manifest?: Record<string, unknown>;
  /** A pack document, sealed, for the export side of the pair. */
  documentBase64Url?: string;
  expected: string;
}

export interface ExportVectorFile {
  version: number;
  description: string;
  layout: {
    format: string;
    twin: string;
    document: string;
    reader: string;
    contentType: string;
    headerLabels: { alg: number; typ: number; kid: number };
    framing: string;
    recordDigest: string;
    itemDigest: string;
    manifestFields: string[];
    collectionArms: string[];
    originalArms: string[];
    encodings: string;
    anchor: string;
    assembled: string;
    verdictFields: string[];
    codes: string[];
    key: { publicKeyHex: string; seed: string; note: string };
  };
  vectors: ExportVector[];
  crossReading: { note: string; cases: ExportCrossReadingCase[] };
}

/** The technical export envelope: whole documents, the reads they are given, and their verdicts. */
export function loadExportVectors(): ExportVectorFile {
  return JSON.parse(readFileSync(join(DATA, 'export-v1.json'), 'utf8')) as ExportVectorFile;
}

/** The keys a row designates for signing manifests: an id, and the public half pinned under it. */
export interface DesignatedManifestKey {
  kid: string;
  publicKeyBase64Url: string;
}

/** What a client reports about the bytes it read, beside the code it answered with. */
export interface SealedManifestAuthentication {
  sealed: boolean;
  authenticated: boolean;
  kid: string | null;
  demanded: boolean;
  advisory: boolean;
}

/** One receipt's claim about its key and moment, in the spelling the shipped rule takes. */
export interface ManifestEpochClaimRow {
  claim: { kid: string; epoch: number; issuedAt: number };
  ok: boolean;
  code?: string;
  basis?: 'windows' | 'current-epoch';
  superseded?: boolean;
  validFrom?: number | null;
  validTo?: number | null;
}

/**
 * One case: the bytes handed to a reader, the keys it designates, what the client answers, and what the
 * envelope reader answers underneath that.
 */
export interface SealedManifestVector {
  name: string;
  note: string;
  /** The document as served, sealed or plain, unpadded base64url. */
  documentBase64Url: string;
  documentByteLength: number;
  read: { designates: DesignatedManifestKey[] };
  /** `verify-ok`, or the code the client path answers with. */
  verdict: string;
  /** `verify-ok`, `not-sealed`, or the code the envelope reader answers with. */
  seal: string;
  authentication?: SealedManifestAuthentication;
  /** The document as the client's parser leaves it, members in the order the parser builds them. */
  parsed?: Record<string, unknown>;
  /** Members a version does not name, which must appear nowhere in `parsed`. */
  dropped?: string[];
  /** The one position a fault case moved. */
  edited?: string;
  reveal?: {
    contextString: string;
    externalAadBase64Url: string;
    protectedHeaderBase64Url: string;
    payloadBase64Url: string;
    payloadByteLength: number;
    payloadSha256Hex: string;
    signatureHex: string;
    sigStructureHex: string;
    headerLabels: { label: number; name: string; value: string | number }[];
  };
  claims?: ManifestEpochClaimRow[];
}

export interface SealedManifestVectorFile {
  version: number;
  description: string;
  layout: {
    format: string;
    twin: string;
    prose: string;
    contentType: string;
    reader: string;
    envelopeReader: string;
    codes: string[];
    verdictFields: string[];
    authenticationFields: string[];
    keyMaterial: Array<{
      id: string;
      seed: string;
      kidHex: string;
      publicKeyHex: string;
      publicKeyBase64Url: string;
      role: string;
    }>;
    [key: string]: unknown;
  };
  vectors: SealedManifestVector[];
  crossReading: { note: string; cases: Array<{ name: string; documentBase64Url: string; expected: string }> };
}

/** The sealed deployment manifest: both served shapes, the designations, and the verdicts owed them. */
export function loadSealedManifestVectors(): SealedManifestVectorFile {
  return JSON.parse(readFileSync(join(DATA, 'manifest-v1.json'), 'utf8')) as SealedManifestVectorFile;
}

/** How a row hands the pack reader its keys: the one key pinned, or the set a resolver answers from. */
export interface PackDesignation {
  pinned?: string;
  retained?: DesignatedManifestKey[];
}

/** One record of a run this suite frames: the predecessor it names and the digest the framing gave back. */
export interface PackRecordRow {
  position: number;
  id: string;
  iat: number;
  prevHex: string;
  receiptByteLength: number;
  digestHex: string;
}

/** One step of a walk whose stamps run against the links, as the reader reports it and never refuses it. */
export interface PackOrderingRow {
  kind: string;
  from: string;
  to: string;
  fromIat: number;
  toIat: number;
}

/**
 * One case: the pack bytes handed to a reader, the designation it is given, what `verifyPack` answers, and what
 * `decodePack` answers for the same bytes with no key in hand.
 */
export interface PackVector {
  name: string;
  note: string;
  /** The sealed pack, unpadded base64url. */
  documentBase64Url: string;
  documentByteLength: number;
  read: PackDesignation;
  /** `verify-ok`, or the code `verifyPack` answers with. */
  verdict: string;
  /** `verify-ok`, or the code `decodePack` answers with before any key is consulted. */
  structural: string;
  /** The run the links reached, in that order. */
  walk?: string[];
  /** The steps where the stamps disagree with the links, empty where they agree. */
  ordering?: PackOrderingRow[];
  /** The window the manifest states, where the row is about the window. */
  span?: { from: number; to: number };
  /** The item a refusal names, where the code reports by naming one. */
  item?: string;
  /** The one position a fault case moved. */
  edited?: string;
}

export interface PackVectorFile {
  version: number;
  description: string;
  layout: {
    format: string;
    twin: string;
    /** The standalone statement of this container, which its own document test holds to the twin. */
    document: string;
    prose: string;
    contentType: string;
    writer: string;
    reader: string;
    headerLabels: { alg: number; typ: number; kid: number };
    codes: string[];
    verdictFields: string[];
    records: PackRecordRow[];
    /**
     * The framing of the run whose every held slot is answered by a reference, in the same rows as `records`. The
     * key keeps the name the run was published under while that pack carried the material itself; the member of
     * the file that names the row this table frames is `framingRule`, and the row is named there.
     */
    attachedRecords: PackRecordRow[];
    /** The whole rule the reader enforces over the reference list and the byte arm, with both ceilings as figures. */
    custodyRule: string;
    framingRule: string;
    keyMaterial: Array<{
      id: string;
      seed: string;
      kidHex: string;
      publicKeyHex: string;
      publicKeyBase64Url: string;
      role: string;
    }>;
    [key: string]: unknown;
  };
  vectors: PackVector[];
  crossReading: { note: string; cases: Array<{ name: string; documentBase64Url: string; expected: string }> };
}

/** The evidence pack: the shapes a deployment hands it over in, the designations, and both reader answers. */
export function loadPackVectors(): PackVectorFile {
  return JSON.parse(readFileSync(join(DATA, 'pack-v1.json'), 'utf8')) as PackVectorFile;
}

/**
 * One record of the pack a redaction speaks about, in the order its links fix it, with the digest the pack's
 * own framing gives back and whether this redaction names it for removal.
 */
export interface RedactionRunRow {
  position: number;
  id: string;
  iat: number;
  prevHex: string;
  digestHex: string;
  namedForRemoval: boolean;
}

/**
 * One survivor: the predecessor its record carries in the pack, the predecessor the reduced chain used
 * instead, and the digest that came out. The two predecessor columns are equal for the first record of a run
 * and differ for every later one, which is the relinking stated as data.
 */
export interface RedactionRecordRow {
  position: number;
  id: string;
  iat: number;
  prevInPackHex: string;
  relinkedFromHex: string;
  digestHex: string;
  namedForRemoval: boolean;
}

/** What the command path answers for one row's pair: the code it prints, and the exit it leaves beside it. */
export interface RedactionCommandAnswer {
  code: string;
  exit: number;
}

/**
 * One case: the redaction bytes, the pack handed beside them, the designation the caller makes, and what the
 * reader's two entry points and the command answer over them. A row with no `packOf` is the reader that was
 * handed one document of the pair and is refused for that and nothing else.
 */
export interface RedactionVector {
  name: string;
  note: string;
  /** The sealed redaction manifest, unpadded base64url. */
  documentBase64Url: string;
  documentByteLength: number;
  /** The row of `pack-v1.json` the pack handed to the reader comes from, when one was handed. */
  packOf?: string;
  /** Stated when the handed pack is that row's bytes with one position moved, which is the only departure. */
  packEdited?: string;
  packBase64Url?: string;
  packByteLength?: number;
  read: PackDesignation;
  /** `verify-ok`, or the code `verifyRedaction` answers with. */
  verdict: string;
  /** `verify-ok`, or the code `decodeRedaction` answers with before any key or pack is consulted. */
  structural: string;
  /**
   * What `ashaveri verify-handover` answers for the same pair: `null` where it answers exactly what `verdict`
   * states, which is an exit of 0 on an accepted row and of 1 on a refusal, and the code and the exit beside it
   * where the command meets this fact one step earlier than the reader does.
   */
  command: RedactionCommandAnswer | null;
  /** The records that remain, in the order the pack's links reach them. */
  survivors?: string[];
  /** The head of the chain over the survivors, and the pack's own signed head, never equal on one row. */
  reducedHex?: string;
  originalHeadHex?: string;
  /** The id a refusal names, where the code reports by naming one. */
  item?: string;
  /** The one position a fault case moved. */
  edited?: string;
}

export interface RedactionVectorFile {
  version: number;
  description: string;
  layout: {
    format: string;
    twin: string;
    prose: string;
    contentType: string;
    reader: string;
    headerLabels: { alg: number; typ: number; kid: number };
    codes: string[];
    verdictFields: string[];
    run: RedactionRunRow[];
    records: RedactionRecordRow[];
    keyMaterial: Array<{
      id: string;
      seed: string;
      kidHex: string;
      publicKeyHex: string;
      publicKeyBase64Url: string;
      role: string;
    }>;
    [key: string]: unknown;
  };
  vectors: RedactionVector[];
  crossReading: { note: string; cases: Array<{ name: string; documentBase64Url: string; expected: string }> };
}

/** The redaction manifest: each pair of documents, both reader answers, and the chain over the survivors. */
export function loadRedactionVectors(): RedactionVectorFile {
  return JSON.parse(readFileSync(join(DATA, 'redaction-v1.json'), 'utf8')) as RedactionVectorFile;
}

/** How a row designates a key to the inventory reader: one pinned key, a kid-indexed set, or neither. */
export interface EpochInventoryDesignation {
  pinned?: string;
  retained?: Record<string, string>;
  /**
   * The run's retention artifacts, unpadded base64url, in the order the call hands them. A row stating none is the
   * call that handed no manifest, which reads the document alone and claims nothing about held material.
   */
  presence?: string[];
}

export interface EpochInventoryVector {
  name: string;
  note: string;
  /** The sealed inventory document, unpadded base64url. */
  documentBase64Url: string;
  documentByteLength: number;
  read: EpochInventoryDesignation;
  /** `verify-ok`, or the code `verifyEpochInventory` answers with. */
  verdict: string;
  /** `verify-ok`, or the code `decodeEpochInventory` answers with before any key is consulted. */
  structural: string;
  /** The refusal sentence the shipped reader gave, published on every refusing row. */
  message?: string;
  /** What the reader reported back for a row it accepted: the run it put together and the summaries it read. */
  readback?: {
    runFiles: string[];
    statedFiles: string[];
    window: { from: number; to: number };
    continuous: boolean;
    breakFiles: string[];
    carried: boolean;
    shortFiles: string[];
  };
  /** Which of the two folded lists a row guards, on the rows that vector one of the twin guards. */
  site?: 'chain.breaks' | 'duty.short';
  /** Which guard of its site a refusing folded-list row reaches, named so the two sites can be compared guard for guard. */
  guard?: string;
  /** The one position a fault row moved. */
  edited?: string;
  /** The text edit a row was built by, beside the row whose text it edited. */
  edit?: { of: string; from: string; to: string };
  /** The honest document taken apart into the four pieces the format publishes. */
  reveal?: Record<string, unknown>;
}

export interface EpochInventoryVectorFile {
  version: number;
  description: string;
  layout: {
    format: string;
    twin: string;
    prose: string;
    contentType: string;
    reader: string;
    headerLabels: { alg: number; typ: number; kid: number };
    codes: string[];
    verdictFields: string[];
    /** The columns every row carries because they say which row and which document it is. */
    rowNamingFields: string[];
    keyMaterial: Array<{
      id: string;
      seed: string;
      kidHex: string;
      publicKeyHex: string;
      publicKeyBase64Url: string;
      role: string;
    }>;
    [key: string]: unknown;
  };
  vectors: EpochInventoryVector[];
}

/** The epoch inventory: each sealed document, both reader answers, and the run the reader put together. */
export function loadEpochInventoryVectors(): EpochInventoryVectorFile {
  return JSON.parse(readFileSync(join(DATA, 'epoch-inventory-v1.json'), 'utf8')) as EpochInventoryVectorFile;
}

/**
 * The estate's synthetic vendor: the certificates, the signed documents and the served answer its suites build
 * rather than capture. It is exported from this entry rather than left inside one package's test directory,
 * because the collateral cases, this package's own pack generator and the CLI's offline proof each reach it from
 * a different package, and the bytes it signs for the published rows are published here.
 */
export {
  fixtureVendor,
  foreignKey,
  mismatchedVendor,
  qeIdentity,
  secondsOf,
  servedAnswer,
  servedChain,
  servedChainOf,
  servedJsonBody,
  servedLevel,
  servedMemberText,
  servedSignatureMember,
  servedTcb,
  servedWrapperBody,
  signedDocument,
  tcbInfo,
  tcbInfoBody,
  testVendor,
  x5cOf,
  type ServedAnswer,
  type ServedComposition,
  type ServedLevel,
  type TestVendor,
} from './fixture-vendor.js';
