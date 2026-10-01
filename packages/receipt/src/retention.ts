import { ReceiptError } from './errors.js';
import { readJsonBytes, type JsonObject } from './json-text.js';

/**
 * The retention manifest, read and written: what `schemas/retention-v1.schema.json` and
 * `schemas/retention-v2.schema.json` state, run.
 *
 * A retention manifest is a deployment's statement about its own store: what it holds, what it retired and on
 * which bound, how long it has actually held what remains, and, from version two, which material of the
 * appraisal context it held at the instant it stamped. It is the one signed-document family of this estate that
 * carries no signature. That is not an oversight to repair and it is not a weakness to route around: a receipt
 * attests one response, a pack attests that the receipts inside a window are all of them, and a manifest
 * attests the state of a volume, which the thing that reads the volume is the only party able to report. Its
 * trust therefore arrives from outside it. The epoch inventory names this file's location and carries sha256
 * over its bytes inside its own signature, and so the bytes of a manifest are evidence for a reader handed the
 * inventory that seals them and are the deployment's say-so for a reader handed only the file. Every choice in
 * this module follows from that split, and the sharpest of them is that the presence observations a run folds
 * are read here but authenticated elsewhere: nothing in this file can tell a sealed manifest from a copy.
 *
 * Two versions are read because two exist to be read. `RETENTION_FORMAT_VERSIONS` is the set, and a version is
 * asked of that list rather than compared with a literal, because the defect a literal leaves behind is silent:
 * a reader that answered `v: 2` by falling through to the `v: 1` branch, or a fold that skipped the manifest of
 * a run whose artifacts had moved, would report green while doing no work at all. Adding a member to a closed
 * map is a version bump rather than an optional member, which is why `presence` is required at two, refused at
 * one, and why a version one manifest stays whole under its own layout instead of being read as a store that
 * held nothing.
 *
 * What this module refuses is the layout and the arithmetic between stated figures. A manifest is malformed for
 * a member that is missing, unnamed, of the wrong type or width, or for two of its own members that cannot both
 * be true: `duty.met` beside the two integers it is the comparison of, `duty.heldSeconds` beside the instant and
 * the window it is measured from, a trim event stamped after the manifest carrying it, and a presence family
 * whose count is not the length of its own list or which names one digest twice. What it does not refuse is any
 * figure a deployment states that this estate would disagree with: no period is bounded, no duty label outside
 * the three is guessed at, and no observation is weighed as to whether the material behind it was worth holding.
 * The distinction is the one the whole estate is built on. A document that contradicts itself is a formatting
 * failure and a reader says so; a document whose numbers describe a deployment this reader would not have chosen
 * is whole, and the verdict about it belongs to whoever holds the mapping and the law.
 *
 * The reader is `parseRetentionDocument` and the writer is `encodeRetentionDocument`, and the writer is a
 * serializer of the shape this module's own type states rather than a `JSON.stringify` of whatever object a
 * caller built: the bytes of a manifest are what an inventory hashes, so the same store state has to produce the
 * same bytes twice, and a writer that emitted the caller's key order would give two writers of one state two
 * digests. Members are emitted in the order the published layouts list them, two spaces indented, newline
 * terminated, and an optional member a caller left out is not emitted rather than emitted as null, because an
 * absent bound means no bound was configured and a null means something else entirely.
 */

/** The versions this module reads, and the only place a retention version is asked. */
export const RETENTION_FORMAT_VERSIONS: readonly number[] = [1, 2];

/** The name a layout is filed under, which is the layout's own version inside the file name. */
function fileNameFor(version: number): string {
  return `retention-v${String(version)}.json`;
}

/** The file name of each layout, as the epoch directory files it and as the inventory's entry names it. */
export const RETENTION_FILE_NAMES: Readonly<Record<number, string>> = Object.fromEntries(
  RETENTION_FORMAT_VERSIONS.map((version) => [version, fileNameFor(version)]),
);

/**
 * The same names as one ordered list, for the reader that accepts any layout a run's artifact is written in. The
 * epoch inventory files a manifest under one of these and seals its digest, and a layout that names a file no
 * version writes is the silent half of a version-set widening: a run of the new layout is refused as a
 * malformed path, every existing vector stays green, and nothing says the fold stopped looking at evidence.
 */
export const RETENTION_FILE_NAME_SET: readonly string[] = RETENTION_FORMAT_VERSIONS.map(fileNameFor);

/**
 * The member lists of every map this layout closes, in the order the published schemas declare them. Exported
 * for a test to hold against the two schema files rather than against this file's reading of them, and for the
 * writer to emit in: which members exist is the layout's answer, and one list per map is what keeps a widening
 * from arriving in one of the three statements alone.
 */
export const RETENTION_V1_MEMBERS = ['v', 'at', 'policy', 'retained', 'retired', 'chain', 'duty'] as const;
export const RETENTION_V2_MEMBERS = ['v', 'at', 'policy', 'retained', 'retired', 'chain', 'duty', 'presence'] as const;
export const RETENTION_POLICY_MEMBERS = ['maxAgeSeconds', 'maxCount'] as const;
export const RETENTION_WINDOW_MEMBERS = ['from', 'to', 'count'] as const;
export const RETENTION_RETIRED_MEMBERS = ['byAge', 'byCount', 'trims'] as const;
export const RETENTION_TRIM_MEMBERS = ['at', 'byAge', 'byCount', 'under'] as const;
export const RETENTION_CHAIN_MEMBERS = ['anchor', 'head'] as const;
export const RETENTION_DUTY_MEMBERS = ['article', 'requiredSeconds', 'heldSeconds', 'met'] as const;
export const RETENTION_PRESENCE_MEMBERS = ['collateral', 'validity'] as const;
export const RETENTION_FAMILY_MEMBERS = ['count', 'held'] as const;
export const RETENTION_HELD_MEMBERS = ['sha256', 'under'] as const;
export const RETENTION_UNDER_MEMBERS = ['kind', 'value'] as const;

/** The duty labels the layout enumerates, and the two ways a held document can be believed. */
export const RETENTION_DUTY_LABELS = ['19(1)', '19(2)', '26(6)'] as const;
export const RETENTION_UNDER_KINDS = ['root', 'chain'] as const;

/** The two families of the appraisal context, named in the order the layout declares them. */
export const RETENTION_PRESENCE_FAMILIES = ['collateral', 'validity'] as const;

/** A retention policy as the artifact states it: an absent bound means no cap rather than a cap of zero. */
export interface RetentionPolicyState {
  readonly maxAgeSeconds?: number;
  readonly maxCount?: number;
}

/** The surviving set, bounded by the stamps on the volume rather than by the bounds configured. */
export interface RetentionWindow {
  readonly from: number;
  readonly to: number;
  readonly count: number;
}

/** One compaction, with the policy that caused it. */
export interface RetentionTrimEvent {
  readonly at: number;
  readonly byAge: number;
  readonly byCount: number;
  readonly under: RetentionPolicyState;
}

/** The retirement history: two totals by cause and the events behind them. */
export interface RetentionRetired {
  readonly byAge: number;
  readonly byCount: number;
  readonly trims: readonly RetentionTrimEvent[];
}

/** Both chain endpoints, as the store reports them at `at`. */
export interface RetentionChain {
  readonly anchor: string;
  readonly head: string;
}

/** The duty, the period taken from it, the time held, and the comparison of the last two. */
export interface RetentionDuty {
  readonly article: (typeof RETENTION_DUTY_LABELS)[number];
  readonly requiredSeconds: number;
  readonly heldSeconds: number;
  readonly met: boolean;
}

/** What a held document was believed under: a self-signed root, or a chain named at its far end. */
export interface RetentionUnder {
  readonly kind: (typeof RETENTION_UNDER_KINDS)[number];
  readonly value: string;
}

/** One document the store held, named by the digest of its bytes and by the value it was believed under. */
export interface RetentionHeld {
  readonly sha256: string;
  readonly under: RetentionUnder;
}

/** One family of the appraisal context: the store's own count, and the documents behind it. */
export interface RetentionFamily {
  readonly count: number;
  readonly held: readonly RetentionHeld[];
}

/** The appraisal context held at the instant the manifest stamped, in the two families it arrives in. */
export interface RetentionPresence {
  readonly collateral: RetentionFamily;
  readonly validity: RetentionFamily;
}

/** The members the two versions share. */
export interface RetentionBody {
  readonly at: number;
  readonly policy: RetentionPolicyState;
  readonly retained: RetentionWindow;
  readonly retired: RetentionRetired;
  readonly chain: RetentionChain;
  readonly duty: RetentionDuty;
}

/** A version one manifest: whole under its own layout, and naming no presence at all. */
export interface RetentionManifestV1 extends RetentionBody {
  readonly v: 1;
}

/** A version two manifest: the same seven members and the observation this version exists to carry. */
export interface RetentionManifestV2 extends RetentionBody {
  readonly v: 2;
  readonly presence: RetentionPresence;
}

export type RetentionManifest = RetentionManifestV1 | RetentionManifestV2;

const text = new TextEncoder();

function bad(detail: string): ReceiptError {
  return new ReceiptError('RETENTION_BAD_DOCUMENT', detail);
}

function unsupportedVersion(detail: string): ReceiptError {
  return new ReceiptError('RETENTION_UNSUPPORTED_VERSION', detail);
}

/**
 * The closure rule, over one map and then the maps it opens, as `pack.cddl` and `epoch-inventory.cddl` state it:
 * a member the version named by `v` does not define makes the document malformed rather than a document read
 * with the unexpected member dropped. `presence` beside a `v: 1` is that rule's most important case here, and it
 * is refused rather than ignored, because a reader that dropped it would fold a run whose store said something
 * the layout says nothing about.
 */
function assertDefined(raw: JsonObject, members: readonly string[], where: string): void {
  for (const key of raw.keys()) {
    if (typeof key !== 'string' || !members.includes(key)) {
      throw bad(`${where} carries a member this version does not define: ${JSON.stringify(String(key))}`);
    }
  }
}

function readMap(value: unknown, position: string): JsonObject {
  if (!(value instanceof Map)) throw bad(`${position} is not an object`);
  return value as JsonObject;
}

/** A whole number of seconds, a count or a length, and nothing else: a figure no smaller than zero. */
function requireFigure(value: unknown, position: string): number {
  if (typeof value !== 'number' || value < 0) {
    throw bad(`${position} must be a whole number no smaller than zero`);
  }
  return value;
}

/** A digest, stated the way this artifact states every one of them: sixty-four lowercase hex characters. */
function requireDigest(value: unknown, position: string): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/u.test(value)) {
    throw bad(`${position} must be sixty-four lowercase hex characters`);
  }
  return value;
}

function requireFlag(value: unknown, position: string): boolean {
  if (typeof value !== 'boolean') throw bad(`${position} must be true or false`);
  return value;
}

/**
 * A policy as the artifact states it, at both positions that carry one. The two bounds are optional in both, and
 * an absent bound is the statement that none was configured rather than a bound of zero, which is why the two
 * spellings are kept apart here and read back out apart by the writer below.
 */
function readPolicy(value: unknown, position: string): RetentionPolicyState {
  const raw = readMap(value, position);
  assertDefined(raw, RETENTION_POLICY_MEMBERS, position);
  const maxAgeSeconds = raw.get('maxAgeSeconds');
  const maxCount = raw.get('maxCount');
  return {
    ...(maxAgeSeconds === undefined ? {} : { maxAgeSeconds: requireFigure(maxAgeSeconds, `${position}.maxAgeSeconds`) }),
    ...(maxCount === undefined ? {} : { maxCount: requireFigure(maxCount, `${position}.maxCount`) }),
  };
}

function readWindow(value: unknown, position: string): RetentionWindow {
  const raw = readMap(value, position);
  assertDefined(raw, RETENTION_WINDOW_MEMBERS, position);
  return {
    from: requireFigure(raw.get('from'), `${position}.from`),
    to: requireFigure(raw.get('to'), `${position}.to`),
    count: requireFigure(raw.get('count'), `${position}.count`),
  };
}

function readChain(value: unknown, position: string): RetentionChain {
  const raw = readMap(value, position);
  assertDefined(raw, RETENTION_CHAIN_MEMBERS, position);
  return {
    anchor: requireDigest(raw.get('anchor'), `${position}.anchor`),
    head: requireDigest(raw.get('head'), `${position}.head`),
  };
}

/**
 * The duty block, refused for a label outside the three the layout enumerates. No period is bounded: the routed
 * articles name no period at all and the article that does makes its floor one beneath a judgment other law can
 * move, which is the deployment's reading rather than a fact this layout can adjudicate.
 */
function readDuty(value: unknown, position: string): RetentionDuty {
  const raw = readMap(value, position);
  assertDefined(raw, RETENTION_DUTY_MEMBERS, position);
  const article = raw.get('article');
  if (typeof article !== 'string' || !(RETENTION_DUTY_LABELS as readonly string[]).includes(article)) {
    throw bad(`${position}.article names ${JSON.stringify(String(article))}, outside the three labels the layout enumerates`);
  }
  const requiredSeconds = raw.get('requiredSeconds');
  if (typeof requiredSeconds !== 'number' || requiredSeconds < 1) {
    throw bad(`${position}.requiredSeconds must be a whole number of seconds of at least one, so that a stated period is a period`);
  }
  return {
    article: article as RetentionDuty['article'],
    requiredSeconds,
    heldSeconds: requireFigure(raw.get('heldSeconds'), `${position}.heldSeconds`),
    met: requireFlag(raw.get('met'), `${position}.met`),
  };
}

function readRetired(value: unknown, position: string): RetentionRetired {
  const raw = readMap(value, position);
  assertDefined(raw, RETENTION_RETIRED_MEMBERS, position);
  const trims = raw.get('trims');
  if (!Array.isArray(trims)) throw bad(`${position}.trims must be an array`);
  return {
    byAge: requireFigure(raw.get('byAge'), `${position}.byAge`),
    byCount: requireFigure(raw.get('byCount'), `${position}.byCount`),
    trims: trims.map((one, index): RetentionTrimEvent => {
      const site = `${position}.trims[${String(index)}]`;
      const event = readMap(one, site);
      assertDefined(event, RETENTION_TRIM_MEMBERS, site);
      return {
        at: requireFigure(event.get('at'), `${site}.at`),
        byAge: requireFigure(event.get('byAge'), `${site}.byAge`),
        byCount: requireFigure(event.get('byCount'), `${site}.byCount`),
        under: readPolicy(event.get('under'), `${site}.under`),
      };
    }),
  };
}

/**
 * What one document was believed under, as a label and a digest of the bytes carrying it. The two are read
 * together because they are one statement: a store either held the thing that signs or held the run of things
 * leading to it, and a fold that knew the digest but not which of the two it was could not tell a reader which
 * check it would have to repeat.
 */
function readUnder(value: unknown, position: string): RetentionUnder {
  const raw = readMap(value, position);
  assertDefined(raw, RETENTION_UNDER_MEMBERS, position);
  const kind = raw.get('kind');
  if (typeof kind !== 'string' || !(RETENTION_UNDER_KINDS as readonly string[]).includes(kind)) {
    throw bad(`${position}.kind names ${JSON.stringify(String(kind))}, outside the two ways a held document is believed`);
  }
  return { kind: kind as RetentionUnder['kind'], value: requireDigest(raw.get('value'), `${position}.value`) };
}

/**
 * One family of the appraisal context, and the two refusals that make its figures mean one thing. `count` is the
 * store's own figure and `held` is the list beside it, so a count that is not the length of the list is the
 * document disagreeing with itself. A digest named twice within one family is refused the same way: the fold
 * matches an entry by the digest it names, the way the inventory matches the rows of its own two lists, and a
 * family that named one digest twice leaves another of its documents answered by the entry that already settled
 * it, which is one document stated twice and one stated nowhere.
 */
function readFamily(value: unknown, position: string): RetentionFamily {
  const raw = readMap(value, position);
  assertDefined(raw, RETENTION_FAMILY_MEMBERS, position);
  const held = raw.get('held');
  if (!Array.isArray(held)) throw bad(`${position}.held must be an array`);
  const entries = held.map((one, index): RetentionHeld => {
    const site = `${position}.held[${String(index)}]`;
    const item = readMap(one, site);
    assertDefined(item, RETENTION_HELD_MEMBERS, site);
    return { sha256: requireDigest(item.get('sha256'), `${site}.sha256`), under: readUnder(item.get('under'), `${site}.under`) };
  });
  const count = requireFigure(raw.get('count'), `${position}.count`);
  if (count !== entries.length) {
    throw bad(`${position}.count states ${String(count)} and ${position}.held lists ${String(entries.length)}, which is the same figure read two ways`);
  }
  const named = new Set<string>();
  for (const one of entries) {
    if (named.has(one.sha256)) {
      throw bad(`${position} names the digest ${one.sha256} twice, so one held document is stated twice and another is named nowhere in the list`);
    }
    named.add(one.sha256);
  }
  return { count, held: entries };
}

function readPresence(value: unknown, position: string): RetentionPresence {
  const raw = readMap(value, position);
  assertDefined(raw, RETENTION_PRESENCE_MEMBERS, position);
  return {
    collateral: readFamily(raw.get('collateral'), `${position}.collateral`),
    validity: readFamily(raw.get('validity'), `${position}.validity`),
  };
}

/**
 * The arithmetic between the members the layout cannot hold, stated in section 5.3 of
 * `docs/receipt-spec.md` and refused here rather than left to a reader's attention. `heldSeconds` is `at` less
 * `retained.from`, or zero for a store holding nothing rather than a subtraction from the epoch, and `met` is the
 * comparison of the two integers beside it. A trim event stamped after the manifest carrying it is the third case
 * of the same fault. Each is refused as a malformed document rather than reported as a deployment that held less
 * than it promised, because the document disagrees with itself and a reader owes that answer the other one.
 */
function assertStatedArithmetic(manifest: RetentionBody): void {
  const expectedHeld = manifest.retained.count === 0 ? 0 : manifest.at - manifest.retained.from;
  if (manifest.duty.heldSeconds !== expectedHeld) {
    throw bad(
      `duty.heldSeconds states ${String(manifest.duty.heldSeconds)} and ${String(manifest.at)} less retained.from ${String(manifest.retained.from)} for a store holding ${String(manifest.retained.count)} is ${String(expectedHeld)}`,
    );
  }
  if (manifest.duty.met !== manifest.duty.heldSeconds >= manifest.duty.requiredSeconds) {
    throw bad(
      `duty.met states ${String(manifest.duty.met)} beside heldSeconds ${String(manifest.duty.heldSeconds)} and requiredSeconds ${String(manifest.duty.requiredSeconds)}`,
    );
  }
  for (const [index, one] of manifest.retired.trims.entries()) {
    if (one.at > manifest.at) {
      throw bad(`retired.trims[${String(index)}] is stamped ${String(one.at)}, after the ${String(manifest.at)} the manifest itself carries`);
    }
  }
}

/**
 * A retention manifest, out of the bytes of the file as it sits on the volume.
 *
 * The reading is the strict one the epoch inventory uses for its own payload, and for the same two reasons: a
 * member named twice would be settled by `JSON.parse` into whichever value the parser reached last while the
 * hashed bytes carry both, and a float wearing an integer arrives at a check as the very number it imitates.
 * Those two facts outlive any layout, and a manifest whose bytes an inventory hashed is exactly the document
 * where a lost member is not a hypothetical.
 *
 * The version is asked of `RETENTION_FORMAT_VERSIONS` rather than matched against a literal, and the version is
 * read before any member of the document is, because which member list applies is the one question a reader has
 * to answer first and the one answer a wrong version cannot be talked out of.
 */
export function parseRetentionDocument(bytes: Uint8Array): RetentionManifest {
  const raw = readJsonBytes(bytes, (detail) => {
    throw new ReceiptError('RETENTION_BAD_DOCUMENT', detail);
  });
  const document = readMap(raw, 'manifest');
  const version = document.get('v');
  if (typeof version !== 'number') {
    throw bad('v must be an integer retention version');
  }
  if (!RETENTION_FORMAT_VERSIONS.includes(version)) {
    throw unsupportedVersion(`retention version ${String(version)} is not a layout this package reads`);
  }
  if (version === 1) {
    assertDefined(document, RETENTION_V1_MEMBERS, 'manifest');
  } else {
    assertDefined(document, RETENTION_V2_MEMBERS, 'manifest');
  }
  const at = requireFigure(document.get('at'), 'at');
  const body: RetentionBody = {
    at,
    policy: readPolicy(document.get('policy'), 'policy'),
    retained: readWindow(document.get('retained'), 'retained'),
    retired: readRetired(document.get('retired'), 'retired'),
    chain: readChain(document.get('chain'), 'chain'),
    duty: readDuty(document.get('duty'), 'duty'),
  };
  assertStatedArithmetic(body);
  if (version === 1) return { v: 1, ...body };
  return { v: 2, ...body, presence: readPresence(document.get('presence'), 'presence') };
}

/** One policy block, its two bounds emitted only where the document states them. */
function policyToWrite(policy: RetentionPolicyState): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (policy.maxAgeSeconds !== undefined) out.maxAgeSeconds = policy.maxAgeSeconds;
  if (policy.maxCount !== undefined) out.maxCount = policy.maxCount;
  return out;
}

function presenceToWrite(presence: RetentionPresence): Record<string, unknown> {
  const family = (one: RetentionFamily): Record<string, unknown> => ({
    count: one.count,
    held: one.held.map((each) => ({ sha256: each.sha256, under: { kind: each.under.kind, value: each.under.value } })),
  });
  return { collateral: family(presence.collateral), validity: family(presence.validity) };
}

/**
 * The document as a file: two-space indented, newline terminated, in the field order the layout declares. This
 * one *is* a rule rather than a convenience, and the reason is the digest: an inventory seals sha256 over this
 * file's bytes, so a writer that emitted a caller's key order would give two deployments holding the same store
 * state two digests, and a reader comparing the two would be told one of them is not what was sealed. An
 * optional member that arrived as `undefined` is left out rather than written as null, because the layout reads
 * an absent bound as no bound configured and a null as a value of the wrong type.
 */
export function encodeRetentionDocument(manifest: RetentionManifest): Uint8Array {
  const body = manifest;
  const document: Record<string, unknown> = {
    v: manifest.v,
    at: body.at,
    policy: policyToWrite(body.policy),
    retained: { from: body.retained.from, to: body.retained.to, count: body.retained.count },
    retired: {
      byAge: body.retired.byAge,
      byCount: body.retired.byCount,
      trims: body.retired.trims.map((one) => ({
        at: one.at,
        byAge: one.byAge,
        byCount: one.byCount,
        under: policyToWrite(one.under),
      })),
    },
    chain: { anchor: body.chain.anchor, head: body.chain.head },
    duty: {
      article: body.duty.article,
      requiredSeconds: body.duty.requiredSeconds,
      heldSeconds: body.duty.heldSeconds,
      met: body.duty.met,
    },
    ...(manifest.v === 2 ? { presence: presenceToWrite(manifest.presence) } : {}),
  };
  return text.encode(`${JSON.stringify(document, null, 2)}\n`);
}

/**
 * The bytes this writer would produce for a manifest, run back through this module's own reader before a caller
 * hands them to an inventory to hash. A deployment cannot seal a manifest its own reader refuses, which is the
 * same promise `signPack` makes about a pack and `signEpochInventory` makes about a run: the refusal arrives
 * where the bytes are made rather than at a reviewer holding them months later.
 */
export function retentionDocumentBytes(manifest: RetentionManifest): Uint8Array {
  const bytes = encodeRetentionDocument(manifest);
  parseRetentionDocument(bytes);
  return bytes;
}
