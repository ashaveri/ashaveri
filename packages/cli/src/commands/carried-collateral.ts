import {
  appraiseCarriedCollateral,
  type CollateralOriginName,
  type CollateralOutcome,
  type CollateralQuery,
  type CollateralRefusal,
  type IntelPlatform,
  type IntelTcbLevel,
} from '@ashaveri/collateral';
import { resolveCarried, toHex, type CollateralSlot, type PackManifest, type TeeKind, type VerifiedPackItem } from '@ashaveri/receipt';
import { UsageError, printedToken } from '../usage.js';
import { readBytes } from './verify-receipt.js';

/**
 * The material a pack carries, weighed against the roots the caller handed.
 *
 * A pack's `carried` list holds the bytes a sealed receipt's `held` anchor slot digests, and `resolveCarried`
 * answers one digest with the object that hashes to it. Those bytes are the vendor's own signed statement about a
 * platform, and such a statement is worth only what it says under the roots a reader stands behind and at the
 * moment it is read against. This file asks the collateral package that question for every slot a pack carries
 * material for, and hands the answer back as rows for the report rather than as a verdict: the command that runs
 * it applies no policy, demands no anchor and changes no exit code on anything it prints here.
 *
 * The question is answerable only for material of the envelope the origin's declaration decodes. Intel serves its
 * documents as a body with a hex signature member and its issuer chain in a response header, cited at each
 * declaration in `@ashaveri/collateral`'s `intel-origin.ts`, and a container holds the body with no header beside
 * it, so bytes taken in as that address actually answers them are refused here at the envelope. A `held` slot
 * states that the pack carries the bytes an anchor digests; it does not state that a reader holding the pack can
 * walk a chain out of them.
 *
 * Where each field of the question comes from is the first thing to settle, because the package settles all of
 * them before it reads a byte of the answer: `askedButNotGiven` refuses an unnamed root, instant or level, and
 * `requestUrl` refuses an unnamed or malformed CPU type, and no refusal of either can be met out of the bytes
 * being weighed. Measured against the two documents that hold this material:
 *
 * - the pack states, per carried entry, bytes and their digest, and `resolveCarried` hands back the bytes it
 *   found by re-hashing them against the digest asked;
 * - the sealed receipt states, per anchor slot, `held` and a digest, and the stamp that record was chained at,
 *   which `resolveCarried` reports beside the material;
 * - the receipt also states `meas.tee`, which is the environment kind its own measurement is of.
 *
 * So the material, the instant the pack states it held it, and the instant to read it against are all stated by
 * the sealed evidence, and every one of them comes from there: `heldAt` and `appraisalAt` are the naming record's
 * stamp, which is what `CarriedCollateral` asks a container's reader for and what leaves the vendor's signed
 * window beside `claim.appraisalAt` in the figures a reader weighs. Nothing here mints a moment out of a clock.
 *
 * What the sealed evidence does not state is the identity the answer is about. `TeeKind` has no `sgx` arm at all,
 * its `snp` and `software` arms name no platform whose collateral this package reads, and the published pack
 * vectors carry an Intel TCB info and a firmware measurements document under receipts whose `tee` is `snp+gpucc`
 * while others of them name `tdx`, so a record's environment kind is a fact about the machine the measurement is
 * of rather than the path its collateral was published by. Reading a platform out of a `tee` would be this file's
 * guess written into somebody else's verdict, and it would make the collateral of every `snp` receipt unweighable.
 * No origin is stated either: the two halves of one anchor hold two different documents, and the format gives a
 * carried object no name but its digest. And the package refuses, on purpose, to let a signed document answer for
 * its own identity: it reads the `fmspc` the document declares and refuses one covering another machine than the
 * one asked about, which is the check that stops a misindexed answer passing.
 *
 * So `--collateral-origin`, `--collateral-platform`, `--collateral-cpu-type` and `--collateral-level` are the
 * caller's designation, each keyed by the anchor slot the container itself names, and the report prints the naming
 * receipt's own `meas.tee` beside the designated platform so that a reader handed a contradiction sees both
 * numbers instead of only the one this run asked with.
 */

/** The flag that names the roots this run stands behind, the same flag `ashaveri verify` reads. */
export const INTEL_ROOT_FLAG = '--intel-root';

/** The flag that names which origin path one anchor slot's material was published by. */
export const COLLATERAL_ORIGIN_FLAG = '--collateral-origin';

/** The flag that names which Intel platform one slot's collateral was published for. */
export const COLLATERAL_PLATFORM_FLAG = '--collateral-platform';

/** The flag that names the CPU type one slot's collateral is indexed by, Intel's FMSPC id as hex text. */
export const COLLATERAL_CPU_TYPE_FLAG = '--collateral-cpu-type';

/** The flag that names which rung of the vendor's ladder the appraisal is asked about. */
export const COLLATERAL_LEVEL_FLAG = '--collateral-level';

/** The two anchor slots, spelled as the container and `resolveCarried` spell them. */
export type CarriedSlotLabel = 'col' | 'val';

const SLOT_LABELS: readonly CarriedSlotLabel[] = ['col', 'val'];

const PLATFORMS: readonly IntelPlatform[] = ['sgx', 'tdx'];

/** The two arms of `IntelTcbLevel`, so an argument that spells neither is refused at the call. */
const LEVEL_KINDS: readonly IntelTcbLevel['by'][] = ['tcb-date', 'tcb-composition'];

/** The five options this file reads, as the one parse in `cli.ts` produces them. */
export interface CarriedFlagValues {
  'intel-root'?: string[];
  'collateral-origin'?: string[];
  'collateral-platform'?: string[];
  'collateral-cpu-type'?: string[];
  'collateral-level'?: string[];
}

/** What one anchor slot was asked about, in the four fields the seal does not state. */
export interface SlotDesignation {
  /** The origin as the caller spelled it: any name of the union, including the four this package does not read. */
  readonly origin: CollateralOriginName;
  readonly platform: IntelPlatform;
  readonly cpuType: string | null;
  readonly level: IntelTcbLevel | null;
  /** Each field beside the flag and slot that carried it, which is the source the report names. */
  readonly from: {
    readonly origin: string;
    readonly platform: string;
    readonly cpuType: string;
    readonly level: string;
  };
}

/** Everything this run was handed about the material a pack carries. */
export interface CarriedDesignations {
  /** The roots as the files hold them, PEM or DER. An empty set is a state of the call, never a default. */
  readonly roots: readonly Uint8Array[];
  /** The names each root was read from, printed so a report says where an anchor came from. */
  readonly rootPaths: readonly string[];
  /** One designation per anchor slot the caller named. */
  readonly bySlot: ReadonlyMap<CarriedSlotLabel, SlotDesignation>;
  /** Whether any of the five flags was handed at all, which decides whether the report owes a line. */
  readonly asked: boolean;
}

/** The question one slot was asked, in the shapes both renderings print. */
export interface CarriedQuestion {
  readonly origin: string;
  readonly platform: string;
  readonly cpuType: string | null;
  readonly level: string | null;
  readonly roots: number;
  readonly from: SlotDesignation['from'] & { readonly roots: string };
}

/** One held slot's answer, as this file weighed it. */
export interface CarriedWeighing {
  /** The digest the held slot states, which is the only name the pack gives this material. */
  readonly digest: string;
  /** The record `resolveCarried` names, and which of its slots asked. */
  readonly item: string;
  readonly slot: CarriedSlotLabel;
  /** Unix seconds: the stamp that record was chained at, which is both the held instant and the moment weighed. */
  readonly iat: number;
  /** How many bytes the pack carries for this digest. */
  readonly bytes: number;
  /** Every held slot of every sealed receipt stating this digest, which is what the pack's deduplication means. */
  readonly namedBy: readonly { readonly item: string; readonly slot: CarriedSlotLabel }[];
  /** The environment kind the naming receipt states, printed beside the designated platform. */
  readonly environment: TeeKind;
  /** The question this run asked, or null where it could not ask one. */
  readonly question: CarriedQuestion | null;
  /** Why nothing was weighed, naming the flag that would have supplied the field. */
  readonly notWeighed: string | null;
  /** What the appraisal answered, or null where none ran. */
  readonly outcome: CollateralOutcome | null;
}

/** A slot that states an absence: owed no material, and answering nothing against a digest. */
export interface CarriedAbsence {
  readonly item: string;
  readonly slot: CarriedSlotLabel;
  readonly presence: string;
  readonly reason: string;
}

/** What one pack's held slots amount to. */
export interface CarriedReading {
  readonly weighings: readonly CarriedWeighing[];
  readonly absences: readonly CarriedAbsence[];
  readonly designations: CarriedDesignations;
}

/** `<slot>=<value>` read as a slot and the rest of it. */
function slotValue(value: string, flag: string): { readonly slot: CarriedSlotLabel; readonly rest: string } {
  const at = value.indexOf('=');
  if (at < 0) {
    throw new UsageError(
      `${flag} takes '<slot>=<value>', where the slot is '${SLOT_LABELS[0]}' or '${SLOT_LABELS[1]}' as an anchor names them, and this argument states no slot before its '='`,
    );
  }
  const slot = value.slice(0, at) as CarriedSlotLabel;
  if (!SLOT_LABELS.includes(slot)) {
    throw new UsageError(`${flag} names '${value.slice(0, at)}', and a sealed receipt's anchor has two slots: '${SLOT_LABELS[0]}' and '${SLOT_LABELS[1]}'`);
  }
  const rest = value.slice(at + 1);
  if (rest.length === 0) {
    throw new UsageError(`${flag} names the '${slot}' slot and states nothing for it`);
  }
  return { slot, rest };
}

/** One slot's designation as the four flags fill it in. */
interface DraftDesignation {
  origin?: { value: CollateralOriginName; from: string };
  platform?: { value: IntelPlatform; from: string };
  cpuType?: { value: string; from: string };
  level?: { value: IntelTcbLevel; from: string };
}

/**
 * One slot's completed designation, refused by the field it lacks rather than by a default standing in for it.
 *
 * Origin and platform go together because the query carries both as fields it cannot leave empty, and the pairing
 * is a fact about the paths: an origin is a document type and a platform is which machine's ladder it is
 * published on. A CPU type and a level are not demanded here because the package demands them by origin, and its
 * own refusal naming the field is a better answer than this file guessing which origin needs which.
 */
function completed(slot: CarriedSlotLabel, draft: DraftDesignation): SlotDesignation {
  const origin = draft.origin;
  const platform = draft.platform;
  if (origin === undefined) {
    throw new UsageError(`${COLLATERAL_PLATFORM_FLAG} names the '${slot}' slot, which ${COLLATERAL_ORIGIN_FLAG} named no origin for: an origin is the path a platform publishes collateral by`);
  }
  if (platform === undefined) {
    throw new UsageError(`${COLLATERAL_ORIGIN_FLAG} names the '${slot}' slot as ${origin.value}, and ${COLLATERAL_PLATFORM_FLAG} names no platform for it: this package publishes collateral for ${PLATFORMS.join(' and ')}`);
  }
  return {
    origin: origin.value,
    platform: platform.value,
    cpuType: draft.cpuType?.value ?? null,
    level: draft.level?.value ?? null,
    from: {
      origin: origin.from,
      platform: platform.from,
      cpuType: draft.cpuType?.from ?? 'none named',
      level: draft.level?.from ?? 'none named',
    },
  };
}

/** `<by>=<value>`, refused by the arm the query does not carry. */
function levelValue(slot: CarriedSlotLabel, value: string): IntelTcbLevel {
  const at = value.indexOf('=');
  const kind = (at < 0 ? value : value.slice(0, at)) as IntelTcbLevel['by'];
  if (!LEVEL_KINDS.includes(kind)) {
    throw new UsageError(
      `${COLLATERAL_LEVEL_FLAG} names '${at < 0 ? value : value.slice(0, at)}' for the '${slot}' slot, and a level is asked by one of the two arms the query carries, '${LEVEL_KINDS[0]}=<value>' or '${LEVEL_KINDS[1]}=<value>'`,
    );
  }
  const rest = at < 0 ? '' : value.slice(at + 1);
  if (rest.length === 0) {
    throw new UsageError(`${COLLATERAL_LEVEL_FLAG} names '${kind}' for the '${slot}' slot and states no value for it`);
  }
  return { by: kind, value: rest };
}

/**
 * The designations this run was handed, with the root files read.
 *
 * Refused before the document is opened, exactly as a key designation is: a slot that is not a slot, a level with
 * no arm, an origin with no platform and an unreadable root file are all mistakes whoever the file turns out to
 * be. Nothing is demanded: a run that handed no designation still reads the pack and reports each held slot as
 * not weighed with the reason, which is the gap in the call stated where the caller reads it.
 */
export async function carriedDesignations(values: CarriedFlagValues): Promise<CarriedDesignations> {
  const rootPaths = values['intel-root'] ?? [];
  const roots: Uint8Array[] = [];
  for (const path of rootPaths) {
    roots.push(await readBytes(path, INTEL_ROOT_FLAG));
  }

  const drafts = new Map<CarriedSlotLabel, DraftDesignation>();
  const draft = (slot: CarriedSlotLabel): DraftDesignation => {
    const found = drafts.get(slot);
    if (found !== undefined) return found;
    const fresh: DraftDesignation = {};
    drafts.set(slot, fresh);
    return fresh;
  };
  // A slot has one of each field, and which field a repeat fills is read off the draft rather than off whether
  // the slot has a draft at all: four flags name one slot in the ordinary run, an origin, a platform, an identity
  // and a rung, and a check on the slot would refuse the call this whole surface is for.
  const once = (flag: string, slot: CarriedSlotLabel, says: string, already: unknown): void => {
    if (already !== undefined) {
      throw new UsageError(`${flag} names the '${slot}' slot twice, and a slot has one ${says} per run`);
    }
  };

  for (const value of values['collateral-origin'] ?? []) {
    const { slot, rest } = slotValue(value, COLLATERAL_ORIGIN_FLAG);
    const one = draft(slot);
    once(COLLATERAL_ORIGIN_FLAG, slot, 'origin, which is the path the bytes were published by', one.origin);
    // The name is matched against no list kept here, on purpose. The package answers an origin it does not read
    // with the sentence naming the two it does, which is the reason all six names are in the union at all; a
    // second copy of that set in this file would be a thing to remember on the day the set grew.
    one.origin = { value: rest as CollateralOriginName, from: `${COLLATERAL_ORIGIN_FLAG} ${slot}=${printedToken(rest)}` };
  }
  for (const value of values['collateral-platform'] ?? []) {
    const { slot, rest } = slotValue(value, COLLATERAL_PLATFORM_FLAG);
    if (!PLATFORMS.includes(rest as IntelPlatform)) {
      throw new UsageError(`${COLLATERAL_PLATFORM_FLAG} names '${rest}' for the '${slot}' slot, and this package publishes collateral for ${PLATFORMS.join(' and ')}`);
    }
    const one = draft(slot);
    once(COLLATERAL_PLATFORM_FLAG, slot, 'platform, which is the machine that path publishes for', one.platform);
    one.platform = { value: rest as IntelPlatform, from: `${COLLATERAL_PLATFORM_FLAG} ${slot}=${rest}` };
  }
  for (const value of values['collateral-cpu-type'] ?? []) {
    const { slot, rest } = slotValue(value, COLLATERAL_CPU_TYPE_FLAG);
    const one = draft(slot);
    once(COLLATERAL_CPU_TYPE_FLAG, slot, 'CPU type', one.cpuType);
    // The shape is not checked here: `requestUrl` refuses a CPU type that is not twelve hex characters, in the
    // code naming the field, and a second pattern in this file would be two answers to one malformed argument.
    one.cpuType = { value: rest, from: `${COLLATERAL_CPU_TYPE_FLAG} ${slot}=${printedToken(rest)}` };
  }
  for (const value of values['collateral-level'] ?? []) {
    const { slot, rest } = slotValue(value, COLLATERAL_LEVEL_FLAG);
    const one = draft(slot);
    once(COLLATERAL_LEVEL_FLAG, slot, 'level, which is one rung of the ladder', one.level);
    one.level = { value: levelValue(slot, rest), from: `${COLLATERAL_LEVEL_FLAG} ${slot}=${printedToken(rest)}` };
  }

  const bySlot = new Map<CarriedSlotLabel, SlotDesignation>();
  for (const [slot, one] of drafts) bySlot.set(slot, completed(slot, one));

  return { roots, rootPaths, bySlot, asked: rootPaths.length > 0 || drafts.size > 0 };
}

/** Which of an anchor's two slots state a digest, and which state an absence instead. */
function slotsOf(one: VerifiedPackItem): readonly {
  readonly item: string;
  readonly slot: CarriedSlotLabel;
  readonly sha256: Uint8Array | null;
  readonly presence: string;
  readonly reason: string;
  readonly environment: TeeKind;
}[] {
  const payload = one.receipt.payload;
  // Every receipt a pack seals names an anchor, so both slots of every item reach the list below: a
  // slot stating a digest asks the pack for the material behind it, and a slot stating an absence asks
  // for nothing.
  const halves: readonly (readonly [CarriedSlotLabel, CollateralSlot])[] = [
    ['col', payload.cva.collateral],
    ['val', payload.cva.validity],
  ];
  return halves.map(([slot, value]) => ({
    item: one.item.id,
    slot,
    sha256: value.presence === 'held' ? value.sha256 : null,
    presence: value.presence,
    reason: value.presence === 'held' ? '' : value.reason,
    environment: payload.meas.tee,
  }));
}

/**
 * The material each held slot names, weighed.
 *
 * Slots are gathered by digest before anything is weighed, because the pack deduplicates its material and
 * `resolveCarried` keys on the digest alone: three records naming one collateral document is one object, and
 * weighing it three times would report three verdicts on bytes the container states once. Every slot stating the
 * digest is printed beside the answer all the same, because the report answers for the slots the receipts state,
 * and the record the lookup names is the one whose stamp the answer is read against.
 *
 * The appraisal is never asked to refuse: `onAbsent` is `unassessed`, which is the difference between a reader
 * reporting an archive and a verifier demanding current context of it. A thrown refusal would turn a
 * `missing-context` answer into an exit code, and nothing the format does not refuse earns one here.
 */
export async function weighCarried(
  manifest: PackManifest,
  walked: readonly VerifiedPackItem[],
  designations: CarriedDesignations,
): Promise<CarriedReading> {
  const stated = walked.flatMap((one) => slotsOf(one));
  const absences: CarriedAbsence[] = stated
    .filter((one) => one.sha256 === null)
    .map((one) => ({ item: one.item, slot: one.slot, presence: one.presence, reason: one.reason }));

  const byDigest = new Map<string, typeof stated>();
  for (const one of stated) {
    if (one.sha256 === null) continue;
    const hex = toHex(one.sha256);
    const named = byDigest.get(hex);
    if (named === undefined) byDigest.set(hex, [one]);
    else named.push(one);
  }

  const weighings: CarriedWeighing[] = [];
  for (const [hex, slots] of byDigest) {
    const first = slots[0] as (typeof stated)[number];
    const resolution = resolveCarried(manifest, first.sha256 as Uint8Array);
    // The environment kind printed beside the designated platform is the naming record's own: the receipt the
    // lookup says asked for this material, rather than whichever slot of the pack was met first here.
    const naming = walked.find((one) => one.item.id === resolution.item);
    const base: CarriedWeighing = {
      digest: hex,
      item: resolution.item,
      slot: resolution.slot,
      iat: resolution.iat,
      bytes: resolution.bytes.byteLength,
      namedBy: slots.map((one) => ({ item: one.item, slot: one.slot })),
      environment: naming?.receipt.payload.meas.tee ?? first.environment,
      question: null,
      notWeighed: null,
      outcome: null,
    };

    const designation = designations.bySlot.get(resolution.slot);
    if (designation === undefined) {
      weighings.push({
        ...base,
        notWeighed: `${COLLATERAL_ORIGIN_FLAG} and ${COLLATERAL_PLATFORM_FLAG} named no '${resolution.slot}' question, so this run asked nothing of the bytes that digest names`,
      });
      continue;
    }

    const question: CarriedQuestion = {
      origin: designation.origin,
      platform: designation.platform,
      cpuType: designation.cpuType,
      level: designation.level === null ? null : `${designation.level.by}=${designation.level.value}`,
      roots: designations.roots.length,
      from: {
        ...designation.from,
        roots: designations.rootPaths.length === 0
          ? `${INTEL_ROOT_FLAG} named none, and no root bundled with the verifier was consulted`
          : `${INTEL_ROOT_FLAG} ${designations.rootPaths.map((one) => printedToken(one)).join(' and ')}`,
      },
    };
    const query: Omit<CollateralQuery, 'retained'> = {
      origin: designation.origin,
      platform: designation.platform,
      cpuType: designation.cpuType,
      level: designation.level,
      appraisalAt: resolution.iat,
      roots: designations.roots,
      onAbsent: 'unassessed',
    };
    // The container states no header beside these bytes, so the pair is handed as a body alone: the appraisal
    // reads the absence rather than inventing a header, and a pack that came to state one would hand its own
    // bytes through the same two positions.
    const outcome = await appraiseCarriedCollateral(query, {
      bytes: resolution.bytes,
      chain: null,
      chainSha256: null,
      heldAt: resolution.iat,
    });
    weighings.push({ ...base, question, outcome });
  }
  return { weighings, absences, designations };
}

/**
 * The one sentence that states the root rule, because it is not the rule `ashaveri verify` keeps and a reader of
 * both will notice the difference.
 *
 * `verify` reads a policy document, and a family that document leaves out accepts the roots bundled with the
 * library: the bundle belongs to whichever verifier is installed, the printed digest covers only what the
 * operator named, and `rootsForFamily` says so in code. This path has no policy document and no family default.
 * The material is not a quote to chain but an archive to weigh, and the collateral package refuses a substituted
 * anchor in the field that carries it: a library default is not this caller's pin, and an appraisal that inherited
 * one would report a verdict reached on a trust decision nobody made at this command line. So the roots here are
 * exactly the files `--intel-root` named, one per flag, and a run that named none asks the appraisal with an
 * empty set and prints the refusal that answers it. The flag's own name is shared with `verify` because the bytes
 * are the same kind of thing, a root the operator holds and cites; it is the rule around them that differs.
 */
export function rootRule(designations: CarriedDesignations): string {
  const handed = designations.rootPaths.length;
  if (handed === 0) {
    return `no ${INTEL_ROOT_FLAG} was handed, so nothing here stands behind any anchor and no root bundled with the verifier was consulted either`;
  }
  return (
    `${String(handed)} ${INTEL_ROOT_FLAG} file(s) handed, and those files are the whole of what this run stands behind: ` +
    'no root bundled with the verifier is consulted on this path, and none was'
  );
}

/** Where each field of the question came from, which is what the report prints beside the answers. */
export function fieldSources(designations: CarriedDesignations): readonly { readonly field: string; readonly from: string }[] {
  const designated = [...designations.bySlot].map(([slot, one]) => `${slot}: ${one.from.origin} and ${one.from.platform}`).join('; ');
  return [
    { field: 'bytes', from: `the pack's carried entry, found by the digest the held slot states and re-hashed by resolveCarried` },
    { field: 'heldAt', from: 'the stamp the naming record was chained at, which resolveCarried reports beside the material' },
    { field: 'appraisalAt', from: 'that same stamp: the moment asked about is the moment the seal states, and no clock of this run reads' },
    {
      field: 'platform',
      from: designated.length === 0
        ? `${COLLATERAL_PLATFORM_FLAG} named none, and a sealed receipt's meas.tee names the machine its own measurement is of rather than the path its collateral was published by`
        : `${COLLATERAL_PLATFORM_FLAG}: ${designated}`,
    },
    { field: 'cpuType', from: `${COLLATERAL_CPU_TYPE_FLAG}, or none where the origin is not indexed by one: the identity a signed document declares for itself is weighed against what was asked and never taken from it` },
    { field: 'level', from: `${COLLATERAL_LEVEL_FLAG}, or none: the vendor's ladder is read at the rung the caller names, and an unanchored rung is how an archive is read as an answer about a platform nobody checked` },
    { field: 'roots', from: `${INTEL_ROOT_FLAG}, and nothing bundled with the verifier` },
    { field: 'onAbsent', from: 'this command, as unassessed: it reports the archive in front of it and demands no current context of it' },
  ];
}

/**
 * The question as one printed line, with an unnamed field spelled as unnamed rather than left blank.
 *
 * Three of the five figures on this line are the caller's own text: the origin and the CPU type as they were
 * spelled, and the rung as it was named, none of which is validated before the appraisal refuses it. They are
 * quoted on the shared cell rule because the line is one of several clauses the row joins with `; `, and a
 * token that could end a row or move a cursor would otherwise be reported as though this run had written it.
 * The platform and the root count need no guard: one is matched against the two arms this package publishes for
 * before it is stored, and the other is a figure.
 */
export function questionText(question: CarriedQuestion): string {
  const parts = [`origin ${printedToken(question.origin)}`, `platform ${question.platform}`];
  parts.push(question.cpuType === null ? 'cpu type none named' : `cpu type ${printedToken(question.cpuType)}`);
  parts.push(question.level === null ? 'level none named' : `level ${printedToken(question.level)}`);
  parts.push(question.roots === 0 ? 'roots none handed' : `roots ${String(question.roots)} handed`);
  return parts.join(', ');
}

/** The refusal an answer carries, or null where the answer carried none. */
export function refusalOf(outcome: CollateralOutcome): CollateralRefusal | null {
  return 'refusal' in outcome ? outcome.refusal : null;
}
