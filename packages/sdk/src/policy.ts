import { toHex } from './b64.js';
import { fromBase64Url } from './b64.js';
import { SdkError } from './errors.js';
import type { CollateralAbsent, CollateralHeld, CollateralSlot, CollateralValidityAnchor } from '@ashaveri/receipt';
import type { EvidenceTrustAnchors } from './evidence.js';
import type { DeploymentManifest } from './manifest.js';

/**
 * How far the client's own clock may sit from a receipt's `iat` before strict mode refuses it:
 * how long after the gateway stamped a receipt a client may still be shown it.
 *
 * Five minutes is the published allowance for presenting a signed statement, taken from the two
 * ecosystems that print the number rather than leaving each implementer to invent one. MIT's
 * `krb5.conf` describes `[libdefaults] clockskew` as what "the library will tolerate before
 * assuming that a Kerberos message is invalid", and states "The default value is 300 seconds, or
 * five minutes"
 * (https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html). AWS, on the page
 * that owns Signature Version 4, gives the same horizon for how stale a signed request may be:
 * "In most cases, a request must reach AWS within five minutes of the time stamp in the request.
 * Otherwise, AWS denies the request"
 * (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html, "Why requests are signed").
 *
 * ashaveri sits at that line rather than below it for one reason specific to this check: neither
 * of those two systems is timing its own document. A KDC and an AWS endpoint both compare a
 * timestamp against a clock on hardware they administer, while `iat` was stamped by a gateway in a
 * confidential VM and is measured here against the clock of a laptop that VM does not own and
 * cannot keep in step. The window has to absorb the skew between two uncoordinated machines plus
 * the fetch of the receipt, which is what those protocols decided a roughly-set clock deserves.
 * Going wider is the wrong trade: past this much time a receipt is a perfectly valid record of a
 * conversation that finished, and a caller that accepts it is answering "is this a replay?" with a
 * signature.
 *
 * A policy with no `maxReceiptAgeSeconds` gets this number. A policy that says
 * `Number.POSITIVE_INFINITY` gets no receipt window at all, which is the archive case.
 */
export const DEFAULT_MAX_RECEIPT_AGE_SECONDS = 300;

/**
 * How far the client's clock may sit from a receipt's `att.ts`, the moment the platform quote it
 * commits to was collected. A different quantity from the one above, and deliberately looser.
 *
 * The looseness is not generosity about the clock; it is the shape of a completion. The gateway
 * starts the evidence fetch beside the upstream call and stamps `iat` after the last byte reaches
 * the client (`gateway/src/server.ts`: "Evidence is gathered while the model generates"), so the
 * quote is older than the receipt by the request's own duration and a verifier sees
 * `now - att.ts = (now - iat) + generation time`. Reusing the 300-second figure here would refuse
 * every long completion for a fault that is not the evidence's, so this is that figure plus ten
 * minutes of generation. The parts the gateway itself bounds sit well inside the addition: the
 * guest agent has 30 seconds per quote call and quotes serially on the TDX driver
 * (`gateway/src/guest.ts`), the first byte from an upstream may take two minutes
 * (`FIRST_EVENT_TIMEOUT_MS`, `gateway/src/server.ts`), and a device collection "costs a real device
 * seconds" (`gateway/src/dstack.ts`).
 *
 * What keeps this in minutes instead of hours is where evidence comes from, and it turned out to
 * come from the tight place. A live deployment mints it per request: the challenge is
 * `sha256(nonce, requestHash)` for the request being served, and `dstackDeployment` caches by that
 * challenge, so the evidence behind a receipt is always a cache miss and a fresh call to the guest
 * agent. The cache exists so a *re-read* of one challenge keeps returning the same bytes (`att.d`
 * binds `sha256(document)`, so `att.url` has to stay fetchable to mean anything) and not so an old
 * quote can answer a new request. Had it cut the other way, with standing evidence reused across
 * requests, `att.ts` would name a boot and no window in minutes could be both honest and usable:
 * this number would then have had to be an uptime, and the check would have stopped catching
 * anything.
 *
 * 900 seconds is also the horizon this gateway already publishes for a signed moment.
 * `REPLAY_WINDOW_SECONDS` in `gateway/src/access.ts` is how long a presented authorization stays
 * remembered on the serving side, so a client that stops trusting an evidence timestamp at the same
 * minute is not the only party keeping that hourglass.
 *
 * One limit stated plainly: nothing here bounds how long a completion may stream, so past roughly
 * fifteen minutes of generation it is this window, not the receipt one, that refuses the response.
 * A deployment that streams longer has to widen this in its clients' policies, and can.
 */
export const DEFAULT_MAX_EVIDENCE_AGE_SECONDS = 900;

/**
 * Client-side pinning policy. `strict` verification requires one: it pins the
 * signing keys, measurements, issuers and instances the client is willing to
 * accept, so a compromised or repointed gateway cannot swap any of them.
 *
 * It is also where the two clocks are set, and both of them run unless this object says
 * otherwise: strict verification is the path that has a policy, so the defaults above are the
 * defaults for a caller who configures nothing.
 *
 * The third time rule here runs the other way round. `maxTimeUncertaintySeconds` bounds how far the
 * source behind a stamp may be from real time, it has no default at all, and it refuses only when a
 * caller writes the demand: a bound nobody asked for is not a verdict anybody should reach.
 */
export interface AshaveriPolicy {
  readonly issuers?: readonly string[];
  readonly instances?: readonly string[];
  /** Ed25519 public keys by kid (hex). */
  readonly keys?: Readonly<Record<string, string>>;
  /**
   * The public keys, by kid (hex), this client designates to authenticate the deployment manifest
   * itself, held apart from `keys` on purpose.
   *
   * A manifest decides which keys sign receipts, so a key that is trusted for receipts cannot also be
   * the proof that the document naming them is the deployment's own: one compromised signing key would
   * rewrite the rotation history that was supposed to retire it. Separating the two maps is what makes
   * a wrapper verified under a receipt key a refusal rather than a pass, and it is why this field names
   * a role rather than a second spelling of the same set.
   *
   * Naming none of these is not a weaker posture, it is a different question: the client checks no
   * manifest signature and reports the manifest as unauthenticated, which is what a deployment that was
   * never handed a manifest key deserves. Naming at least one makes an unauthenticated manifest a
   * refusal, because a caller who designated a signing identity for this document and was handed
   * another one has been shown a deployment that is not the one it pinned.
   *
   * This field lives on the policy object and not in the policy file format, which refuses a document
   * naming it as an unknown key: see the note by `PIN_FIELDS` in `policy-file.ts` for why the digest
   * question is a decision to make in the open rather than a side effect of this field arriving.
   */
  readonly manifestKeys?: Readonly<Record<string, string>>;
  /** Allowed measurements (hex), keyed by environment kind. */
  readonly measurements?: Readonly<Record<string, readonly string[]>>;
  /**
   * The client's own bound on how far a receipt's `iat` may sit from its clock. A number here wins
   * over `DEFAULT_MAX_RECEIPT_AGE_SECONDS`, in both directions: 60 refuses more than the default,
   * 1200 refuses less.
   *
   * Omitting this and setting `Number.POSITIVE_INFINITY` are not the same decision, and only one
   * of them is a claim. An absent field means nobody thought about the clock, so the default
   * guards it. Infinity means "I have thought about this, and the clock must not vote": it is what
   * a caller verifying an archived receipt writes, deliberately, because the alternative is a
   * number that silently accepts the archive too.
   *
   * That off switch is this object's, and it is read by whatever verifier the caller hands it to. A
   * version 1 policy document spells a window as a whole number of seconds or as `null`, and `null`
   * loads back as the absent field, which is the default guarding the clock; `policyFileFromPolicy`
   * refuses a non-finite window rather than writing one out as `null`, so a policy published as a
   * document names a number or names none, and a policy that runs no clock stays in the process that
   * verifies it.
   */
  readonly maxReceiptAgeSeconds?: number;
  /**
   * The client's own bound on how far a receipt's `att.ts` may sit from its clock, with the same
   * two readings as `maxReceiptAgeSeconds`: a number wins over `DEFAULT_MAX_EVIDENCE_AGE_SECONDS`,
   * and `Number.POSITIVE_INFINITY` is the deliberate off switch rather than the absence of one.
   * The document route has the same rule for this window as for that one, and the same refusal.
   */
  readonly maxEvidenceAgeSeconds?: number;
  /**
   * How far the source a stamp was read from may stand from the instant it names, demanded of the
   * deployment rather than measured by the client. A reviewer's demand turned into a number: it bounds
   * how far a receipt's `iat` may be from the instant it states, which is the one time question a
   * receipt's own bytes cannot answer.
   *
   * This is not a window and it has no default beside it, on purpose. The two numbers above close a
   * span between a signed instant and this clock, and a caller that named none still gets the shipped
   * allowance. This one asks how good the signed instant itself was, and a default would answer that
   * question for every deployment that has never been asked it: any number here refuses
   * `HOST_CLOCK_SOURCE`, which is what a gateway that wired no measured source stamps with, so a
   * shipped default would turn an unasked question into a verdict and move it. An absent field demands
   * nothing, which is what keeps a policy written before this field existed reading the same document
   * the same way, and `0` is a demand rather than a weaker one: only a source that declares its
   * readings exact answers it.
   *
   * The bound is checked against what the source declares about itself, not against what this clock
   * says the stamp was off by, so the number is the deployment's statement and the demand is the
   * client's. Read it through `assertStampSourceWithinPolicy`, which is the one place the comparison
   * lives.
   *
   * This field defines no sentinel, where the two windows above make `Number.POSITIVE_INFINITY` one. A
   * demand of `Number.POSITIVE_INFINITY` bounds nothing and a demand of `Number.NaN` bounds nothing
   * too, since no declared number is ever above infinity and every comparison against a not-a-number is
   * false, so a policy object carrying either accepts every source it is handed. Neither spelling
   * survives the way out into a document: `policyFileFromPolicy` refuses both rather than let a demand
   * an operator wrote arrive as the absence of one.
   */
  readonly maxTimeUncertaintySeconds?: number;
  /**
   * How many of a receipt's anchor slots this verifier requires to state that their material was taken
   * in and is held, demanded of the deployment rather than measured by the client.
   *
   * This is the presence half of what an anchor can be weighed for, and it is a demand about the anchor:
   * nothing here is a span, a clock or an instant, and the number counts slots. A receipt's anchor states
   * two of them, the signed collateral the evidence was appraised against and the validity context it was
   * appraised in, and each states one of three things about itself: that its bytes were taken in and are
   * held, that its material was absent where it should have come from, or that this deployment never took
   * it in. The two absences are not nothing: they are the deployment's own account of a gap, and an anchor
   * that carries a gap in a slot the verifier needed is not an anchor that verifier can weigh.
   *
   * The demand is a count and not a switch, because the two slots answer different questions and a
   * deployment can genuinely fill one. `2` asks for the pair, which is the posture that treats an anchor
   * with a hole in it as no anchor; `1` asks for at least one half and accepts the other's stated absence,
   * which is the reading for a verifier that weighs what it can reach and reports the rest. Both are
   * sentences an operator can mean, and neither is a weaker form of the other.
   *
   * Naming nothing asks nothing: a policy that leaves this field out puts no document at a disadvantage it
   * was not already in, which is what keeps every verdict taken under a policy written before this field
   * existed the verdict it was. `0` is not that absence spelled another way: a demand of no slots is a
   * demand every artifact meets, which is a silence written as a decision, so the loader refuses it and
   * points at leaving the field out. A number above the slots an anchor has is refused on the same ground
   * from the other side, and the ceiling is `MAX_ANCHOR_SLOTS_DEMANDABLE` beside this declaration.
   *
   * One state this demand does not reach, stated because it looks like a hole from here and is not: whether a
   * slot stating `held` still resolves. A digest of material nobody retained weighs nothing, and answering that
   * takes the availability of the material the reader holds, which is a question this field deliberately leaves
   * open and `minAnchorSlotsWeighed` beside it asks. Every document a reader of this format opens
   * states an anchor with both of its halves, since the format declares one payload version and the `cva` row of
   * `docs/receipt-spec.md` section 3 requires it, so a demand that is stated always finds two slots to weigh.
   */
  readonly minAnchorSlotsHeld?: number;
  /**
   * How many of a receipt's anchor slots this verifier requires the reader to have reached, and to have found
   * standing as their own signed statement at the instant that receipt states.
   *
   * This is the second thing an anchor can be weighed for, and it is a different question from the count above
   * rather than a stronger form of it. That count asks what the artifact stated about issuance, which is a fact
   * inside the bytes and is answered by reading them. This one asks what a reader can still do with the material
   * those bytes digest, which no member of the receipt states and cannot: a payload names a digest and no bytes, and
   * whether the bytes behind that digest are reachable depends on the container the reader holds. A slot stating
   * `held` whose material resolves to nothing is a claim that looks like proof, which is why a verifier that wants
   * proof asks this of it and not only the count.
   *
   * Three facts make a slot weighed here, and they are the three a reader can establish without trusting anything
   * this estate said. The digest the slot states resolves to bytes inside the scope the reader already holds,
   * addressed by that digest rather than by a naming convention someone has to keep honouring. Those bytes carry a
   * signature that stands under the roots this reader names, so the statement is the vendor's own and not a body of
   * data shaped like one. And the window that signature states covers the receipt's own `iat`, which is the instant
   * the appraisal ran on this material, so the statement reaches the moment the record claims. The comparison is the
   * format's own arithmetic: a window covers an instant from its first second up to but not including its last.
   *
   * A demand of `1` is not a weaker version of a demand of `2`; it is a different sentence, for a verifier that will
   * weigh what it can reach and report the rest. Naming nothing asks nothing, which is what keeps every verdict taken
   * under a policy that never named this field the verdict it was, at the digest as at the answer. `0` is refused at
   * the loader as the count above is, because a demand every artifact meets is a silence written as a decision, and
   * the ceiling is the same `MAX_ANCHOR_SLOTS_DEMANDABLE` because it is the same two slots being counted.
   *
   * Two states this demand does not reach, stated because both read like holes from here. Whether the vendor still
   * stands behind the level the material states is its own question, answered by the collateral package under
   * `COLLATERAL_REVOKED_BY_VENDOR`; a weighing that reports a withdrawn level is reported here as withdrawn, in its own
   * words, and never as a window that missed. And a statement that the material was reachable at some past sealing
   * instant is not this demand either: reach is weighed at the reader, over the containers the reader holds, and a
   * container states no instant at which anyone watched an origin answer.
   *
   * What is handed to this demand decides how honest it can be. The readings arrive as `AnchorSlotReading` values,
   * produced by whoever holds the material out of the container carrying it, and a held slot with no reading beside
   * it is refused rather than passed: a verifier that was handed nothing reached nothing, and treating an unread
   * anchor as a compliant one is how an absence of evidence becomes a pass.
   */
  readonly minAnchorSlotsWeighed?: number;
  /**
   * The shape each text member a deployment authors has to match, keyed by the payload's own member names. Every
   * value is a regular expression source read without flags, matched against the whole value, and the source is
   * compiled where the policy is made rather than where a document is judged.
   *
   * This is the reader's half of a rule the writer already keeps. `packages/receipt/src/receipt.ts` refuses to sign
   * any of these members carrying a character that could end or reorder the line it is later printed on, and a
   * producer's refusal is the deployment's own standard: what the deployment decided not to sign says nothing about
   * what a particular auditor will accept from it. A document that clears the writer can still arrive with a model id
   * out of a routing table, a URL on an origin nobody pinned or a collector's sentence where an operator expected a
   * label, and only a verifier can decide whether that is acceptable. So the verifier says so here, and an auditor
   * runs a rule over their own receipts instead of reading a promise in a document.
   *
   * Naming nothing asks nothing, as the three fields above do: a key left out demands nothing of that member, an empty
   * map demands nothing of any, and no verdict taken under a policy that named no shape moves. A demand that a member
   * hold nothing at all is written the same way, by leaving that key out; a shape of `^$` is a demand no artifact meets
   * and the loader refuses it beside a source that will not compile, because both are a silence spelled as a decision.
   *
   * `v` is deliberately not one of the positions. It is the version this reader was built to parse rather than a
   * statement the deployment authored, and a shape refusing it would answer with a code about somebody's text.
   */
  readonly attestedTextShapes?: Readonly<Partial<Record<AttestedTextMember, string>>>;
  /**
   * Vendor roots hardware evidence must chain to. Omit to accept the roots
   * bundled with `@ashaveri/attest-core`; set it to pin your own.
   */
  readonly trustAnchors?: EvidenceTrustAnchors;
}

/**
 * Where a stamp's instant came from, as the party that read it states it: a name, and how far its
 * readings can stand from the instant they name.
 *
 * The pair is not invented here. `gateway/src/store.ts` states exactly these two fields as
 * `StampDeclaration`, on the store through `timeSource()` and beside every record a range walk hands
 * back, because a stamp without its source is a number nobody can weigh, and the receipt's own bytes
 * carry neither: the bound belongs to the deployment's declaration and not to the signed payload. A
 * caller hands over what it was handed, and this is the shape both of those statements arrive in.
 *
 * `uncertaintySeconds` of `null` means nobody measured, which is a different sentence from a bound of
 * zero and is refused by a policy that demands one.
 */
export interface StampSourceDeclaration {
  readonly name: string;
  readonly uncertaintySeconds: number | null;
}

/**
 * Refuse a stamp whose source stands further from real time than the policy demands.
 *
 * Three refusals below, and a state that reaches none of them: a policy naming no bound demands
 * nothing, so every stamp passes and no verdict taken under such a policy moves, which is what
 * `test/policy-replay.test.ts` holds by pinning the digests and verdicts such a policy had before this
 * demand could be stated.
 *
 * The three are a source declaring more than the demand, a source declaring that nobody measured one,
 * which is refused rather than read as a bound of zero, and a source declaring something that is not a
 * count of seconds at all. Every message names the source and the bound the policy demands, and the two
 * refusals that have a number the source declared state it beside that bound. Why the unmeasured case
 * is refused, and what an operator does about any of the three, is argued once at the row this code has
 * in `docs/error-codes.md`, and the messages below are the sentences its tests hold.
 */
export function assertStampSourceWithinPolicy(
  policy: AshaveriPolicy | undefined,
  source: StampSourceDeclaration,
): void {
  const demanded = policy?.maxTimeUncertaintySeconds;
  if (demanded === undefined) return;
  const declared = source.uncertaintySeconds;
  if (declared === null) {
    throw new SdkError(
      'STAMP_SOURCE_TOO_UNCERTAIN',
      `a stamp read from '${source.name}' is refused: that source declares no measured uncertainty at all, and an ` +
        `unmeasured claim is not a bound of zero, so nothing here shows it inside the ${demanded} seconds this policy ` +
        `demands a stamp's source be bounded at. Either the deployment wires a source that carries a measurement, or ` +
        `the policy says in writing that it demands nothing`,
    );
  }
  if (!Number.isFinite(declared) || declared < 0) {
    throw new SdkError(
      'STAMP_SOURCE_TOO_UNCERTAIN',
      `a stamp read from '${source.name}' is refused: the source declares ${String(declared)} seconds of ` +
        `uncertainty, which is no number of seconds a reading can be away by, so it answers the ${demanded} seconds ` +
        `this policy demands a stamp's source be bounded at with nothing that can be weighed against it`,
    );
  }
  if (declared > demanded) {
    throw new SdkError(
      'STAMP_SOURCE_TOO_UNCERTAIN',
      `a stamp read from '${source.name}' is refused: its readings can stand ${declared} seconds away from the ` +
        `instants they name, which is wider than the ${demanded} seconds this policy demands a stamp's source be ` +
        `bounded at. Either the deployment wires a better-bounded source, or the policy lowers the demand to the ` +
        `number that source actually carries`,
    );
  }
}

/**
 * The largest demand either anchor count can state and a document can still answer: the number of slots
 * one anchor holds. `minAnchorSlotsHeld` counts the slots stating they were taken in, and
 * `minAnchorSlotsWeighed` counts how many of those a reader reached and found standing; both are bounded
 * here because both count the same two slots.
 *
 * The format owns that number, as the member list `COLLATERAL_ANCHOR_MEMBERS` declares in
 * `packages/receipt/src/receipt.ts`, and this is a restatement of it in the same way
 * `COLLATERAL_PRESENCES` restates the capture record's presence labels across the same package boundary.
 * `test/anchor-slot-demand.test.ts` reads the list out of the format's own source and holds the two
 * together, so a third slot widens this ceiling by a failing test and not by a number nobody moved.
 *
 * A demand above it is refused at the loader, because no artifact can ever meet it: the posture it states
 * is unwritable rather than strict, and a policy that cannot be satisfied is a policy that has already
 * refused everything.
 */
export const MAX_ANCHOR_SLOTS_DEMANDABLE = 2;

/**
 * Refuse an anchor whose slots state less than the policy demands, and say which state did it.
 *
 * One refusal, in one place, reached only by a policy that named a demand: `verifyCompletionReceipt`
 * calls this over the anchor every sealed receipt states, which is where a deployment hands a receipt over
 * and where the client's own standards are applied, and not the format reader, which weighs nothing a
 * policy asked for and has to keep working for an auditor holding no policy.
 *
 * The count is what decides, and the slots are what the sentence names. A demand of `n` is met by an
 * anchor with `n` slots stating `held`, and the two absences answer alike because neither is material a
 * verifier can weigh: one says the world had nothing, the other says this deployment never took what was
 * there. They are one code and not two because what a caller does with either is the same act, refuse
 * this receipt and say so, and which of the two it was is the part of the sentence that tells an operator
 * where the gap sits: `absent-at-source` points at a source that published nothing, `not-taken-in` points
 * at a collector that looked away. The message names the slot, its state, the reason the slot itself
 * states, the count that answered and the count demanded, so the finding is readable off one line.
 *
 * Two states reach nothing here, and each is a decision rather than an omission. A slot stating `held`
 * passes this test and only this one: whether its material still resolves is a second question, answered
 * by an availability interval a verifier reaches outside the artifact, and a held digest that turns out to
 * name nothing retained is not a hole in this check. And a policy that named no demand returns before any of
 * it, which is the property `test/anchor-slot-demand.test.ts` pins as numbers: no verdict taken under a policy
 * that asked nothing of an anchor moves. Every document this reader opens states an anchor with both of its
 * halves, so a stated demand always has two slots to weigh.
 */
export function assertAnchorHeldUnderPolicy(
  policy: AshaveriPolicy | undefined,
  anchor: CollateralValidityAnchor,
): void {
  const demanded = policy?.minAnchorSlotsHeld;
  if (demanded === undefined) return;
  const slots: readonly (readonly [name: string, slot: CollateralSlot])[] = [
    ['collateral', anchor.collateral],
    ['validity', anchor.validity],
  ];
  const held = slots.filter(([, slot]) => slot.presence === 'held').length;
  if (held >= demanded) return;
  const gaps = slots
    .filter((entry): entry is readonly [string, CollateralAbsent] => entry[1].presence !== 'held')
    .map(([name, slot]) =>
      slot.presence === 'absent-at-source'
        ? `the ${name} slot states its material was absent at the source it should have come from (absent-at-source), saying: ${slot.reason}`
        : `the ${name} slot states that this deployment never took its material in (not-taken-in), saying: ${slot.reason}`,
    )
    .join(' and ');
  throw new SdkError(
    'ANCHOR_SLOT_NOT_HELD',
    `an anchor with ${String(held)} of ${String(slots.length)} slots held is refused: this policy demands ${String(demanded)}, and ${gaps}. ` +
      'Neither absence is an anchor a verifier can weigh, so either the deployment issues from a collector that took the appraisal context in, ' +
      'or this policy lowers its demand to the count these artifacts carry or names no demand at all',
  );
}

/**
 * Which of an anchor's two slots a reading is about, spelled as the container carrying the material spells it:
 * `col` for the collateral an appraisal ran against, `val` for the validity context it ran in.
 *
 * The receipt's own members are `collateral` and `validity`, and the pack's carried lookup answers with these two
 * labels, so this is the seam's spelling rather than a third name for the same half. A reading about the wrong slot
 * is not a reading about the anchor, which is why the label is a field of it and not an assumption about order.
 */
export type AnchorSlotLabel = 'col' | 'val';

/**
 * What one anchor slot's material amounts to where the reader reached it, as the reader that reached it states it.
 *
 * This is the shape the demand below weighs, and it is handed rather than looked up on purpose: the SDK verifies a
 * document a caller handed it, and the material a `held` digest names lives in whatever container that caller holds,
 * which the format package reads through `resolveAttached` and the collateral package appraises through
 * `appraiseCarriedCollateral`. Neither of those two answers is a number this package can reach without the container,
 * so the reader hands what it established and this package asks whether it is enough.
 *
 * `reached` says the digest resolved to bytes inside the scope the reader holds, and the digest it resolved *to* is
 * restated because a lookup that returned other bytes is a finding about the container rather than an anchor weighed.
 * `signature` is the vendor's own statement as the reader established it: `established` under the roots that reader
 * named, `withdrawn` where those roots stand behind the document and the document withdraws the level it states, and
 * `not-established` where nothing reached was a signature this reader can stand behind, which is the honest spelling
 * of an unreadable envelope, an unknown vendor status and a chain that reaches no named root alike. `window` is the
 * validity window that signed statement states for itself, or `null` where none was readable.
 */
export interface AnchorSlotReading {
  readonly slot: AnchorSlotLabel;
  /** The digest the slot states, lowercase hex, which is the only name the anchor gives this material. */
  readonly digest: string;
  readonly reached: boolean;
  /** The digest the reached bytes actually hash to, when `reached` is true. */
  readonly resolvedDigest?: string;
  readonly signature: 'established' | 'not-established' | 'withdrawn';
  readonly window: { readonly from: number; readonly until: number } | null;
}

/** Whether a reading names this digest, whether it reached it, and whether the reached bytes are that digest. */
function reachedOf(reading: AnchorSlotReading | undefined): 'no-reading' | 'not-reached' | 'wrong-bytes' | 'reached' {
  if (reading === undefined) return 'no-reading';
  if (!reading.reached) return 'not-reached';
  if (reading.resolvedDigest !== undefined && reading.resolvedDigest !== reading.digest) return 'wrong-bytes';
  return 'reached';
}

/** Whether the reading's own signed window states the instant, in the arithmetic the format uses. */
function coversInstant(window: { readonly from: number; readonly until: number } | null, at: number): boolean {
  return window !== null && at >= window.from && at < window.until;
}

/**
 * Refuse an anchor whose material the reader reached fewer slots of than the policy demands, and name the reading
 * that failed rather than a single word for all of them.
 *
 * Two refusals, and they are two because the gaps are two. `ANCHOR_MATERIAL_UNREACHED` is the material: no reading
 * at all for a digest the anchor states, a reading that reached nothing, or bytes that do not hash to the digest
 * asked for. `ANCHOR_MATERIAL_NOT_STANDING` is the statement behind the material: bytes reached that establish no
 * signature under these roots, that state no window anyone can weigh, that state a window not reaching the instant
 * asked, or that the vendor itself withdraws. A verifier told only that "the anchor failed" cannot act on either, and
 * a material retired on schedule is not a signature that failed, so the codes stay apart and each message names which
 * slot, which digest, and which reading inside the code it reached.
 *
 * The ordering is the order of dependence, not of severity: a slot with nothing reached has no signature to weigh and
 * no window to compare, so the unreached refusal is given whenever any demanded slot falls that way, even when
 * another slot fell the other way. The count that answered is stated either way, beside the count demanded.
 *
 * One state is refused under a code that already exists rather than a new one: an anchor stating fewer `held` slots
 * than this demand names cannot have that many weighed at all, and the gap is the presence the artifact stated, which
 * is `ANCHOR_SLOT_NOT_HELD`'s own question. One state reaches nothing: a policy naming no demand returns before any of
 * it, which is what keeps every verdict taken under such a policy the verdict it was, and what
 * `test/anchor-weighing.test.ts` pins beside digests.
 *
 * Whether the appraisal that produced a reading watched an origin answer is not one of these questions and cannot be,
 * on the path that has material to weigh: a container states no observation instant, so material read out of one is
 * never a current answer and never arrives with the window refusal beside it. That is why this weighs the window the
 * material states for itself against the instant the record claims, rather than the state the appraisal settled on.
 */
export function assertAnchorWeighedUnderPolicy(
  policy: AshaveriPolicy | undefined,
  anchor: CollateralValidityAnchor,
  readings: readonly AnchorSlotReading[],
  atSeconds: number,
): void {
  const demanded = policy?.minAnchorSlotsWeighed;
  if (demanded === undefined) return;
  const slots: readonly (readonly [name: string, label: AnchorSlotLabel, slot: CollateralSlot])[] = [
    ['collateral', 'col', anchor.collateral],
    ['validity', 'val', anchor.validity],
  ];
  const held = slots
    .filter((entry): entry is readonly [string, AnchorSlotLabel, CollateralHeld] => entry[2].presence === 'held')
    .map(([name, label, slot]) => ({ name, label, digest: toHex(slot.sha256) }));
  if (held.length < demanded) {
    throw new SdkError(
      'ANCHOR_SLOT_NOT_HELD',
      `an anchor stating ${String(held.length)} of ${String(slots.length)} slots held is refused: this policy demands ${String(demanded)} ` +
        'weighed, and a slot stating an absence names no material to weigh, so no reader could ever answer this demand out of these bytes. ' +
        'Either the deployment issues from a collector that took the appraisal context in, or this policy lowers the count it demands to the ' +
        'slots these artifacts state held, or it names no demand at all',
    );
  }
  const read = (label: AnchorSlotLabel, digest: string): AnchorSlotReading | undefined =>
    readings.find((one) => one.slot === label && one.digest === digest);
  const states = held.map((one) => ({ ...one, reading: read(one.label, one.digest), reached: reachedOf(read(one.label, one.digest)) }));
  const stood = (one: (typeof states)[number]): boolean =>
    one.reached === 'reached' &&
    one.reading !== undefined &&
    one.reading.signature === 'established' &&
    coversInstant(one.reading.window, atSeconds);
  const weighed = states.filter(stood).length;
  if (weighed >= demanded) return;

  const unreached = states.filter((one) => one.reached !== 'reached');
  if (unreached.length > 0) {
    const gaps = unreached
      .map((one) =>
        one.reached === 'no-reading'
          ? `the ${one.name} slot states the digest ${one.digest} and this run was handed no reading for it, so nothing in scope was reached at all`
          : one.reached === 'not-reached'
            ? `the ${one.name} slot states the digest ${one.digest} and the reading handed for it reached no bytes`
            : `the ${one.name} slot states the digest ${one.digest} and the bytes reached for it hash to ${String(one.reading?.resolvedDigest)}, which is a different object than the one the anchor names`,
      )
      .join(' and ');
    throw new SdkError(
      'ANCHOR_MATERIAL_UNREACHED',
      `an anchor with ${String(weighed)} of ${String(held.length)} held slots weighed is refused: this policy demands ${String(demanded)}, and ${gaps}. ` +
        'A held digest nobody can reach is a claim that looks like proof rather than a piece of it, so either the reader holds the container carrying ' +
        'these bytes, or this policy lowers its demand to what it can reach, or it names no demand at all',
    );
  }

  const standing = states
    .filter((one) => !stood(one))
    .map((one) => {
      const reading = one.reading as AnchorSlotReading;
      if (reading.signature === 'not-established') {
        return `the ${one.name} slot's material (${one.digest}) states no signature the roots this run stands behind establish, which covers a document this reader cannot decode as well as one whose chain reaches no named root`;
      }
      if (reading.signature === 'withdrawn') {
        return `the ${one.name} slot's material (${one.digest}) is the vendor's own signed statement and that statement withdraws the level it states, which no window reading covers and no later document un-says`;
      }
      const window = reading.window;
      if (window === null) {
        return `the ${one.name} slot's material (${one.digest}) is signed and reached but states no validity window at all, so nothing here can be weighed against the instant ${String(atSeconds)}`;
      }
      return `the ${one.name} slot's material (${one.digest}) stands from ${String(window.from)} up to but not including ${String(window.until)} and the instant asked is ${String(atSeconds)}, which is outside it`;
    })
    .join(' and ');
  throw new SdkError(
    'ANCHOR_MATERIAL_NOT_STANDING',
    `an anchor with ${String(weighed)} of ${String(held.length)} held slots weighed is refused: this policy demands ${String(demanded)}, and ${standing}. ` +
      'Each of these is reached material that does not answer for the moment the record claims, so either the reader appraises it against the roots and the ' +
      'level it is actually about, or the deployment seals the collateral whose window reaches its own stamps, or this policy lowers its demand to what stands ' +
      'here or names no demand at all',
  );
}

/**
 * The text members a deployment authors inside a receipt, named as the payload names them.
 *
 * This is the class the writer already refuses to sign: every `tstr` a payload document carries, read off
 * `packages/receipt/receipt.cddl`, minus `v`, which is the version this reader was built to parse rather than text a
 * deployment authored. `test/anchor-weighing.test.ts` derives the list from that file's own declarations and
 * holds the two together, so a ninth text member joins this union by a failing test rather than by a rule an auditor
 * was never handed.
 */
export type AttestedTextMember =
  | 'iss'
  | 'ins'
  | 'mdl'
  | 'att.url'
  | 'mk.sch'
  | 'sd.name'
  | 'cva.col.r'
  | 'cva.val.r';

/** Every position a policy can name a shape for, in the order the payload declares them. */
export const ATTESTED_TEXT_MEMBERS: readonly AttestedTextMember[] = [
  'iss',
  'ins',
  'mdl',
  'att.url',
  'mk.sch',
  'sd.name',
  'cva.col.r',
  'cva.val.r',
];

/**
 * One shape as this package reads it: compiled, whole-value anchored, and refused before it reaches a verdict.
 *
 * A demand an operator wrote that does not compile is not a demand that matches nothing, which is what reading a bad
 * source as a literal would amount to, and a source that matches the empty string demands a member no receipt can hold
 * empty. Both are refused here, and the loader for a policy document calls this on the way in, so a policy built in
 * code and a policy read from a file are held to one rule by one implementation.
 */
export function attestedTextShape(source: string): RegExp {
  let bare: RegExp;
  try {
    bare = new RegExp(source, 'u');
  } catch {
    throw new SdkError(
      'POLICY_FILE_INVALID',
      `'attestedTextShapes' states ${JSON.stringify(source)}, which compiles to no regular expression at all: a shape ` +
        'a verifier cannot run asks nothing of the member it is named for, and this loader refuses it rather than read it ' +
        'as a pattern that matches nothing',
    );
  }
  // Wrapped rather than trusted to spell its own anchors, so `dpl-.*` and `^dpl-.*$` are one demand. An operator who
  // writes the anchors keeps them: an assertion inside a group that is already pinned at both ends says the same thing
  // twice and changes nothing about what the shape matches.
  const whole = new RegExp(`^(?:${bare.source})$`, 'u');
  if (whole.test('')) {
    throw new SdkError(
      'POLICY_FILE_INVALID',
      `'attestedTextShapes' states ${JSON.stringify(source)}, which the empty text matches: a shape every value meets ` +
        'demands nothing of the member it is named for, and a rule that asks nothing is written by leaving that member out',
    );
  }
  return whole;
}

/**
 * Refuse a receipt whose deployment-authored text is outside a shape the policy names for it.
 *
 * The positions are the payload's own, and a position this argument states as `null` carries no text at all, which is
 * the anchor's held arm: a shape named for `cva.col.r` is a rule about the sentence a collector writes when it has no
 * bytes, and a slot stating it holds the bytes states no sentence to run the rule over. Such a position is skipped
 * rather than passed with a note, because the demand was about a text that is not there.
 *
 * The refusal names the position, the shape it did not match and the length of what was found, and never prints the
 * value. That is the one place this differs from the refusals above, and it is on purpose: the class this rule runs
 * over is text a foreign signer could put in a receipt to forge the line a report prints beside its label, and a
 * refusal that pasted it in would carry the forgery into the tool that reports it. The reader who wants the value has
 * the document.
 */
export function assertAttestedTextShapes(
  policy: AshaveriPolicy | undefined,
  text: Readonly<Partial<Record<AttestedTextMember, string | null>>>,
): void {
  const shapes = policy?.attestedTextShapes;
  if (shapes === undefined) return;
  for (const member of ATTESTED_TEXT_MEMBERS) {
    const source = shapes[member];
    if (source === undefined) continue;
    const value = text[member];
    if (value === null || value === undefined) continue;
    if (!attestedTextShape(source).test(value)) {
      throw new SdkError(
        'ATTESTED_TEXT_OUTSIDE_SHAPE',
        `the receipt's ${member} is ${String(value.length)} characters and matches no shape this policy names for it: ` +
          `the demand is ${JSON.stringify(source)}, and what the document states is not printed here because this class of ` +
          'text is the class that forges a printed line, so the reader who wants it has the document. Either the deployment ' +
          'authors that member inside the shape, or this policy widens the shape to the text it actually accepts, or it names ' +
          'no shape for that member',
      );
    }
  }
}

/**
 * The pins a deployment publishes, read out of its manifest. What these are worth depends on whether
 * the manifest arrived sealed and authenticated, which is a fact about the transport rather than about
 * this function: a manifest verified under a key this client designated out of band is the deployment's
 * own statement, and one it could not verify is trust-on-first-use, because the document came from the
 * party being verified. Strict mode checks the receipt against the pins either way, so an unverified
 * manifest can fail a check and cannot open one.
 *
 * `manifestKeys` is deliberately absent from the result. The manifest names no key that signs itself,
 * and a builder that filled that field from the document it was handed would manufacture the one
 * circularity the field exists to close: the signer would be designated by the signed. Whatever reaches
 * that map has to arrive from somewhere the deployment does not control.
 *
 * Neither window is set here, and that is the point. The manifest comes from the party being
 * verified, so it is not where a freshness rule may be loosened: what a manifest-derived policy
 * checks the clock against is `DEFAULT_MAX_RECEIPT_AGE_SECONDS` and
 * `DEFAULT_MAX_EVIDENCE_AGE_SECONDS`, which are in this package's code and on no wire. For the same
 * reason neither a bound on a stamp's source nor a demand about an anchor is asked for here: a deployment
 * cannot choose what a client asks of it, so a manifest-derived policy demands nothing and refuses nothing
 * on either leg.
 */
export function policyFromManifest(manifest: DeploymentManifest): AshaveriPolicy {
  const keys: Record<string, string> = {};
  for (const key of manifest.keys) {
    keys[key.kid] = key.publicKey;
  }
  return {
    issuers: [manifest.iss],
    instances: [manifest.ins],
    keys,
    measurements: { [manifest.meas.tee]: [manifest.meas.m] },
  };
}

export function policyKeyByKid(policy: AshaveriPolicy, kid: Uint8Array): Uint8Array | undefined {
  const encoded = policy.keys?.[toHex(kid)];
  return encoded === undefined ? undefined : fromBase64Url(encoded);
}
