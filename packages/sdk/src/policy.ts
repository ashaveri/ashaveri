import { toHex } from './b64.js';
import { fromBase64Url } from './b64.js';
import { SdkError } from './errors.js';
import type { CollateralAbsent, CollateralSlot, CollateralValidityAnchor } from '@ashaveri/receipt';
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
   */
  readonly maxReceiptAgeSeconds?: number;
  /**
   * The client's own bound on how far a receipt's `att.ts` may sit from its clock, with the same
   * two readings as `maxReceiptAgeSeconds`: a number wins over `DEFAULT_MAX_EVIDENCE_AGE_SECONDS`,
   * and `Number.POSITIVE_INFINITY` is the deliberate off switch rather than the absence of one.
   */
  readonly maxEvidenceAgeSeconds?: number;
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
   * Two states this demand does not reach, stated because both look like holes from here and neither is.
   * The first is a document of a version that names no anchor at all: it makes no statement about presence
   * either way, and refusing it would be a rule about version numbers rather than about an anchor, which is
   * what `docs/receipt-spec.md` section 3's rows already settle. The second is whether a slot stating
   * `held` still resolves: a digest of material nobody retained weighs nothing, and answering that takes the
   * availability of the material the reader holds, which is a question this field deliberately leaves open
   * and its documentation says so rather than half-answers it.
   */
  readonly minAnchorSlotsHeld?: number;
  /**
   * Vendor roots hardware evidence must chain to. Omit to accept the roots
   * bundled with `@ashaveri/attest-core`; set it to pin your own.
   */
  readonly trustAnchors?: EvidenceTrustAnchors;
}

/**
 * The largest demand `minAnchorSlotsHeld` can state and a document can still answer: the number of slots
 * one anchor holds.
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
 * calls this over the anchor a `v: 3` payload carries, which is where a deployment hands a receipt over
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
 * Three states reach nothing here, and each is a decision rather than an omission. A slot stating `held`
 * passes this test and only this one: whether its material still resolves is a second question, answered
 * by an availability interval a verifier reaches outside the artifact, and a held digest that turns out to
 * name nothing retained is not a hole in this check. A document of a version that names no anchor makes no
 * statement about presence at all, so there is nothing here to weigh, and refusing it would be a rule about
 * version numbers. And a policy that named no demand returns before any of it, which is the property
 * `test/anchor-slot-demand.test.ts` pins as numbers: no verdict taken under a policy that asked nothing of
 * an anchor moves.
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
 * reason no demand about an anchor is asked for here either: a deployment cannot choose what a client
 * asks of it, so a manifest-derived policy demands nothing and refuses nothing on that leg.
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
