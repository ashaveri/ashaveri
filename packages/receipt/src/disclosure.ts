/**
 * Two disclosures a receipt states about itself, in the members `v: 3` carries them in.
 *
 * Both answer a question a reader cannot otherwise ask of a signed artifact. `StampDisclosure` names
 * where an issuance instant came from and how far that source admits it can be from an instant, so a
 * reviewer weighing a verdict knows what the timestamp is worth instead of assuming it is worth a
 * second. `CollateralValidityAnchor` states what became of the collateral and the validity context the
 * appraisal of the evidence ran on, so a digest of a document nobody retained cannot be read as a
 * verdict that held up.
 *
 * Both are read and written by the format: `v: 3` names `sd` and `cva` as required members, the CDDL
 * rule, its JSON twin and the projection in `json.ts` all declare the same two shapes, and the parser
 * refuses a document that leaves either out or holds it in another shape. What is not the case sits on
 * the producing side: no receipt published as a vector carries either member, because every receipt
 * under `packages/fixtures/data` is a `v: 1` or `v: 2` document, so the only `v: 3` bytes this tree
 * reads are ones a test handed the codec with both members spelled out. These are shapes a reader reads
 * and a writer writes today, and not yet a record any published receipt carries. That is also why they
 * are types in this package rather than in the one that reads a receipt: the writer that will fill them
 * in for real is the issuer, and the issuer's codec lives here.
 */

/**
 * Where one stamped instant came from, in the source's own words.
 *
 * The field names are `TimeSource`'s, in `gateway/src/store.ts`, so that an emitter hands its own source's
 * statement over without renaming it: this is the two-field half of that interface, the half that is a
 * claim about the source rather than a way to read one. The instant itself stays where it already is, in
 * `iat`: a disclosure that carried a second copy of it would be two owners of one fact, and only one of
 * them is signed.
 *
 * `uncertaintySeconds` is `null` when nobody measured how far this source can be from the instants it
 * names, which is a different sentence from `0`. Zero is a claim that the source is right; `null` is a
 * statement that nothing here knows whether it is. A policy that demands a bound refuses the second and
 * is not satisfied by it, which is why the absence of a measurement is a value the type can hold rather
 * than an omitted field: `undefined` would be readable as either, and an omitted bound defaults to the
 * reading a reader prefers.
 */
export interface StampDisclosure {
  /** What this process reads, as its owner names it: `host clock` is the shipped answer. */
  readonly name: string;
  /** Seconds a reading may be away from the instant it names, or `null` where nobody measured. */
  readonly uncertaintySeconds: number | null;
}

/**
 * What became of one piece of appraisal context. Three states because two are not enough: a record
 * that says nothing about its collateral cannot be told apart from one whose collateral never existed,
 * and the difference is between a deployment that had nothing to show and a collector that looked away.
 *
 * The three labels are the capture record's `CapturePresence`, in `packages/sdk/src/capture.ts`, restated
 * here rather than imported because the dependency runs the other way: the SDK reads this package, so a
 * type here cannot take one from there. `test/disclosure.test.ts` holds the two spellings to each other,
 * which is the only way a restatement stays one vocabulary and not two that drift.
 */
export const COLLATERAL_PRESENCES = ['held', 'absent-at-source', 'not-taken-in'] as const;

export type CollateralPresence = (typeof COLLATERAL_PRESENCES)[number];

/** The context this anchor holds: the digest of its bytes as they arrived, and only that. */
export interface CollateralHeld {
  readonly presence: 'held';
  /**
   * sha256 of the collateral exactly as it was taken in, in the 32-byte representation the rest of a
   * receipt's digests use. The bytes themselves are not here, which is why no byte count rides along
   * either: a count of bytes this document does not carry is a number nothing can check it against,
   * while a digest is checked against whatever the reader is holding.
   */
  readonly sha256: Uint8Array;
}

/** The context this anchor does not hold, and which of the two reasons it names. */
export interface CollateralAbsent {
  /** `absent-at-source` is a statement about the world; `not-taken-in` is a statement about us. */
  readonly presence: Exclude<CollateralPresence, 'held'>;
  /** Required, in one line of the collector's own words: an absence nobody explained is a hole. */
  readonly reason: string;
}

export type CollateralSlot = CollateralHeld | CollateralAbsent;

/**
 * The context an appraisal was made in, as it was captured.
 *
 * Two slots, because the capture record's own context is the pair and a reader needs both to weigh a
 * verdict: the signed collateral the bytes were appraised against, and the validity context they were
 * appraised in. A deployment can hold one and be missing the other, and that combination is exactly the
 * case an anchor exists to make visible rather than to resolve: collateral with no window around it is
 * not an anchor, and an anchor that defaults a missing half to a pass is a claim of a capability nothing
 * measured.
 *
 * This carries no verdict field, deliberately. Whether the collateral verifies is decided by a reader
 * holding its own pins, and a record that stated the conclusion would turn custody of bytes into
 * verification of them, which is the mistake the capture record exists to make impossible.
 */
export interface CollateralValidityAnchor {
  readonly collateral: CollateralSlot;
  readonly validity: CollateralSlot;
}
