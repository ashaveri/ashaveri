import type { CollateralValidityAnchor, StampDisclosure } from '@ashaveri/receipt';
import { declarationOf, type TimeSource } from './store.js';

/**
 * The two `v: 3` members that state what this issuance knew about itself.
 *
 * `packages/receipt/src/disclosure.ts` publishes the shapes and `docs/receipt-spec.md` section 3
 * publishes which field of a payload holds which half. Filling them in is what lives here, because a
 * converter whose caller holds no input for it is a pass-through nobody can check. Both conversions live
 * in the package that owns the process doing the issuing, and both are answered by a deployment's wiring
 * rather than by a value a caller can pass.
 *
 * Neither answer is softened into something that reads as a pass, which is the whole discipline of these
 * two members. A disclosure for an unmeasured clock says unmeasured; an anchor for material nobody took
 * in says nobody took it in, in the words that name the collector rather than the world.
 */

/**
 * The disclosure of the source `iat` was read from.
 *
 * `sd` names the source of the issuance instant, so this is read from the `TimeSource` the gateway was
 * constructed with, which is the one reading `stamp()` in `server.ts` takes `iat` and every item's `t`
 * from. It is not read from the deployment's `AttestationBundle.stamped`, which is a declaration about a
 * different instant: that bundle's `timestamp` is the moment evidence was collected, it is carried by
 * `att.ts`, and the section that publishes `att` gives it three members and no source, so naming the
 * bundle's source beside `iat` would attribute the issuance stamp to a clock that did not make it.
 *
 * The two can be the same object, and on a deployment that wires one source everywhere they are:
 * `gateway/src/cli.ts` hands the same `TimeSource` to every builder it calls. But they are two fields
 * read at two moments, and nothing here averages them or picks the earlier, because a disclosure that
 * blends two clocks answers for neither.
 *
 * The two reads are `declarationOf`, which is the function the store already states its own source with,
 * so a renamed field has to be renamed once.
 */
export function stampDisclosureOf(source: TimeSource): StampDisclosure {
  return declarationOf(source);
}

/**
 * The anchor of an issuance that took in no appraisal context, which is the only state a gateway that
 * captures no collateral and reads no validity window can put in a payload.
 *
 * The presence is `not-taken-in` in both slots, and that choice is a statement about this collector
 * rather than about the world, which is exactly what the third state exists to keep apart from the
 * second: signed collateral and a validity window are things that exist, and this gateway never puts
 * them in a record. Withholding the version until a collector is wired, or leaving the member out, would
 * return that fact to silence, and the silence is what the member was added to refuse. The reasons say
 * what happened, at the site it happened, so a reader who wants the material knows who to ask and a
 * verifier that refuses this state is refusing a stated gap rather than a malformed document.
 *
 * Each reason is also bounded by what its site can know. `not-taken-in` is the collector's own sentence
 * and `absent-at-source` is the world's, which is the difference the two labels exist to keep readable,
 * so a reason here that stated that no window ever stood open would be reporting an appraisal this
 * process never ran and letting a reader weigh two different absences by one yardstick. The validity
 * reason says that no window was put into the record and that nothing here looked: the rest is the
 * verifier's to find out, from the evidence this document digests and the pins it holds itself.
 *
 * This is the whole of what a gateway that captures nothing can attest, and it stops being true the
 * moment something is wired that can do better: the caller that takes evidence in is the caller that has
 * to answer for what it held.
 */
export function notTakenInAnchor(): CollateralValidityAnchor {
  return {
    collateral: {
      presence: 'not-taken-in',
      reason:
        'this gateway takes no collateral into issuance: the deployment hands back an evidence document, its ' +
        'stamp and a url, and nothing that was chained to it, and no collector in this repository holds the ' +
        'vendor chain an appraisal of that document would run on',
    },
    validity: {
      presence: 'not-taken-in',
      reason:
        'this gateway records no validity context at issuance: nothing in this process appraises the evidence ' +
        'whose digest it signs, so no window was put into this record, and whether one stood open at the ' +
        'instant this receipt was stamped is a fact this gateway never looked at; the appraisal that needs ' +
        'one belongs to a verifier, run afterwards against bytes this document only digests',
    },
  };
}
