/**
 * The provenance vocabulary, and the one reduction over it.
 *
 * A receipt attests one response. A pack and an export qualify the material they carry with where that
 * material came from, in one field of its own and not in a sentence: `live` for material a running
 * deployment produced while answering a real request, `captured` for a vendor-signed document recorded
 * elsewhere and replayed into a locally issued receipt, and `fixture` for material derived from this
 * repository's own fixtures. The three are the whole vocabulary, and this module states it once so the
 * pack's reader, the export's reader, and the fixtures generator that writes both apply one rule rather
 * than three readings of one sentence.
 *
 * Two facts about the field are load-bearing, and they are the reason the reduction is a function here
 * rather than a parameter a writer picks. First, a container's own `prov` is the weakest value among
 * its items, so a container cannot be assembled to claim `live` while carrying one fixture: the
 * reduction never strengthens a value, and live software never becomes hardware evidence. Second, a
 * captured original can retain its value among live items, so a mixture of live and captured material
 * reduces to `captured` rather than being washed down to `live`. Both follow from taking the weakest
 * value, in the order this file declares.
 *
 * The field is separate from execution assurance, from source and custody, and from appraisal. Which
 * measurement a receipt claims, which origins its anchors name and what duty a window answers under are
 * three other questions, and none of them is the one this one answers: where the material came from.
 * Whether a vendor signature behind captured material verifies, and at what instant a reader weighs it,
 * stay the questions of whoever holds the roots, and no value here states a verdict about either.
 */

/**
 * The three values, in the order the format writes them, strongest first: `live` is the only value a
 * claim about production behaviour stands on, `captured` carries real vendor evidence that was not
 * produced by a live run, and `fixture` is the demonstration path. The order is this file's own and it
 * is the order the reduction reads: the weakest value of a list is its last entry in this order.
 */
export const PROVENANCES = ['live', 'captured', 'fixture'] as const;

export type Provenance = (typeof PROVENANCES)[number];

/**
 * Whether a value is one of the three. A reader that met a fourth label refuses it rather than reading
 * it as whichever of the three it resembled, which is the confusion the closed vocabulary exists to
 * make impossible.
 */
export function isProvenance(value: unknown): value is Provenance {
  return typeof value === 'string' && (PROVENANCES as readonly string[]).includes(value);
}

/**
 * The weakest of the values handed in, which is the single value a container's own `prov` member may
 * state.
 *
 * The list a container carries is never empty: a pack declares at least one item and the two export
 * arms that carry material declare at least one each, and both readers refuse an empty array before any
 * reduction is asked for. A call over nothing is therefore a defect in the caller rather than in a
 * document, and it is refused in those words instead of inventing a third kind of value.
 */
export function reduceProvenance(values: readonly Provenance[]): Provenance {
  const first = values[0];
  if (first === undefined) {
    throw new Error('a provenance reduction over no items has no weakest value');
  }
  let weakest: Provenance = first;
  for (const one of values) {
    if (PROVENANCES.indexOf(one) > PROVENANCES.indexOf(weakest)) weakest = one;
  }
  return weakest;
}
