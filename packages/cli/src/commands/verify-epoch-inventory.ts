import { EPOCH_INVENTORY_CONTENT_TYPE } from '@ashaveri/receipt';
import { runVerifyHandover, type VerbPin, type VerifyHandoverFlags } from './verify-handover.js';

/**
 * `ashaveri verify-epoch-inventory <document> [options]`: an epoch inventory, and nothing but one.
 *
 * `verify-handover` answers what a file is, which is the right question about a pile of handover output and the
 * wrong one about a step that came for the run's summary. Read the other way round, a script written to check
 * the statement a closed epoch ends on quietly checks a pack instead, prints a verdict about material nobody
 * meant to adjudicate, and exits 0. Pinning the content type is what turns that silence into a refusal, and the
 * refusal is the one `verify-handover` already gives a document whose type it holds no reader for,
 * `BAD_PROTECTED_HEADER` naming the `typ` the header carries, because which shape these bytes claim is stated in
 * one field and wants one answer rather than a code per verb.
 *
 * Everything else is that command's, unchanged: the same reader over the same bytes, the same two renderings,
 * the same keys designated by `--key` and matched on the kid a header names, the same three exit codes. This
 * verb adds no option, no code and no rule, which is the point of it being a pin rather than a second
 * implementation. One input a caller cannot hand here is stated by the reading rather than by this file: the
 * presence fold an inventory's reader can do over the run's retention artifacts has no flag carrying those
 * bytes, so both verbs read the sealed document alone and report that the fold answered nothing.
 */
export const EPOCH_INVENTORY_VERB: VerbPin = {
  verb: 'verify-epoch-inventory',
  contentType: EPOCH_INVENTORY_CONTENT_TYPE,
};

/** `ashaveri verify-epoch-inventory <document> [options]`, including its exit codes. */
export async function runVerifyEpochInventory(positionals: string[], values: VerifyHandoverFlags): Promise<number> {
  return runVerifyHandover(positionals, values, EPOCH_INVENTORY_VERB);
}
