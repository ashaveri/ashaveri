import { EXPORT_CONTENT_TYPE } from '@ashaveri/receipt';
import { runVerifyHandover, type VerbPin, type VerifyHandoverFlags } from './verify-handover.js';

/**
 * `ashaveri verify-export <document> [options]`: an export, and nothing but an export.
 *
 * The same argument as `verify-pack` makes for itself: a caller that names the shape it came for wants a
 * run that stops rather than one that reads whatever arrives and reports on it happily. An export is the
 * document where the mismatch costs most, because what it carries is originals beside a claim about them,
 * so a step written to check a handover's material can quietly check a completeness statement instead and
 * exit 0. The pin answers that with `verify-handover`'s own refusal of a type it holds no reader for,
 * `BAD_PROTECTED_HEADER` naming the `typ` the header carries, since the content type is the field that
 * states which of the four signed shapes these bytes claim to be.
 *
 * The options are the handover's and no others. `--key` designates the key whose signature this run
 * accepts, matched on the kid the export's header names, which is the one reader of the four that takes a
 * single pinned key rather than a resolver, and `--companion` hands over the files an item's original
 * travels in, matched by the bare name the signed item carries. An item whose companion was not handed
 * over is refused by that name here exactly as it is there, because an export that reported on material
 * nobody put in the reader's hand is the defect that container exists not to have.
 */
export const EXPORT_VERB: VerbPin = { verb: 'verify-export', contentType: EXPORT_CONTENT_TYPE };

/** `ashaveri verify-export <document> [options]`, including its exit codes. */
export async function runVerifyExport(positionals: string[], values: VerifyHandoverFlags): Promise<number> {
  return runVerifyHandover(positionals, values, EXPORT_VERB);
}
