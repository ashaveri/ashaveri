import { PACK_CONTENT_TYPE } from '@ashaveri/receipt';
import { runVerifyHandover, type VerbPin, type VerifyHandoverFlags } from './verify-handover.js';

/**
 * `ashaveri verify-pack <document> [options]`: a pack, and nothing but a pack.
 *
 * `verify-handover` answers what a file is, which is the right question about a pile of handover output
 * and the wrong one about a script. A caller that already knows which file it is holding, because it
 * assembled the pack or was handed it under that name, wants a run that stops when the file in front of
 * it is not one: read the other way round, a step written to check a pack quietly checks an export,
 * prints a verdict about material nobody meant to adjudicate, and exits 0. Pinning the content type is
 * what turns that silence into a refusal, and the refusal is the one `verify-handover` already gives a
 * document whose type it holds no reader for, `BAD_PROTECTED_HEADER` naming the `typ` the header carries,
 * because the fact is the same fact and a second code for it would be one more thing to learn about a
 * file that states it in one field.
 *
 * Everything else is that command's, unchanged: the same readers over the same bytes, the same two
 * renderings, the same keys designated by `--key` and matched on the kid a header names, the same three
 * exit codes. This verb adds no option, no code and no rule, which is the point of it being a pin rather
 * than a second implementation. A pack whose span crosses a key rotation is verified here exactly as it
 * is there, against the epochs the caller retained, and the duty figures come back as the deployment's
 * own statement and are judged by nothing in this tool.
 */
export const PACK_VERB: VerbPin = { verb: 'verify-pack', contentType: PACK_CONTENT_TYPE };

/** `ashaveri verify-pack <document> [options]`, including its exit codes. */
export async function runVerifyPack(positionals: string[], values: VerifyHandoverFlags): Promise<number> {
  return runVerifyHandover(positionals, values, PACK_VERB);
}
