/**
 * The estate's printed-line character class, with one owner.
 *
 * A character is in this class when a reader of the printed row would see something other than the bytes the
 * row is made of. Four kinds are, each for its own reason. The C0 range carries the line feed and the carriage
 * return, which end a line. The C1 range carries next line and its neighbours, which anything that splits text
 * on line breaks ends a line on too. Every Unicode format character is in it because that property class is what
 * covers the zero width, directional, isolating and interlinear ones along with a soft hyphen: none of them ends
 * a line, and each either hides part of one or reorders it, so the visible row stops being the byte order the
 * document signed. The two line separators are spelled out beside the property classes because no property class
 * reaches them, being category Zl and Zp, neither control nor format. The tag block is spelled out as a range for
 * the other reason: which class a character belongs to is data the runtime supplies, and on a runtime whose
 * tables classify U+E0020 through U+E007F otherwise the range is the only thing that catches them. A class that
 * bounds what this package refuses carries its own copy of the ranges that matter rather than trusting the tables
 * it happens to be running on.
 *
 * What is not in it is as deliberate as what is. A space in the middle of a value, a length, and every character
 * outside ASCII are text a line is made of, and none of them is refused here or by any consumer below.
 *
 * Three sites in this package consume it and none of them states it again: the receipt writer refuses the attested
 * text members of a payload at the step that signs them (`src/receipt.ts`), the epoch inventory refuses a run
 * label that cannot be printed beside the run (`src/epoch-inventory.ts`), and every `ReceiptError` message is
 * escaped through it so that a refusal about a token cannot itself carry a token that moves a cursor
 * (`src/errors.ts`). Which positions a site applies the class to, what byte ceiling bounds the value beside it,
 * how a refusal names the position, and which code it carries are the site's own, because those are the facts
 * that differ between text this package writes and text it reads from somebody else. A test drives the same
 * roster of characters through the two refusal sites and the escaping one and holds them to one membership
 * (`test/line-text.test.ts`), so a class that drifts at one site fails a test rather than a paragraph.
 *
 * Two packages outside this one state the same ranges for their own boundary, the CLI before printing a value and
 * `attest-core` before quoting one, and share no module with this one. That is a different question from who owns
 * a class inside a package, and is answered beside them.
 */

/** The class as ranges, in the spelling a character class body takes, so a consumer can add its own flags. */
export const FORGES_A_LINE_RANGES = '\\p{Cc}\\p{Cf}\\u{2028}\\u{2029}\\u{e0000}-\\u{e007f}';

/**
 * The class as a test. Module-private on purpose: a caller asks about a whole value and gets the code point it
 * stopped on, which is `firstForgingCodePoint`, and a caller that needs the class with other flags builds it from
 * the ranges above rather than sharing a pattern whose global state belongs to somebody else.
 */
const FORGES_A_LINE = new RegExp(`[${FORGES_A_LINE_RANGES}]`, 'u');

/**
 * The first code point of `text` that belongs to the class, or `undefined` when none of it does.
 *
 * Walked by code point rather than by the regex's own first match on the whole string, because both refusal
 * sites report which character they stopped on, and a report that named a UTF-16 half of an astral character
 * would name a code point the document does not hold.
 */
export function firstForgingCodePoint(text: string): number | undefined {
  for (const character of text) {
    if (FORGES_A_LINE.test(character)) return character.codePointAt(0);
  }
  return undefined;
}
