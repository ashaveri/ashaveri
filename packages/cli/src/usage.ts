/**
 * A refusal the operator can act on. Everything thrown from a command path for a reason the person
 * typing can fix exits 2 and prints its message alone, so a stack trace stays reserved for the bugs
 * nobody at a terminal can do anything about.
 */
export class UsageError extends Error {}

/**
 * The characters a terminal either hides or obeys: the C0 and C1 control ranges, which carry the
 * newline that would start a line this program never wrote; every Unicode format character, which
 * covers the zero-width, directional, isolating and interlinear ones along with a soft hyphen; and
 * the tag block, invisible and astral at once.
 *
 * The tag block is spelled out as a range beside the property classes rather than folded into them,
 * because which class a character belongs to is data the runtime supplies. On this build, whose
 * tables are Unicode 16, `\p{Cf}` does match U+E0020 through U+E007F, and on a runtime whose tables
 * classify them otherwise the range is the only thing that catches them. A class like this one is the
 * boundary of what the program trusts, so it carries its own copy of the ranges that matter.
 *
 * Detection and replacement are built from this one string because an earlier version of this guard
 * had a class that noticed U+007F in a label and a second class that escaped everything except
 * U+007F. A character that is noticed but not escaped is a hole sitting next to a passing test.
 *
 * The two line separators are spelled out because no property class here catches them: U+2028 and
 * U+2029 are category Zl and Zp, neither a control character nor a format character, and a reader
 * that splits text on lines treats them as one. `JSON.stringify` leaves them raw inside its own
 * quotes, so the machine-readable form needs them as much as the printed row does.
 */
const INVISIBLE = '\\p{Cc}\\p{Cf}\\u{2028}\\u{2029}\\u{e0000}-\\u{e007f}';

/**
 * The set above plus the two characters a quoted value has to survive being copied back into an
 * editor, which is the whole of when a printed field should be put in quotes.
 */
export const NEEDS_QUOTING = new RegExp(`[${INVISIBLE}"\\\\]`, 'u');

const EVERY_INVISIBLE = new RegExp(`[${INVISIBLE}]`, 'gu');

/**
 * The escaped form of each character in the class: one `\uXXXX` per UTF-16 unit, so a BMP character
 * yields one escape and an astral one yields its surrogate pair, which keeps the result valid JSON.
 * Applied to a message at the one place messages reach a stream, because a message about a token
 * carries the token, and the `fs` module carries whatever path it was handed inside its own text.
 */
export function escapeInvisible(text: string): string {
  return text.replace(EVERY_INVISIBLE, (char) => {
    // One escape per UTF-16 code unit, walked by index: the string iterator combines a surrogate
    // pair into a single code point, and reading it that way hands back the high half alone.
    const units: string[] = [];
    for (let index = 0; index < char.length; index += 1) {
      units.push(`\\u${char.charCodeAt(index).toString(16).padStart(4, '0')}`);
    }
    return units.join('');
  });
}

/**
 * The same escaping over an already-serialized document, where it has to be narrower. An indented
 * object carries newlines of its own between its fields, and those are structure rather than data,
 * so only the quoted spans are rewritten. A `\uXXXX` escape is the other spelling of the same
 * character to anything that parses the document, which is the whole of the trick.
 */
export function escapeInvisibleJson(document: string): string {
  return document.replace(/"(?:[^"\\]|\\[\s\S])*"/g, (literal) => escapeInvisible(literal));
}
