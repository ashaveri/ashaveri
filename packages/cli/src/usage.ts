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
 * One outside token inside a row this program composes: quoted when it carries anything that would end
 * the row, reorder it, or let it be mistaken for two rows, and escaped inside that quote.
 *
 * Three rules in this estate answer for a token that did not come from here, and they differ by what
 * the reader is owed. A refusal quotes a short clean token and prints a digest for anything else,
 * because the point of a refusal is the code and a copy of an unbounded vendor string would be a
 * second line to read (`@ashaveri/collateral` keeps that in `quoteOrDigest`). An inventory refuses the
 * value outright, because a label is written beside a run and a run with an unprintable name is a
 * record nobody can cite (`@ashaveri/receipt` keeps that in `requireLabel`). A report row is owed
 * neither: the reader of a verification report has to see the words the document signed and the reason
 * the collector gave, so hiding them behind a digest would cost the one thing the row is for, and
 * refusing them would make an unreadable document unreportable. So the token is kept, put in quotes
 * when it is not a clean short run of text, and escaped so that the quotes are the only ones the row
 * carries and no character inside them can move a cursor or start a line the program never wrote.
 *
 * `NEEDS_QUOTING` decides when to quote, and it is the same test `credential` keeps for its label
 * column: the invisible class plus the two characters a quoted value has to survive being copied back
 * into an editor. Quoting alone is not enough, for the reason that comment gives: the platform's
 * stringifier leaves the C1 range, the two line separators and every format character exactly as raw
 * as they were.
 */
export function printedToken(text: string): string {
  return NEEDS_QUOTING.test(text) ? escapeInvisible(JSON.stringify(text)) : text;
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

/**
 * One machine-readable document per call, so no command has to decide for itself whether it needs the
 * guard above. A `--json` stream is piped into a file and read on a terminal on the way there, and
 * `JSON.stringify` passes every invisible character through as raw text, so the escaping follows it.
 * Only the quoted spans are rewritten: the newlines between an indented document's fields are
 * structure, and inside a string an escape is the other spelling of the same character to anything
 * that parses it. Every value printed here has usually been validated first, and this does not
 * assume it was, because the validation lives in another file.
 */
export function writeJson(value: unknown): void {
  process.stdout.write(`${escapeInvisibleJson(JSON.stringify(value, null, 2))}\n`);
}
