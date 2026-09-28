/**
 * The strict reading of a JSON document, for the containers of this estate whose payload *is* a JSON file.
 *
 * Two documents are written that way and signed as the bytes were written: the epoch inventory, whose payload
 * is the file a deployment leaves at the root of an epoch directory, and the retention manifest, which is a
 * JSON file a deployment writes about its own store and which travels under the digest a sealed inventory
 * carries beside it. Both are read here, under one rule stated once, because the two facts this section exists
 * to settle are facts about `JSON.parse` and not about either layout.
 *
 * It keeps the last of two members with one name and says nothing, so a payload naming `packs` twice would
 * read as the second list while the bytes carry both, which is the silent drop the closure rule exists to
 * prevent. And it decodes the number `1.0` to the very value `1` decodes to, so by the time any check could ask
 * which spelling the writer signed the two are one JavaScript number, which is why this estate reads integers
 * where no float may stand in for one. Both are settled here, while the characters are still distinguishable.
 *
 * A fault leaves as `onFault` was written, because what a reader owes a caller is the code of the container it
 * was handed: the same lost member answered in an inventory and in a retention manifest are two refusals with
 * two prefixes, and a shared scanner that picked the code itself would be the one place a document could be
 * diagnosed as the wrong container.
 */

/** One JSON object read into the shape this package's readers close over: members in document order. */
export type JsonObject = Map<unknown, unknown>;

/**
 * How many levels of nesting the reading goes to. The epoch inventory's own deepest position is five: the
 * document, one member of `packs`, one entry, one block inside that entry, and the figure inside that block, so
 * the slack above five is where a document that is not that layout is refused rather than walked until the
 * reader gives out. A payload is bytes nobody believes, and a scanner that recursed without a bound would
 * answer a hostile document with a crash standing where the format promises a code.
 */
export const MAX_JSON_DEPTH = 8;

/** RFC 8259 structural whitespace, and nothing else: a newline inside a string is an escape, not a byte. */
function isSpace(char: string): boolean {
  return char === ' ' || char === '\t' || char === '\n' || char === '\r';
}

/**
 * The number grammar JSON allows, matched sticky so the scan reads one token where it stands rather than
 * copying the rest of the document per number. Whether what it matched is a number these layouts write is
 * `scanNumber`'s question, and the two are deliberately apart: this recognises the spelling, that one refuses
 * the spellings no position of either layout can hold.
 */
const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[Ee][-+]?[0-9]+)?/yu;

/**
 * A number, refused unless it is written as an integer. The token grammar above already declines a leading
 * plus and a leading zero, because neither starts a JSON number, and this is the other half: a fraction, an
 * exponent and negative zero do parse, equal the integer they imitate, and are refused here rather than read as
 * it, because neither layout has a position that holds any of them. Every figure the two documents state is a
 * unix second, a count of records, a number of seconds or an epoch number, and `JSON.stringify` of any of those
 * writes the grammar this accepts.
 */
function scanNumber(token: string, onFault: (detail: string) => never): number {
  if (!/^-?(?:0|[1-9][0-9]*)$/u.test(token) || (token.startsWith('-') && Number(token) === 0)) {
    return onFault(`the number ${token} is not written as an integer, which is all this document's numbers are`);
  }
  const value = Number(token);
  if (!Number.isSafeInteger(value)) {
    return onFault(`the number ${token} is past the widest integer a reader of this document holds exactly`);
  }
  return value;
}

/**
 * A JSON document, read as this estate states it: one value with nothing after it, objects whose member names
 * are unique and kept in the order they were written, and numbers written only as integers. Leaf strings come
 * through `JSON.parse` over the one token so that escapes mean what the specification says they mean.
 */
export function scanJson(source: string, onFault: (detail: string) => never): unknown {
  let at = 0;
  let depth = 0;

  const fail = (detail: string): never => onFault(`${detail} at offset ${String(at)}`);

  const space = (): void => {
    while (at < source.length && isSpace(source.charAt(at))) at += 1;
  };

  const value = (): unknown => {
    space();
    if (at >= source.length) return fail('the document ends where a value belongs');
    if (depth >= MAX_JSON_DEPTH) return fail('the document nests deeper than this layout goes');
    depth += 1;
    try {
      return atom();
    } finally {
      depth -= 1;
    }
  };

  const string = (): string => {
    const start = at;
    at += 1;
    for (;;) {
      if (at >= source.length) return fail('a string is not closed');
      const char = source.charAt(at);
      if (char === '\\') {
        at += 2;
        continue;
      }
      if (char === '"') break;
      at += 1;
    }
    const slice = source.slice(start, at + 1);
    at += 1;
    let parsed: unknown;
    try {
      parsed = JSON.parse(slice);
    } catch {
      return fail('a string, or an escape inside one, is not well formed');
    }
    if (typeof parsed !== 'string') return fail('a string is not well formed');
    return parsed;
  };

  const object = (): JsonObject => {
    at += 1;
    const members: JsonObject = new Map();
    space();
    if (source.charAt(at) === '}') {
      at += 1;
      return members;
    }
    for (;;) {
      space();
      if (source.charAt(at) !== '"') return fail('an object member name is not a string');
      const name = string();
      if (members.has(name)) return fail(`the member '${name}' is stated twice, and only one of the two can be read`);
      space();
      if (source.charAt(at) !== ':') return fail(`the member '${name}' is not followed by a colon`);
      at += 1;
      members.set(name, value());
      space();
      const next = source.charAt(at);
      if (next === ',') {
        at += 1;
        continue;
      }
      if (next === '}') {
        at += 1;
        return members;
      }
      return fail(`an object has '${next}' where a comma or a closing brace belongs`);
    }
  };

  const array = (): unknown[] => {
    at += 1;
    const items: unknown[] = [];
    space();
    if (source.charAt(at) === ']') {
      at += 1;
      return items;
    }
    for (;;) {
      items.push(value());
      space();
      const next = source.charAt(at);
      if (next === ',') {
        at += 1;
        continue;
      }
      if (next === ']') {
        at += 1;
        return items;
      }
      return fail(`an array has '${next}' where a comma or a closing bracket belongs`);
    }
  };

  const literal = (word: string, result: unknown): unknown => {
    if (!source.startsWith(word, at)) return fail('expected a value');
    at += word.length;
    return result;
  };

  const atom = (): unknown => {
    const char = source.charAt(at);
    if (char === '{') return object();
    if (char === '[') return array();
    if (char === '"') return string();
    if (char === 't') return literal('true', true);
    if (char === 'f') return literal('false', false);
    if (char === 'n') return literal('null', null);
    const digits = NUMBER;
    digits.lastIndex = at;
    const token = digits.exec(source)?.[0];
    if (token === undefined || token.length === 0) return fail(`expected a value and met ${JSON.stringify(char)}`);
    at += token.length;
    return scanNumber(token, onFault);
  };

  const root = value();
  space();
  if (at !== source.length) return fail('bytes follow the document, which is one value and not two');
  return root;
}

const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * A JSON document out of the bytes of a file, which is how both of these containers arrive: as text a
 * deployment wrote, and signed or sealed as those very bytes. A payload that is not UTF-8 is refused here rather
 * than read as replacement characters, because a document a reader cannot spell is a document it cannot check.
 */
export function readJsonBytes(bytes: Uint8Array, onFault: (detail: string) => never): unknown {
  let source: string;
  try {
    source = decoder.decode(bytes);
  } catch (reason) {
    const detail = reason instanceof Error ? reason.message : String(reason);
    return onFault(`the payload is not UTF-8, and this document is written as text: ${detail}`);
  }
  return scanJson(source, onFault);
}
