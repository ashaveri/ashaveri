import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  MARKING_MEMBER_NAME,
  PROVENANCE_V1_MEMBER_SCHEME,
  ReceiptError,
  emptyRegion,
  extractMarkedRegion,
  markingInsertionPoint,
  provenanceV1Member,
  toHex,
} from '../src/index.js';

/**
 * The extraction rule of section 3.3 of `docs/receipt-spec.md`, tested against byte spans rather
 * than against parsed objects: what `mk.d` commits to is where a region sits in a response, and a
 * rule that read the right value out of the wrong span would pass every test written in JSON.
 */

const AT = 1_772_000_000;

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function text(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/** The member as a writer serializes it, at the top level of whatever object carries it. */
function memberText(at: number = AT): string {
  return `"${MARKING_MEMBER_NAME}":${JSON.stringify(provenanceV1Member(at))}`;
}

function bufferedBody(content: string, at: number = AT): string {
  return JSON.stringify({
    id: 'chatcmpl-1',
    object: 'chat.completion',
    created: at,
    model: 'mock-model-1',
    choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' }],
    usage: { prompt_tokens: 9, completion_tokens: 6, total_tokens: 15 },
    ...{ [MARKING_MEMBER_NAME]: provenanceV1Member(at) },
  });
}

function chunkFrame(payload: Record<string, unknown>): string {
  return `data: ${JSON.stringify(payload)}\n\n`;
}

function markingFrame(at: number = AT): string {
  return chunkFrame({
    id: 'chatcmpl-marking',
    object: 'chat.completion.chunk',
    created: at,
    model: 'mock-model-1',
    choices: [],
    [MARKING_MEMBER_NAME]: provenanceV1Member(at),
  });
}

function streamedBody(content: string, at: number = AT): string {
  return (
    chunkFrame({ id: 'chatcmpl-1', object: 'chat.completion.chunk', created: at, model: 'mock-model-1', choices: [{ index: 0, delta: { content }, finish_reason: null }] }) +
    markingFrame(at) +
    'data: [DONE]\n\n'
  );
}

/** A completion shaped like the one above and carrying no marking at all. */
function unmarkedBody(content: string): string {
  return JSON.stringify({
    id: 'chatcmpl-1',
    object: 'chat.completion',
    created: AT,
    model: 'mock-model-1',
    choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' }],
  });
}

/** Where a region starts inside the response that carries it, in bytes, or -1. */
function offsetOfRegion(response: Uint8Array): number {
  const region = extractMarkedRegion('provenance-v1', response);
  return Buffer.from(response).indexOf(Buffer.from(region));
}

function mismatch(action: () => unknown): ReceiptError {
  try {
    action();
  } catch (err) {
    if (err instanceof ReceiptError && err.code === 'MARK_MISMATCH') return err;
    throw err;
  }
  throw new Error('expected a MARK_MISMATCH and got no refusal');
}

describe('provenance-v1 in a buffered completion', () => {
  it('takes the member exactly as the response carries it', () => {
    const response = bytes(bufferedBody('Mock reply: café ☕ served.'));
    const region = extractMarkedRegion('provenance-v1', response);
    expect(new TextDecoder().decode(region)).toBe(memberText());
    // The span is a slice of the response and not a re-serialization of the value, which is the
    // whole of why a port and this reader can agree about a digest: the bytes came from the body.
    expect(Buffer.from(response).indexOf(Buffer.from(region))).toBeGreaterThan(0);
  });

  it('is unaffected by how wide the characters ahead of it are', () => {
    // The member is found by walking octets, so a multi-byte run of text ahead of it moves the span
    // without moving the rule. Offset by character count rather than by byte count, the slice below
    // would land inside the value and decode to something that is not the member.
    const wide = bytes(bufferedBody('☕'.repeat(40)));
    const narrow = bytes(bufferedBody('x'.repeat(40)));
    expect(offsetOfRegion(wide)).toBeGreaterThan(offsetOfRegion(narrow));
    expect(new TextDecoder().decode(extractMarkedRegion('provenance-v1', wide))).toBe(memberText());
    expect(new TextDecoder().decode(extractMarkedRegion('provenance-v1', narrow))).toBe(memberText());
  });

  it('reads the member when a trailing newline follows the body', () => {
    // The response digest vectors carry one such body, so the rule has to count the byte it is not
    // asked about as framing rather than as a second document glued to the first.
    const response = bytes(`${bufferedBody('hi')}\n`);
    expect(new TextDecoder().decode(extractMarkedRegion('provenance-v1', response))).toBe(memberText());
  });

  it('refuses a body that is two documents glued together', () => {
    const response = bytes(`${bufferedBody('hi')}${bufferedBody('hi')}`);
    expect(mismatch(() => extractMarkedRegion('provenance-v1', response)).message).toContain('no region');
  });

  it('refuses a response with no region at all', () => {
    const unmarked = bytes(
      JSON.stringify({ id: 'chatcmpl-1', choices: [{ index: 0, message: { content: 'hi' } }] }),
    );
    expect(mismatch(() => extractMarkedRegion('provenance-v1', unmarked)).message).toContain('no region');
  });

  it('refuses a response carrying the region twice', () => {
    // A backend that marks its own output and a gateway that marks the result are the case this
    // refusal is for: a reader cannot be asked to choose which of two digests the signature names.
    const twice = bytes(
      `${markingFrame()}${markingFrame()}`,
    );
    const error = mismatch(() => extractMarkedRegion('provenance-v1', twice));
    expect(error.message).toContain('2 regions');
  });

  it('ignores a member that shares the name but not the scheme', () => {
    // Somebody else's extension inside the namespace: it is content, and the rule is the shape this
    // registry row binds to one label.
    const other = bytes(
      JSON.stringify({ id: 'chatcmpl-1', choices: [], [MARKING_MEMBER_NAME]: { note: 'not a marking' } }),
    );
    expect(mismatch(() => extractMarkedRegion('provenance-v1', other)).message).toContain('no region');
  });

  it('ignores a marking-shaped object nested below the top level', () => {
    const nested = bytes(
      JSON.stringify({
        id: 'chatcmpl-1',
        choices: [],
        usage: { [MARKING_MEMBER_NAME]: provenanceV1Member(AT) },
      }),
    );
    expect(mismatch(() => extractMarkedRegion('provenance-v1', nested)).message).toContain('no region');
  });

  it('ignores the shape where it appears only inside a string', () => {
    // The transcript quoting a mark is model output, and `res` covers it as part of the transcript:
    // a rule that counted quoted text would refuse a completion for repeating a shape back.
    const quoted = bufferedBody(`here is a mark: {${memberText()}}`);
    expect(new TextDecoder().decode(extractMarkedRegion('provenance-v1', bytes(quoted)))).toBe(memberText());
  });
});

describe('provenance-v1 in a streamed completion', () => {
  it('takes one whole frame line and none of its terminator', () => {
    const response = bytes(streamedBody('Mock reply: café ☕ served.'));
    const region = extractMarkedRegion('provenance-v1', response);
    const text = new TextDecoder().decode(region);
    expect(text).toBe(markingFrame().slice(0, -2));
    expect(text.startsWith('data: ')).toBe(true);
    expect(text.endsWith('\n')).toBe(false);
  });

  it('keeps a CRLF-framed stream readable and digests the line, not its framing bytes', () => {
    const crlf = bytes(streamedBody('hi').replaceAll('\n\n', '\r\n\r\n'));
    const text = new TextDecoder().decode(extractMarkedRegion('provenance-v1', crlf));
    expect(text.startsWith('data: ')).toBe(true);
    expect(text.endsWith('}')).toBe(true);
  });

  it('does not count a content chunk that carries the member beside choices', () => {
    // The tail chunk of a stream is the one the rule names, so a backend writing the member inside a
    // frame that also carries a delta leaves exactly one candidate rather than making a reader guess.
    const withContentMember = bytes(
      chunkFrame({
        id: 'chatcmpl-1',
        object: 'chat.completion.chunk',
        created: AT,
        model: 'mock-model-1',
        choices: [{ index: 0, delta: { content: 'hi' }, finish_reason: null }],
        [MARKING_MEMBER_NAME]: provenanceV1Member(AT),
      }) + markingFrame(),
    );
    expect(new TextDecoder().decode(extractMarkedRegion('provenance-v1', withContentMember))).toBe(
      markingFrame().slice(0, -2),
    );
  });

  it('refuses a stream whose terminator is the only thing that parses', () => {
    expect(mismatch(() => extractMarkedRegion('provenance-v1', bytes('data: [DONE]\n\n'))).message).toContain(
      'no region',
    );
  });

  it('reads a final frame that arrived without its blank line', () => {
    // The last write of a response can be the frame itself; the region is the line either way, so a
    // reader that needed the terminator would refuse a body it was handed whole.
    const text = new TextDecoder().decode(extractMarkedRegion('provenance-v1', bytes(markingFrame().slice(0, -2))));
    expect(text).toBe(markingFrame().slice(0, -2));
  });
});

describe('none', () => {
  it('names the empty region over a response that carries no mark', () => {
    const unmarked = bytes(unmarkedBody('hi'));
    expect(new TextDecoder().decode(unmarked)).not.toContain(MARKING_MEMBER_NAME);
    expect(extractMarkedRegion('none', unmarked)).toEqual(emptyRegion());
    expect(toHex(sha256(extractMarkedRegion('none', unmarked)))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('refuses a marked response, because the label declares that no region is marked', () => {
    // The upstream-injection case on a deployment that marks nothing: the streaming path forwards a
    // backend's bytes unread, so this is the one place a mark the gateway never wrote is caught.
    const error = mismatch(() => extractMarkedRegion('none', bytes(streamedBody('hi'))));
    expect(error.message).toContain('carry 1 matching');
  });

  it('takes an unrelated member sharing the name as no region', () => {
    const other = bytes(
      JSON.stringify({ id: 'chatcmpl-1', choices: [], [MARKING_MEMBER_NAME]: { note: 'not a marking' } }),
    );
    expect(extractMarkedRegion('none', other)).toEqual(emptyRegion());
  });
});

describe('where a buffered body takes the member', () => {
  it('names the closing brace of the one object the body is', () => {
    const body = bytes('{"id":"chatcmpl-1","n":2}');
    const insert = markingInsertionPoint(body);
    expect(insert).toEqual({ at: body.length - 1, comma: true });
    if (insert === null) return;
    // Splicing at the point it named, with the comma it asked for, yields a body whose marking member
    // is exactly the region the rule extracts: the writer's point and the reader's span, agreeing.
    const spliced = bytes(`${text(body.subarray(0, insert.at))},${memberText()}${text(body.subarray(insert.at))}`);
    expect(text(extractMarkedRegion('provenance-v1', spliced))).toBe(memberText());
  });

  it('asks for no comma before the only member of an empty object', () => {
    expect(markingInsertionPoint(bytes('{}'))).toEqual({ at: 1, comma: false });
  });

  it('keeps a body\'s own whitespace and names the brace it ends at', () => {
    // The insertion is a splice, so a pretty-printed upstream answer stays pretty-printed and only
    // the member is new: a re-serialization would have moved every byte behind it.
    expect(markingInsertionPoint(bytes('{\n  "a": 1\n}\n'))).toEqual({ at: 11, comma: true });
  });

  it('gives no point at all for bytes that are not one object', () => {
    for (const body of ['[1,2]', '"text"', '{"a":1}trailing', '{"a":1}{"b":2}', '', '   ']) {
      expect(markingInsertionPoint(bytes(body)), body).toBeNull();
    }
  });
});

describe('the member a writer builds', () => {
  it('spells the scheme as the namespaced label and the generation as machine made', () => {
    expect(provenanceV1Member(AT)).toEqual({
      marking: { sch: PROVENANCE_V1_MEMBER_SCHEME, gen: 'ai', at: AT },
    });
  });

  it('refuses a time no integer spells', () => {
    // The member is hashed as text, so a value a reader cannot write back is refused where it is
    // built rather than at the digest: this is the writer agreeing with the stricter reader instead
    // of signing bytes only it can reproduce.
    for (const bad of [1.5, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(expectThrows(() => provenanceV1Member(bad)).code).toBe('BAD_PAYLOAD');
    }
  });

  it('writes negative zero as the integer zero it means', () => {
    // `Number.isSafeInteger(-0)` holds and `-0 < 0` does not, so the guard above lets it through,
    // and JSON's own number spelling takes the sign off: one text for one whole number, which is
    // the rule the CBOR writer in this package keeps from its own side.
    expect(JSON.stringify(provenanceV1Member(-0))).toContain('"at":0');
  });
});

function expectThrows(action: () => unknown): ReceiptError {
  try {
    action();
  } catch (err) {
    if (err instanceof ReceiptError) return err;
    throw err;
  }
  throw new Error('expected a ReceiptError and got none');
}
