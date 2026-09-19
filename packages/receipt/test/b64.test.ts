import { describe, expect, it } from 'vitest';
import { fromBase64Url, toBase64Url } from '../src/b64.js';

/**
 * `String.fromCharCode` takes its arguments on the call stack, so spreading a whole character
 * array into it is a cliff, not a slowdown. Measured on this host (Node 24 / V8): a bare
 * `String.fromCharCode(...new Array(n).fill(65))` answers at 124,757 arguments and raises
 * `RangeError` at 124,758, and 124,758 characters is 93,568 input bytes. Inside the encoder's own
 * call path the cliff arrives at or before 93,567 bytes (124,756 characters), because the limit
 * moves with the stack depth already spent. Either way it is roughly 91 KB of input, not the
 * ledger's 48 KB. Every in-tree caller is far under it, but this is an exported helper, so the
 * bound belongs to the package and not to its callers.
 */
describe('toBase64Url past the argument cliff', () => {
  // Three residue classes, so a chunked build cannot drop a tail: 93,567 = 3n, 93,568 = 3n+1,
  // 100,000 = 3n+1, 100,001 = 3n+2, 100,002 = 3n. All five threw before the fix; 93,567 is the
  // smallest size here and the one the bare-node spread still answered.
  const sizes = [93_567, 93_568, 100_000, 100_001, 100_002];

  it.each(sizes)('round-trips %i bytes, which is past the spread limit', (size) => {
    const bytes = Uint8Array.from({ length: size }, (_unused, index) => index % 251);
    const encoded = toBase64Url(bytes);
    expect(encoded).toHaveLength(4 * Math.floor(size / 3) + (size % 3 === 0 ? 0 : size % 3 + 1));
    expect(encoded).not.toMatch(/[+/=]/u);
    expect(fromBase64Url(encoded)).toEqual(bytes);
  });

  it('encodes a hundred kilobytes to the length the arithmetic predicts', () => {
    expect(toBase64Url(new Uint8Array(100_000))).toHaveLength(133_334);
  });
});
