/**
 * A backward scan and one slice: an anchored plus-quantified slash pattern
 * backtracks from every start position over a run that ends in a non-slash,
 * quadratic on operator-configured input.
 */
export function stripTrailingSlashes(s: string): string {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 0x2f) end -= 1;
  return end === s.length ? s : s.slice(0, end);
}