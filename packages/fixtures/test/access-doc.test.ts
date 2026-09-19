import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadPopVectors } from '../src/index.js';

const DOC = fileURLToPath(new URL('../../../docs/access-control.md', import.meta.url));
const MARKER = '<!-- pop-signing-string:completion-post -->';

describe('docs/access-control.md', () => {
  it('shows the signing string the golden vector signs, byte for byte', () => {
    const text = readFileSync(DOC, 'utf8');
    const at = text.indexOf(MARKER);
    expect(at, `${MARKER} must sit above the worked example`).toBeGreaterThan(-1);
    const block = /```text\n([\s\S]*?)```/.exec(text.slice(at));
    expect(block, 'the worked example is a fenced text block').not.toBeNull();
    const [vector] = loadPopVectors().vectors;
    expect(block?.[1]?.replace(/\n$/, '')).toBe(vector?.signingString);
  });

  it('documents every field the writer can emit', () => {
    const text = readFileSync(DOC, 'utf8');
    for (const field of ['`t`', '`rid`', '`cred`', '`auth`', '`scope`', '`m`', '`p`', '`rcp`', '`nce`', '`st`', '`dur`', '`deny`']) {
      expect(text, `the allowlist section documents ${field}`).toContain(field);
    }
  });
});
