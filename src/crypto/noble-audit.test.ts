/* What "audited" covers for the @noble/ciphers this lab ships.
 *
 * Three places called it audited with no version: the README ("@noble/ciphers'
 * audited raw single-block API"), src/crypto/xts.ts ("@noble/ciphers' audited
 * `unsafe` block API") and the scope panel ("an audited implementation"). The
 * library records its latest audit as "at version 1.0.0, in Sep 2024,
 * independently, by [cure53]", and this lab pins ^2.4.0, past it.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');
const flat = (text: string) => text.replace(/\n\s*\*\s?/g, ' ').replace(/\s+/g, ' ');

const pkg = JSON.parse(read('../../package.json'));
const nobleReadme = read('../../node_modules/@noble/ciphers/README.md');

describe('the @noble/ciphers audit claim', () => {
  it('pins a version later than the latest audit the library records', () => {
    expect(pkg.dependencies['@noble/ciphers']).toBe('^2.4.0');
    expect(nobleReadme).toContain('The library has been audited');
    expect(nobleReadme).toMatch(/at version 1\.0\.0, in Sep 2024, independently, by \[cure53\]/);
    expect(nobleReadme).not.toMatch(/at version 2\.\d+\.\d+, in [A-Z]/);
  });

  it('names that version in every place that calls the library audited', () => {
    for (const [name, text] of [
      ['README.md', flat(read('../../README.md'))],
      ['src/crypto/xts.ts', flat(read('./xts.ts'))],
      ['src/ui/panelScope.ts', flat(read('../ui/panelScope.ts'))],
    ] as const) {
      expect(text, name).not.toContain("' audited raw");
      expect(text, name).not.toContain("audited `unsafe` block API");
      expect(text, name).not.toContain('an audited implementation');
      expect(text, name).toMatch(/at version 1\.0\.0, in Sep 2024, independently, by \[?cure53\]?/);
      expect(text, name).toMatch(/\^2\.4\.0/);
    }
  });
});
