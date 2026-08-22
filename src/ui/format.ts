import { toHex } from '../crypto/bytes.js';
import { h } from './dom.js';
import type { ReadStatus } from '../volume/types.js';
import { READ_STATUS_LABEL } from '../volume/types.js';

/** Hex in byte-pair groups, so a 16-byte block reads as sixteen things. */
export function groupedHex(bytes: Uint8Array, limit = bytes.length): string {
  const shown = bytes.subarray(0, limit);
  const parts: string[] = [];
  for (let i = 0; i < shown.length; i++) parts.push(toHex(shown.subarray(i, i + 1)));
  return parts.join(' ') + (limit < bytes.length ? ' …' : '');
}

export interface Tone {
  /** Decorative; the word beside it carries the meaning. */
  glyph: string;
  fill: 'fill-ok' | 'fill-alarm' | 'fill-info';
}

export const TONE_OK: Tone = { glyph: '✓', fill: 'fill-ok' };
export const TONE_ALARM: Tone = { glyph: '✕', fill: 'fill-alarm' };
export const TONE_STALE: Tone = { glyph: '↺', fill: 'fill-alarm' };
export const TONE_INFO: Tone = { glyph: '●', fill: 'fill-info' };

/**
 * A verdict pill: glyph, word, colour. Never colour alone — the glyph is
 * `aria-hidden` and the word is the accessible content, so the state survives
 * grayscale, deuteranopia and a screen reader equally.
 */
export function verdictPill(tone: Tone, label: string): HTMLElement {
  return h('span', { class: `verdict ${tone.fill}` }, [
    h('span', { class: 'verdict-glyph', 'aria-hidden': 'true', text: tone.glyph }),
    h('span', { text: label }),
  ]);
}

export function toneForStatus(status: ReadStatus): Tone {
  if (status === 'INTACT') return TONE_OK;
  if (status === 'SUCCEEDS_CLEANLY_STALE') return TONE_STALE;
  return TONE_ALARM;
}

export function statusLabel(status: ReadStatus): string {
  return READ_STATUS_LABEL[status];
}

export function definition(term: string, value: string): HTMLElement {
  return h('div', { class: 'readout-line' }, [h('dt', { text: term }), h('dd', { text: value })]);
}

export function percent(value: number): string {
  return `${value.toFixed(2)}%`;
}
