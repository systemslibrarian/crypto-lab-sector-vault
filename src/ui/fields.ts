import { h } from './dom.js';

export interface NumberField {
  root: HTMLElement;
  input: HTMLInputElement;
  /** The current value, or null when the box holds something out of range. */
  value(): number | null;
  set(value: number): void;
}

/**
 * A labelled whole-number box with real `min`/`max`. `value()` returns null
 * rather than clamping, so a caller has to decide what an out-of-range entry
 * means instead of silently acting on a different number than the one on
 * screen.
 */
export function numberField(id: string, label: string, min: number, max: number, initial: number): NumberField {
  const input = h('input', {
    type: 'number',
    id,
    min: String(min),
    max: String(max),
    step: '1',
    value: String(initial),
    inputmode: 'numeric',
  }) as HTMLInputElement;
  const root = h('div', { class: 'field' }, [
    h('label', { for: id, text: `${label} (${min}–${max})` }),
    input,
  ]);
  const value = (): number | null => {
    const parsed = Number(input.value);
    const ok = input.value.trim() !== '' && Number.isInteger(parsed) && parsed >= min && parsed <= max;
    input.setAttribute('aria-invalid', String(!ok));
    return ok ? parsed : null;
  };
  return {
    root,
    input,
    value,
    set(next: number) {
      input.value = String(next);
      value();
    },
  };
}
