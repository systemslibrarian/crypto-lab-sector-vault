/** Minimal DOM helpers. No framework; the page is small and explicit. */

type Attrs = Record<string, string | number | boolean | undefined>;
type Child = Node | string | null | undefined;

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: Child[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    if (key === 'class') node.className = String(value);
    else if (key === 'text') node.textContent = String(value);
    else node.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function replace(node: Element, children: Child[]): void {
  clear(node);
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
}

/** A section card with the standard act heading. */
export function actCard(id: string, actLabel: string, title: string): HTMLElement {
  const section = h('section', { class: 'card', id, 'aria-labelledby': `${id}-title` });
  section.append(
    h('div', { class: 'act-head' }, [
      h('span', { class: 'act-num', text: actLabel }),
      h('h2', { id: `${id}-title`, text: title }),
    ]),
  );
  return section;
}

/** A horizontally scrolling region that a keyboard can actually reach. */
export function scroller(label: string, ...children: Child[]): HTMLElement {
  return h('div', { class: 'scroller', role: 'region', tabindex: '0', 'aria-label': label }, children);
}
