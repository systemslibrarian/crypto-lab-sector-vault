import './style.css';
import { h } from './ui/dom.js';
import { createState, type AppState, type LabContext } from './ui/state.js';
import { heroBlock, introCard } from './ui/panelIntro.js';
import { mountDiskPanel } from './ui/panelDisk.js';
import { mountBitFlipPanel } from './ui/panelBitFlip.js';
import { mountRelocatePanel } from './ui/panelRelocate.js';
import { mountWatermarkPanel } from './ui/panelWatermark.js';
import { mountComparisonPanel } from './ui/panelComparison.js';
import { mountLogPanel, scopeCard } from './ui/panelScope.js';

const app = document.getElementById('app');
if (!app) throw new Error('#app is missing from index.html');

let state: AppState = createState();

const panels: { root: HTMLElement; refresh: () => void }[] = [];

const ctx: LabContext = {
  get state() {
    return state;
  },
  refresh() {
    for (const panel of panels) panel.refresh();
  },
  record(message: string) {
    state.log.unshift(message);
    ctx.refresh();
  },
  reset() {
    state = createState();
    state.log.unshift('Reformatted the volume with fresh session keys.');
    ctx.refresh();
  },
};

const disk = mountDiskPanel(ctx);
const flip = mountBitFlipPanel(ctx);
const relocate = mountRelocatePanel(ctx);
const watermark = mountWatermarkPanel(ctx);
const comparison = mountComparisonPanel();
const log = mountLogPanel(ctx);
panels.push(disk, flip, relocate, watermark, comparison, log);

const main = h('main', {}, [
  introCard(),
  disk.root,
  flip.root,
  relocate.root,
  watermark.root,
  comparison.root,
  log.root,
  scopeCard(),
]);

app.append(
  heroBlock(),
  main,
  h('footer', { class: 'scripture-footer' }, [
    h('p', {
      text: 'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31',
    }),
  ]),
);

ctx.refresh();
