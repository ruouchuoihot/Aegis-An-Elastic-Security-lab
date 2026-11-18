// Docs-only PNG renderer. Runtime services do not depend on Node or resvg.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const { Resvg } = require(resolve(root, 'lab/runtime/docs-render/node_modules/@resvg/resvg-js'));
for (const name of ['AEGIS-Design', 'Telemetry-Detection', 'AI-Investigation', 'Deployment-Architecture']) {
  const svg = readFileSync(resolve(root, `docs/assets/${name}.svg`));
  const renderer = new Resvg(svg, { font: { loadSystemFonts: true, defaultFontFamily: 'Segoe UI' } });
  const png = renderer.render().asPng();
  writeFileSync(resolve(root, `docs/assets/${name}.png`), png);
  if (name === 'AEGIS-Design') {
    mkdirSync(resolve(root, 'assets'), { recursive: true });
    writeFileSync(resolve(root, `assets/${name}.svg`), svg);
    writeFileSync(resolve(root, `assets/${name}.png`), png);
  }
}
console.log('Rendered 4 PNG architecture diagrams.');
