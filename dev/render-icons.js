// Renders the icons of the web UI (resources/ui/app.js, ICONS) as PNGs
// for the desktop UI (SWT): resources/icons/<name>.png (16 px),
// <name>@2x.png (32 px), <name>-32.png / <name>-32@2x.png (blue) and <name>-w32*.png (white, dialog header).
// Usage: PW=$(npm root -g)/playwright node dev/render-icons.js
const fs = require('fs');
const path = require('path');
const { chromium } = require(process.env.PW || 'playwright');

const src = fs.readFileSync(path.join(__dirname, '../resources/ui/app.js'), 'utf8');
const block = src.slice(src.indexOf('const ICONS = {'), src.indexOf('};', src.indexOf('const ICONS = {')) + 2);
const ICONS = new Function(block + ' return ICONS;')();
const out = path.join(__dirname, '../resources/icons');
fs.mkdirSync(out, { recursive: true });

(async () => {
  const b = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
  const variants = [
    ['', 16, 1, '#2b2b2b', 1.4], ['@2x', 16, 2, '#2b2b2b', 1.4],
    ['-32', 32, 1, '#0067c0', 1.4], ['-32@2x', 32, 2, '#0067c0', 1.4],
    // white for the dark dialog header (KeePass style "Dark")
    ['-w32', 32, 1, '#ffffff', 1.5], ['-w32@2x', 32, 2, '#ffffff', 1.5],
  ];
  for (const [suffix, size, scale, color, sw] of variants) {
    const p = await b.newPage({ viewport: { width: size, height: size }, deviceScaleFactor: scale });
    for (const [name, body] of Object.entries(ICONS)) {
      await p.setContent('<html><body style="margin:0;background:transparent">' +
        `<svg width="${size}" height="${size}" viewBox="0 0 16 16" style="display:block;stroke:${color};fill:none;stroke-width:${sw};stroke-linecap:round;stroke-linejoin:round">${body}</svg></body></html>`);
      await p.screenshot({ path: path.join(out, name + suffix + '.png'), omitBackground: true, clip: { x: 0, y: 0, width: size, height: size } });
    }
    await p.close();
  }
  await b.close();
  console.log(Object.keys(ICONS).length + ' icons');
})();
