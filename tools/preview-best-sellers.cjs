// Local-only visual preview. Product data is the shop's existing preview snapshot.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');
const types = {'.html':'text/html; charset=utf-8','.webp':'image/webp','.png':'image/png'};
http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  if (req.method !== 'GET') { res.writeHead(405).end(); return; }
  if (url.pathname === '/api/products') {
    const html = fs.readFileSync(path.join(root, 'lion-forge-shop.html'), 'utf8');
    const literal = html.match(/const LOCAL_PREVIEW_PRODUCTS = (\[[\s\S]*?\n\]);/)[1];
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify({list:vm.runInNewContext(literal)})); return;
  }
  if (url.pathname.startsWith('/api/')) {
    res.writeHead(401, {'Content-Type':'application/json'}).end('{"error":"Local preview: signed out"}'); return;
  }
  const file = path.resolve(root, '.' + decodeURIComponent(url.pathname));
  if (!file.startsWith(root + path.sep) || !types[path.extname(file)]) { res.writeHead(404).end(); return; }
  fs.readFile(file, (err, data) => {
    if (err) {res.writeHead(404).end(); return;}
    res.writeHead(200, {'Content-Type':types[path.extname(file)],'Cache-Control':'no-store'}).end(data);
  });
}).listen(4173, '127.0.0.1', () => console.log('Shop preview: http://127.0.0.1:4173/lion-forge-shop.html'));
