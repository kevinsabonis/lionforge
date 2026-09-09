const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'lion-forge-shop.html'), 'utf8');
for (const [,script] of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)) new vm.Script(script);
const context = vm.createContext({selectedVariants:{}, quantities:{}});
vm.runInContext(html.slice(html.indexOf('const FEATURED_IDS'), html.indexOf('function selectVariant')), context);
for (const [id, strengths] of [[1,['10MG','20MG']],[4,['10MG','20MG']],[10,['500MG']],[13,['10MG','20MG']]]) {
  for (const strength of strengths) {
    const filename = context.featuredVialImage(id,strength);
    assert(fs.existsSync(path.join(root,filename)), `Missing image: ${filename}`);
    assert.equal(context.featuredVialImage(id,strength.toLowerCase().replace('mg',' mg')),filename);
  }
}
assert.equal(context.featuredVialImage(1,'30MG'),null);
// Reordering inventory must not put a 10mg image on the selected 20mg variant.
const product = {id:1,name:'RETATRUTIDE',variants:[{label:'20MG',price:40,stock:0},{label:'10MG',price:30,stock:5}]};
const available = context.renderCard(product,true);
assert.match(available,/retatrutide-10mg-v1.webp/);
assert.match(available,/\$30\.00/);
assert.match(available,/20MG — Out of stock/);
assert(!available.includes('class="add-btn" disabled'));
assert.equal(context.selectedVariants[1],1,'cart uses the displayed in-stock variant');
assert.equal(context.defaultVariantIndex({variants:[{stock:0},{stock:0}]}),0);
assert.equal(context.defaultVariantIndex({variants:[{stock:2},{stock:5}]}),0);
context.selectedVariants[1] = 0; // A customer can still inspect a sold-out size.
const rendered = context.renderCard(product,true);
assert.match(rendered,/retatrutide-20mg-v1.webp/);
assert.match(rendered,/\$40\.00/);
assert.match(rendered,/class="add-btn" disabled/);
assert(!context.renderCard(product,false).includes('vial-image-wrap'));
product.variants[0].label = '30MG';
const unknown = context.renderCard(product,true);
assert.match(unknown,/Image coming soon for this strength/);
assert(!unknown.includes('retatrutide-10mg-v1.webp'));
console.log('PASS: inline script syntax, seven image files, label normalization, reordered variants, unknown strengths, sold-out state, and non-featured cards.');
