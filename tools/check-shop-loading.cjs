const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, '..', 'lion-forge-shop.html'), 'utf8');
const start = html.indexOf('async function loadShopProducts');
const source = html.slice(start, html.indexOf('</script>', start));
const product = {id:1,name:'RETATRUTIDE',variants:[{label:'10MG',price:30,stock:2}]};
const ok = () => ({ok:true,json:async()=>({list:[product]})});
function harness(fetch) {
  const states = [];
  const context = vm.createContext({products:[],nextId:1,catalogRequestPending:false,catalogLoadState:'loading',
    location:{protocol:'https:'},fetch,AbortController,setTimeout:(fn)=>setTimeout(fn,15),clearTimeout,
    console:{warn(){}},renderProducts:()=>states.push(context.catalogLoadState)});
  vm.runInContext(source,context);
  return {context,states};
}
(async()=>{
  let resolve;
  let calls = 0;
  let h = harness(()=>{calls++;return new Promise(r=>{resolve=r;});});
  const pending = h.context.loadShopProducts();
  assert.deepEqual(h.states,['loading']);
  await h.context.loadShopProducts();
  assert.equal(calls,1,'duplicate loads are suppressed');
  resolve(ok()); await pending;
  assert.equal(h.context.catalogLoadState,'ready');
  assert.equal(h.context.products.length,1);
  calls = 0;
  h = harness(async()=>{if(++calls===1)throw Error('transient network failure');return ok();});
  await h.context.loadShopProducts();
  assert.equal(calls,2);assert.equal(h.context.catalogLoadState,'ready');
  h = harness(async()=>({ok:false,status:503}));
  await h.context.loadShopProducts();assert.equal(h.context.catalogLoadState,'error');
  h.context.fetch = async()=>ok();await h.context.loadShopProducts();
  assert.equal(h.context.catalogLoadState,'ready','manual retry recovers');
  h = harness(async()=>({ok:true,json:async()=>({error:'no list'})}));
  await h.context.loadShopProducts();assert.equal(h.context.catalogLoadState,'error');
  h = harness((_url,{signal})=>new Promise((_,reject)=>signal.addEventListener('abort',()=>reject(Error('timeout')))));
  await h.context.loadShopProducts();assert.equal(h.context.catalogLoadState,'error','hung requests are bounded');
  h = harness(async()=>({ok:true,json:async()=>({list:[]})}));
  await h.context.loadShopProducts();assert.equal(h.context.catalogLoadState,'ready');assert.equal(h.context.products.length,0);
  console.log('PASS: loading state, duplicate prevention, transient failure retry, HTTP errors, manual recovery, malformed responses, timeouts, and empty catalog.');
})().catch(error=>{console.error(error);process.exitCode=1;});
