const test = require('node:test');
const assert = require('node:assert/strict');
const { SOURCE, GROUPS, parseScore, analyze } = require('../core.js');
test('paper totals and exact severity group rates', () => {
  assert.equal(GROUPS.reduce((a,g)=>a+g.n,0),SOURCE.sampleSize);
  assert.equal(GROUPS.reduce((a,g)=>a+g.k,0),SOURCE.kevTotal);
  assert.deepEqual(GROUPS.map(g=>[g.name,g.n,g.k]),[['None',1,0],['Low',626,1],['Medium',15993,13],['High',11251,70],['Critical',4231,65]]);
  assert.equal(analyze('9.8','yes').rate.toFixed(5),'1.53628');
  assert.equal(analyze('6.5','no').rate.toFixed(5),'0.08129');
  assert.equal((65/4231)/(13/15993)>18.89,true);
});
test('severity boundaries',()=>{
  for (const [input,expected] of [['0','None'],['0.1','Low'],['3.9','Low'],['4.0','Medium'],['6.9','Medium'],['7.0','High'],['8.9','High'],['9.0','Critical'],['10.0','Critical']]) assert.equal(parseScore(input).group.name,expected);
});
test('invalid input always fails safely',()=>{
  for (const input of ['', ' ', '-1','11','NaN','Infinity','3.95','9.99','abc','<script>alert(1)</script>',null,undefined])assert.equal(analyze(input,'yes').ok,false,String(input));
  assert.equal(analyze('9.8','bad').ok,false);
});
test('KEV status changes guidance, never labels absence as safe',()=>{
  assert.match(analyze('7.5','yes').advice,/실제 악용/);
  assert.match(analyze('7.5','no').advice,/판단할 수 없습니다/);
  assert.match(analyze('7.5','unknown').advice,/확인/);
  assert.doesNotMatch(analyze('7.5','no').advice,/안전합니다/);
});
