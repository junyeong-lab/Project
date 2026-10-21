const test=require('node:test');
const assert=require('node:assert/strict');
const {__test}=require('../api/search.js');
const sample={id:'CVE-2024-3094',published:'2024-03-29',descriptions:[{lang:'en',value:'xz upstream package vulnerability'}],metrics:{cvssMetricV31:[{source:'redhat.com',type:'Primary',cvssData:{baseScore:10.0}}]}};
const item={cveID:'CVE-2024-3094',vendorProject:'Tukaani',product:'XZ Utils',vulnerabilityName:'xz vulnerability',dateAdded:'2024-04-01',shortDescription:'Supply-chain vulnerability',requiredAction:'Follow advisory.'};
const catalog={records:[item],byId:new Map([[item.cveID,item]]),version:'test'};
test('CVSS v3.1 selection preserves paper score hierarchy',()=>{
 const x=structuredClone(sample);
 x.metrics.cvssMetricV31.push({source:'nvd@nist.gov',type:'Primary',cvssData:{baseScore:9.0}});
 assert.equal(__test.metric(x).score,9.0);
 assert.equal(__test.metric(sample).grade,'Critical');
});
test('CISA KEV known / absent / unavailable distinguished',()=>{
 assert.equal(__test.record(sample,catalog).kevStatus,'yes');
 assert.equal(__test.record({...sample,id:'CVE-2024-55555'},catalog).kevStatus,'no');
 assert.equal(__test.record({...sample,id:'CVE-2024-55555'},null).kevStatus,'unknown');
});
test('keyword and CVE search via NVD mocked, no external dependency',async()=>{
 const fakeNvd=async()=>({totalResults:1,vulnerabilities:[{cve:sample}]});
 const opts={getNvd:fakeNvd,getKev:async()=>catalog};
 let result=await __test.lookup('XZ Utils',opts);
 assert.equal(result.status,200);assert.equal(result.items[0].cvssV31.score,10.0);
 result=await __test.lookup('CVE-2024-3094',opts);
 assert.equal(result.status,200);assert.equal(result.items[0].kevStatus,'yes');
});
test('NVD error retains CISA KEV fallback without inventing scores',async()=>{
 const result=await __test.lookup('XZ',{getNvd:async()=>{throw new Error('429')},getKev:async()=>catalog});
 assert.equal(result.status,200);assert.equal(result.mode,'kev-fallback');
 assert.equal(result.items[0].cvssV31,null);assert.equal(result.items[0].kevStatus,'yes');
});
test('unavailable sources and bad queries fail safely',async()=>{
 assert.equal((await __test.lookup('?',{})).status,400);
 assert.equal((await __test.lookup('<script>',{})).status,400);
 const result=await __test.lookup('OpenSSH',{getNvd:async()=>{throw new Error('blocked')},getKev:async()=>null});
 assert.equal(result.status,503);
});
