'use strict';
/**
 * Public NVD keyword/CVE search, enriched with the official CISA KEV mirror.
 * No personal data, API keys, or input-dependent remote hosts.
 */
const NVD='https://services.nvd.nist.gov/rest/json/cves/2.0';
const KEV='https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json';
const CVE=/^CVE-\d{4}-\d{4,}$/i;
const GROUPS=[['None',0,0],['Low',.1,3.9],['Medium',4,6.9],['High',7,8.9],['Critical',9,10]];
let kevCache=null;
let kevExpires=0;
async function fetchJSON(url,timeout=12000) {
  const r=await fetch(url,{signal:AbortSignal.timeout(timeout),headers:{'Accept':'application/json','User-Agent':'VulnPriority/2.0 (educational vulnerability lookup)'}});
  if(!r.ok) { const e=new Error('공개 데이터 제공기관이 요청을 처리하지 못했습니다.');e.code=r.status;throw e; }
  return r.json();
}
async function getKEV() {
  if(kevCache && Date.now()<kevExpires)return kevCache;
  try {
    const raw=await fetchJSON(KEV,8000);
    if(!Array.isArray(raw.vulnerabilities))throw new Error('KEV 데이터 형식을 확인하지 못했습니다.');
    const records=raw.vulnerabilities;
    const byId=new Map(records.filter(x=>typeof x.cveID==='string').map(x=>[x.cveID.toUpperCase(),x]));
    kevCache={records,byId,version:raw.catalogVersion||null,released:raw.dateReleased||null};
    kevExpires=Date.now()+30*60*1000;
    return kevCache;
  } catch(e) { if(kevCache)return kevCache;return null; }
}
function metric(cve) {
  const entries=Array.isArray(cve?.metrics?.cvssMetricV31)?cve.metrics.cvssMetricV31:[];
  const ordered=entries.filter(m=>Number.isFinite(m?.cvssData?.baseScore))
    .sort((a,b)=>priority(a)-priority(b));
  const selected=ordered[0];
  if(!selected)return null;
  const score=selected.cvssData.baseScore;
  const grade=GROUPS.find(g=>score>=g[1]&&score<=g[2]);
  return {score,grade:grade?.[0]||null,scoreSource:selected.source||'NVD',scoreType:selected.type||'Unknown'};
}
function priority(m) {
  const nvd=String(m.source||'').toLowerCase()==='nvd@nist.gov';
  const primary=String(m.type||'').toLowerCase()==='primary';
  return nvd&&primary?0:primary?1:nvd?2:3;
}
function describe(cve) {
  const d=Array.isArray(cve.descriptions)?cve.descriptions:[];
  const en=d.find(x=>x.lang==='en')||d[0];
  return String(en?.value||'설명 정보가 제공되지 않았습니다.').slice(0,800);
}
function record(cve,catalog) {
  const id=String(cve.id||'').toUpperCase();
  const kev=catalog?.byId.get(id);
  const hasNvdKev=Boolean(cve.cisaExploitAdd);
  const status=kev||hasNvdKev?'yes':catalog?'no':'unknown';
  const score=metric(cve);
  return {id,description:describe(cve),published:cve.published||null,cvssV31:score,kevStatus:status,kevDate:kev?.dateAdded||cve.cisaExploitAdd||null,
    kevTitle:kev?.vulnerabilityName||null,product:kev?.product||null,vendor:kev?.vendorProject||null,
    kevAction:kev?.requiredAction||cve.cisaRequiredAction||null,source:'NVD'};
}
function searchKEV(catalog,q) {
  const lower=q.toLowerCase();
  return catalog.records.filter(x=>[x.cveID,x.vendorProject,x.product,x.vulnerabilityName,x.shortDescription]
    .some(v=>String(v||'').toLowerCase().includes(lower))).slice(0,15)
    .map(x=>({id:x.cveID,description:String(x.shortDescription||x.vulnerabilityName||'').slice(0,800),published:null,
      cvssV31:null,kevStatus:'yes',kevDate:x.dateAdded||null,kevTitle:x.vulnerabilityName||null,
      product:x.product||null,vendor:x.vendorProject||null,kevAction:x.requiredAction||null,source:'CISA KEV (CVSS 확인 전)'}));
}
async function lookup(query,{getNvd=fetchJSON,getKev=getKEV}={}) {
  const q=String(query||'').trim();
  if(q.length<2||q.length>80||/[\r\n\t<>{}]/.test(q))return {status:400,error:'제품명·영문 키워드 또는 올바른 CVE 번호(2~80자)를 입력해 주세요.'};
  const id=CVE.test(q);
  const params=new URLSearchParams();
  if(id)params.set('cveId',q.toUpperCase());else {params.set('keywordSearch',q);params.set('resultsPerPage','15');params.set('noRejected','');}
  const url=NVD+'?'+params.toString();
  const [nv,kv]=await Promise.allSettled([getNvd(url,12000),getKev()]);
  const catalog=kv.status==='fulfilled'?kv.value:null;
  if(nv.status==='fulfilled'&&Array.isArray(nv.value.vulnerabilities)) {
    const entries=nv.value.vulnerabilities.map(row=>record(row.cve||{},catalog));
    return {status:200,query:q,totalResults:nv.value.totalResults??entries.length,items:entries,mode:'nvd',
      kevChecked:Boolean(catalog),kevVersion:catalog?.version||null,
      notice:catalog?null:'KEV 원본 연결이 원활하지 않아 일부 항목은 등재 상태를 확인하지 못했습니다.'};
  }
  if(catalog) {
    const items=searchKEV(catalog,q);
    return {status:200,query:q,totalResults:items.length,items,mode:'kev-fallback',kevChecked:true,kevVersion:catalog.version,
      notice:'현재 NVD 검색에 연결할 수 없어 CISA KEV 목록에서만 검색했습니다. CVSS v3.1 점수는 제공되지 않으며 임의로 채우지 않습니다.'};
  }
  return {status:503,error:'NVD·CISA 공개 데이터에 일시적으로 연결할 수 없습니다. 잠시 후 다시 시도하거나 아래 수동 입력을 이용해 주세요.'};
}
async function handler(req,res) {
  res.setHeader('Content-Type','application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Cache-Control','public, s-maxage=600, stale-while-revalidate=900');
  if(req.method!=='GET'){res.setHeader('Allow','GET');return res.status(405).json({error:'GET 요청만 지원합니다.'});}
  try {const q=typeof req.query?.q==='string'?req.query.q:'';const result=await lookup(q);const {status,...body}=result;return res.status(status).json(body);}
  catch(e){return res.status(500).json({error:'검색 처리 중 오류가 발생했습니다.'});}
}
module.exports=handler;
module.exports.__test={lookup,record,metric,priority,searchKEV};
