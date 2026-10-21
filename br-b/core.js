/* T10 paper-derived fixed descriptive statistics. Not a predictive model. */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.VulnPriorityCore = api;
})(typeof window !== 'undefined' ? window : null, function () {
  'use strict';
  const SOURCE = Object.freeze({title:'2024년 공개 취약점의 CVSS v3.1 심각도와 CISA KEV 등재 비율의 연관성 분석',publishedYear:2024,kevAsOf:'2026-10-16',sampleSize:32102,kevTotal:149});
  const GROUPS = Object.freeze([
    Object.freeze({id:'none',name:'None',min:0,max:0,n:1,k:0}),
    Object.freeze({id:'low',name:'Low',min:0.1,max:3.9,n:626,k:1}),
    Object.freeze({id:'medium',name:'Medium',min:4,max:6.9,n:15993,k:13}),
    Object.freeze({id:'high',name:'High',min:7,max:8.9,n:11251,k:70}),
    Object.freeze({id:'critical',name:'Critical',min:9,max:10,n:4231,k:65})
  ]);
  const NEXT = Object.freeze([
    '대상 자산이 실제 영향을 받는 버전인지 확인합니다.',
    '인터넷 노출도와 업무 중요도를 확인합니다.',
    '공식 권고문과 패치·완화 가능성을 검토합니다.'
  ]);
  function parseScore(raw) {
    const text = String(raw == null ? '' : raw).trim();
    if (!/^(?:10(?:\.0)?|[0-9](?:\.[0-9])?)$/.test(text)) return {ok:false,error:'0.0부터 10.0까지, 소수 첫째 자리까지 입력해 주세요.'};
    const value = Number(text);
    const group = GROUPS.find(g => value >= g.min && value <= g.max);
    if (!group) return {ok:false,error:'유효한 CVSS v3.1 점수 구간을 찾을 수 없습니다.'};
    return {ok:true,value,group};
  }
  function analyze(score, kev) {
    const parsed = parseScore(score);
    if (!parsed.ok) return parsed;
    if (!['yes','no','unknown'].includes(kev)) return {ok:false,error:'KEV 등재 여부를 선택해 주세요.'};
    let title, advice;
    if (kev === 'yes') {title='KEV 등재 확인 — 대응 검토 필요';advice='실제 악용 근거가 알려진 취약점으로 확인한 상태입니다. 자산 영향 여부와 공식 조치 지침을 우선 검토하세요.';}
    else if (kev === 'no') {title='KEV 미등재 — 안전 판정 불가';advice='KEV에 없다는 이유만으로 악용되지 않았다고 판단할 수 없습니다. 자산 노출도, 중요도, 공개 권고문을 함께 확인하세요.';}
    else {title='KEV 확인 전 — 공식 목록 확인 권장';advice='심각도만으로 악용 여부를 판단하지 말고, 공식 CISA KEV 목록에서 해당 CVE의 등재 여부를 먼저 확인하세요.';}
    return {ok:true,score:parsed.value,group:parsed.group,rate:parsed.group.k/parsed.group.n*100,kev,title,advice,next:NEXT};
  }
  return Object.freeze({SOURCE,GROUPS,parseScore,analyze});
});
