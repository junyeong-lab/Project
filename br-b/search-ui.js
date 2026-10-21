(function(){
 'use strict';
 const searchForm=document.getElementById('lookup-form');
 if(!searchForm)return;
 const input=document.getElementById('lookup-query');
 const submit=document.getElementById('lookup-submit');
 const feedback=document.getElementById('lookup-feedback');
 const results=document.getElementById('lookup-results');
 const selected=document.getElementById('selected-cve');
 const score=document.getElementById('cvss');
 const kev=document.getElementById('kev');
 let active=null;
 function el(tag,cls,txt){
   const n=document.createElement(tag);
   if(cls)n.className=cls;
   if(txt!==undefined)n.textContent=String(txt);
   return n;
 }
 function kevLabel(s){return s==='yes'?'KEV 등재 확인':s==='no'?'KEV 목록 미등재':'KEV 확인 불가';}
 function selectItem(item){
   if(!/^CVE-\d{4}-\d{4,}$/i.test(item.id))return;
   const hasScore=item.cvssV31&&Number.isFinite(item.cvssV31.score);
   score.value=hasScore?Number(item.cvssV31.score).toFixed(1):'';
   kev.value=['yes','no','unknown'].includes(item.kevStatus)?item.kevStatus:'unknown';
   score.dispatchEvent(new Event('input',{bubbles:true}));
   kev.dispatchEvent(new Event('change',{bubbles:true}));
   selected.replaceChildren();
   const h=el('h4',null,item.id+' · '+(item.cvssV31?.grade||'CVSS v3.1 점수 미제공'));
   const source=el('p',null,(hasScore?'CVSS v3.1 '+item.cvssV31.score.toFixed(1)+'점 · ':'CVSS v3.1 점수 미제공 · ')+kevLabel(item.kevStatus)+(item.kevDate?' · KEV 등재일 '+item.kevDate:''));
   const description=el('p','selected-description',item.description);
   const caution=el('p','selected-description','주의: 현재 NVD/CISA 정보와 2024년 논문의 고정 분석 표본은 조회 시점·연도가 다를 수 있습니다. 연구 비율은 이 CVE의 악용 확률이 아닙니다.');
   const link=el('a',null,'NVD 취약점 원문 보기 ↗');
   link.href='https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(item.id);
   link.target='_blank';link.rel='noopener noreferrer';
   selected.append(h,source,description,caution,link);
   selected.hidden=false;
   feedback.textContent=item.id+' 선택 완료. '+(hasScore?'점수와 KEV 상태를 아래 입력란에 채웠습니다.':'CVSS v3.1 점수가 없어 아래 수동 점수는 비워 두었습니다.');
   document.getElementById('check-form').scrollIntoView({behavior:'smooth',block:'center'});
   if(hasScore)score.focus({preventScroll:true});
 }
 function render(items,meta){
   results.replaceChildren();
   if(!items.length){results.hidden=true;feedback.textContent='검색 결과가 없습니다. 영문 제품명이나 다른 키워드로 다시 검색해 주세요.';return;}
   const heading=el('p','results-heading',items.length+'개 결과 표시'+(meta.totalResults>items.length?' · 전체 '+meta.totalResults.toLocaleString('ko-KR')+'건 중 일부':''));
   results.appendChild(heading);
   items.forEach(item=>{
     const b=el('button','cve-hit');
     b.type='button';
     const top=el('span','hit-top');
     top.append(el('strong',null,item.id),el('span','hit-score',item.cvssV31?'CVSS v3.1 '+Number(item.cvssV31.score).toFixed(1)+' · '+item.cvssV31.grade:'CVSS v3.1 확인 필요'));
     const d=el('span','hit-desc',item.description);
     const foot=el('span','hit-foot',kevLabel(item.kevStatus)+(item.published?' · 공개일 '+String(item.published).slice(0,10):'')+' · 선택하여 적용하기 →');
     b.append(top,d,foot);
     b.addEventListener('click',()=>selectItem(item));
     results.appendChild(b);
   });
   results.hidden=false;
   let note=meta.mode==='kev-fallback'?'NVD 연결이 원활하지 않아 CISA KEV 목록의 결과만 표시합니다.':meta.totalResults.toLocaleString('ko-KR')+'건 검색됨. 필요한 CVE를 골라 주세요.';
   if(meta.notice)note+=' '+meta.notice;
   feedback.textContent=note;
 }
 searchForm.addEventListener('submit',async(event)=>{
   event.preventDefault();
   const q=input.value.trim();
   if(q.length<2||q.length>80){feedback.textContent='영문 제품명 또는 CVE 번호를 2~80자로 입력해 주세요.';input.focus();return;}
   if(active)active.abort();
   const controller=new AbortController();
   active=controller;
   submit.disabled=true;
   submit.textContent='검색 중…';
   results.hidden=true;
   feedback.textContent='NVD/CISA 공개 자료를 확인하고 있습니다.';
   const timeout=setTimeout(()=>controller.abort(),19000);
   try{
     const response=await fetch('/api/search?q='+encodeURIComponent(q),{signal:controller.signal,headers:{Accept:'application/json'}});
     const data=await response.json().catch(()=>({error:'검색 응답을 해석할 수 없습니다.'}));
     if(!response.ok)throw new Error(data.error||'현재 검색할 수 없습니다.');
     render(Array.isArray(data.items)?data.items:[],data);
   }catch(error){
     if(controller.signal.aborted && active!==controller)return;
     feedback.textContent=controller.signal.aborted?'연결 시간이 초과됐습니다. 다시 검색하거나 직접 입력을 사용해 주세요.':error.message||'검색 연결에 실패했습니다.';
   }finally{
     clearTimeout(timeout);
     if(active===controller){active=null;submit.disabled=false;submit.textContent='취약점 검색 →';}
   }
 });
 document.querySelectorAll('[data-query]').forEach(btn=>btn.addEventListener('click',()=>{
   input.value=btn.dataset.query;
   searchForm.requestSubmit();
 }));
})();