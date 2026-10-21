(function () {
  'use strict';
  const core = window.VulnPriorityCore;
  if (!core) return;
  const $ = id => document.getElementById(id);
  const form = $('check-form');
  const score = $('cvss');
  const kev = $('kev');
  const error = $('score-error');
  const empty = $('result-empty');
  const content = $('result-content');
  const status = $('result-status');
  const number = new Intl.NumberFormat('ko-KR');
  let selectedCve = null;
  function reset() { content.hidden=true;empty.hidden=false;status.textContent='분석 대기'; }
  function clearSelectedCve() {
    selectedCve = null;
    const selectedBox = $('selected-cve');
    if(selectedBox) selectedBox.hidden = true;
  }
  score.addEventListener('input',function(){error.textContent='';score.removeAttribute('aria-invalid');clearSelectedCve();reset();});
  kev.addEventListener('change',function(){clearSelectedCve();reset();});
  window.addEventListener('vulnpriority:cve-selected',function(event){
    const item = event.detail;
    if(item && /^CVE-\d{4}-\d{4,}$/i.test(String(item.id||''))) selectedCve = item;
  });
  document.querySelectorAll('[data-score]').forEach(button => button.addEventListener('click',function(){score.value=button.dataset.score;error.textContent='';score.removeAttribute('aria-invalid');reset();score.focus();}));
  form.addEventListener('submit', function (event) {
    event.preventDefault();
    const result = core.analyze(score.value,kev.value);
    if (!result.ok) {error.textContent=result.error;score.setAttribute('aria-invalid','true');reset();score.focus();return;}
    error.textContent='';score.removeAttribute('aria-invalid');
    $('result-grade').textContent=result.group.name;
    $('result-grade').dataset.grade=result.group.id;
    $('result-range').textContent=`CVSS v3.1 ${result.group.min.toFixed(1)}–${result.group.max.toFixed(1)}점`;
    $('result-percent').textContent=`${result.rate.toFixed(5)}%`;
    $('result-count').textContent=`${number.format(result.group.n)}건 중 ${number.format(result.group.k)}건 등재`;
    const kevLabel=result.kev==='yes'?'KEV 등재 확인':result.kev==='no'?'KEV 목록 미등재':'KEV 상태 확인 전';
    if(selectedCve) {
      $('current-data-title').textContent='현재 조회된 취약점 정보';
      $('current-data-origin').textContent='NVD 취약점 조회 · CISA KEV 공개 목록 확인 결과';
      $('current-cve-title').textContent=selectedCve.id;
      $('current-cve-detail').textContent='CVSS v3.1 '+result.score.toFixed(1)+'점 ('+result.group.name+') · '+kevLabel;
      $('current-cve-date').textContent=(selectedCve.published?'공개일: '+String(selectedCve.published).slice(0,10)+' · ':'')+
        (selectedCve.kevDate?'KEV 등재일: '+selectedCve.kevDate:'조회 시점에 따라 값이 달라질 수 있습니다.');
    } else {
      $('current-data-title').textContent='직접 입력한 취약점 정보';
      $('current-data-origin').textContent='NVD/CISA 자동 조회 결과가 아닌 수동 입력값입니다.';
      $('current-cve-title').textContent='CVE 조회 정보 없음';
      $('current-cve-detail').textContent='CVSS v3.1 '+result.score.toFixed(1)+'점 ('+result.group.name+') · '+kevLabel;
      $('current-cve-date').textContent='실제 대상 CVE의 점수와 KEV 상태를 확인해 주세요.';
    }
    $('advice-title').textContent=result.title;
    $('advice-text').textContent=result.advice;
    const steps=$('next-steps');steps.replaceChildren();
    result.next.forEach(item=>{const li=document.createElement('li');li.textContent=item;steps.appendChild(li);});
    empty.hidden=true;content.hidden=false;status.textContent='분석 완료';
  });
})();
