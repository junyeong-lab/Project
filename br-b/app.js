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
  function reset() { content.hidden=true;empty.hidden=false;status.textContent='분석 대기'; }
  score.addEventListener('input',function(){error.textContent='';score.removeAttribute('aria-invalid');reset();});
  kev.addEventListener('change',reset);
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
    $('advice-title').textContent=result.title;
    $('advice-text').textContent=result.advice;
    const steps=$('next-steps');steps.replaceChildren();
    result.next.forEach(item=>{const li=document.createElement('li');li.textContent=item;steps.appendChild(li);});
    empty.hidden=true;content.hidden=false;status.textContent='분석 완료';
  });
})();
