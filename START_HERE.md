# BR-B VulnPriority v2 · 제출용 소스 및 검증 기록

- 최종 웹앱: https://vulnpriority-br-b.vercel.app/
- BR-A 포트폴리오: https://project-br-a.vercel.app/#projects
- 논문: https://project-br-a.vercel.app/research.html
- 확인 기록: evidence/BRB_사용자_테스트_확인_기록.md
- 익명 동료 감상: evidence/BRB-C11_익명_동료_피드백.md
- 통과 기준/남길 것: BR-B_최종_체크리스트.md
- 제출 설명: BR-B_제출창_입력문구.md

## 실행 안내

1. BR-B 공식 제출은 Vercel 공개 URL로 진행합니다. 이 ZIP은 현재 GitHub 소스와 보조 증빙을 함께 보관하는 자료입니다.
2. 새 임시 폴더에 압축 해제하고 index.html을 열면 수동 CVSS 입력과 논문 통계를 볼 수 있습니다.
3. 제품명/CVE 온라인 검색은 Vercel 서버리스 API가 필요해 단순 파일 열기만으로 실행되지 않습니다. 검색 시연은 위 공개 URL을 이용하세요.
4. Node.js 18+가 있으면 'node --test tests/*.test.cjs' 로 로직을 검증할 수 있습니다. 실시간 외부 API 가용성을 보장하지 않습니다.

개인정보/출처: 공개 취약점 자료와 사용자 제공 익명 감상만 사용. 논문 집단 통계를 개별 CVE 악용 확률이라 주장하지 않습니다.

스크린샷: 사용자 실제 화면은 채팅에 첨부됨. 이 소스 전용 ZIP에는 이미지가 포함되어 있지 않으며, 확인 내용은 evidence/BRB_사용자_테스트_확인_기록.md에 있습니다.
