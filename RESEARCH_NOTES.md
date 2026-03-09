# SVO 의미 제약 기반 공격 명령어 자가 복구 — 연구 노트

> 논문 작성용 진행 기록. 실험 결과, 개선점, 한계점 누적.

---

## 연구 주제
**"SVO 의미 제약 기반 공격 명령어 자가 복구 시 생성 명령어 특성 분석"**
- 자연어 CTI 보고서 → MITRE ATT&CK 기법 추출 → SVO 트리플릿 → Caldera Ability 생성 → ReAct 자율 수정
- 핵심 질문: SVO 의미 제약이 자가 복구 과정에서 생성되는 명령어의 특성에 어떤 영향을 주는가?

---

## 환경
- 플랫폼: MITRE Caldera (adversary emulation)
- 에이전트: WS01 (Windows 11, User 권한, paw=nbtlvt)
- C2 관리 주소: 192.168.50.19:8888 (Python REST API)
- C2 에이전트 주소: 192.168.40.112:8888 (에이전트 접근, 망분리)
- LLM: gpt-oss:120b (Ollama, 192.168.50.252:11434)

---

## 세션별 실험 결과

### Thief 시나리오 (APT29-style 데이터 수집/유출)
기법: T1074.001, T1005, T1560.001, T1041 (5 links)

| 세션 | 초기 성공 | 최종 성공 | 라운드 | 주요 이슈 |
|------|---------|---------|------|----------|
| 164744 | ? | ? | ? | get_link_output 버그 (항상 "True"), 진동 문제 |
| 181108 | 3/5 | - | - | 실제 에러 메시지 노출 확인, T1005 false positive 발견 |
| 184815 | 3/5 | - | - | C2 주소 오류 (192.168.50.19 vs 192.168.40.112) |
| 224602 | 3/5 | 5/5 | 3 | try-catch false positive, `curl.exe` HTTP 500 무시 |
| 230834 | 2/5 | 5/5 | 1 | 멀티라인 Caldera 줄바꿈 제거 버그, 빈 fix 생성 문제 |
| 232330 | 3/5 | 5/5 | 1 | **최초 신뢰 가능한 5/5 성공**, `#{server}/#{paw}` 업로드 동작 확인 |

### APT3 시나리오 (Gothic Panda, 12 기법)
기법: T1588.003, T1195, T1053.005, T1543.003, T1068, T1027.013, T1556.002, T1057, T1021.001, T1119, T1573.002, T1048.003

| 세션 | 초기 성공 | 최종 성공 | 라운드 | 조건 |
|------|---------|---------|------|------|
| 233432 | 2/12 (17%) | 9/12 (75%) | 3 | failure_type 힌트 있음 |
| 002017 | 4/12 (33%) | 8/12 (67%) | 3 | **failure_type 힌트 제거** |

---

## 개선된 점 (시계열)

### 인프라/버그 수정
- **get_link_output() 수정**: Caldera API 응답에서 `result["result"]` (base64 stdout) 읽도록 수정. 이전에는 `link.output` (boolean) 읽어 항상 "True" 반환
- **진동(oscillation) 방지**: prev_attempts에 original_command도 포함 (fixed_command만 있으면 원래 명령어 재생성 가능)
- **C2 주소 분리**: `CALDERA_CONFIG["url"]` (관리용) vs `CALDERA_CONFIG["agent_url"]` (에이전트용, 망분리 환경)
- **`#{server}`, `#{paw}` 변수 활용**: Caldera 내장 변수로 업로드 인증 해결. X-Request-Id 헤더 필수
- **멀티라인 금지**: Caldera 실행 시 `\n` 제거 → 세미콜론 단일 라인 강제

### 프롬프트 설계
- **try-catch 제거**: catch는 terminating error만 잡아 false positive 다수 → 제거
- **형식 강요 완화**: `$ErrorActionPreference`, `Write-Output` 의무화 → 제거 (LLM 자유도 증가)
- **업로드 패턴 명시**: HttpClient + X-Request-Id + Add-Type 패턴을 프롬프트에 단일 라인으로 제공

### ReAct 성능
- Round 당 평균 수정 성공률 향상
- APT3: 초기 17% → 최종 75% (3라운드)
- SVO 의미 보존하면서 도구 대체 사례 확인 (T1021.001: mstsc timeout → Start-Process 비동기)

---

## 한계점

### 구조적 한계 (코드/설계)
1. **false positive 잔존**: `ForEach-Object` 빈 루프 = exit 0. 명령어 논리적 성공 여부를 exit code만으로 판단 불가
2. **failure_type 분류 정확도 낮음**: 실험 기법 중 60-70%가 `unknown` 분류. 한국어 에러 메시지, 신규 에러 패턴 미매칭
3. **멀티라인 명령어 불가**: Caldera 플랫폼 제약. 긴 스크립트 표현이 어려움
4. **빈 fix 생성**: LLM이 해결책 없을 때 `""` 반환 → 파이프라인이 이를 처리하지 못함

### 환경적 한계
5. **권한 제약**: User 권한으로 서비스 생성(T1543.003), Password Filter DLL 등록(T1556.002) 불가. ReAct로 우회 불가능한 구조적 한계
6. **Caldera payload 의존**: `'File key was not provided'` — 없는 파일 참조 시 실패. 실제 공격과 달리 Caldera payload 목록에 의존
7. **C2 업로드 구조**: `/file/upload`는 agent-authenticated 엔드포인트. 일반 HTTP 클라이언트로 접근 시 X-Request-Id 헤더 필요
8. **GUI 프로세스 Timeout**: mstsc, msconfig 등 GUI 앱은 60초 내 종료 안 됨 → 강제 종료

### 연구 관점 한계
9. **SVO focus 분류 일관성**: `svo_focus` 필드가 실제로 어떤 SVO 요소를 수정했는지 검증 어려움
10. **성공의 의미**: 많은 경우 "성공"이 실제 공격 행위 수행 vs 에러 없이 종료(false positive)를 구분하기 어려움

---

## 패턴 매칭 (failure_type 분류) 설계 메모

### 현황
- 코드 기반 string contains 매칭 (`react_agent.py::FAILURE_PATTERNS`)
- 매칭 실패 시 `unknown` → LLM 프롬프트에 힌트 없이 전달

### 미매칭 패턴 (관찰됨)
| 에러 메시지 | 올바른 분류 | 현재 분류 |
|-----------|-----------|---------|
| `'File key was not provided'` | object_failure | unknown |
| `'Access to the path ... is denied'` | subject_failure | unknown |
| `ZipArchiveHelper: The process cannot access the file` | object_failure | unknown |
| `fork/exec ...WindowsPowerShell...` | env_failure | unknown |
| `Timeout reached` | env_failure | unknown |
| 한국어 에러 (`경로가 없거나 유효한 파일 시스템 경로가 아닙니다`) | object_failure | unknown |

### 설계 결정 (2026-03-09)
**failure_type = 분석용 레이블 O / LLM 프롬프트 힌트 X**

- `classify_failure()` 유지: 코드 기반 패턴 매칭, 결과 JSON에 기록
- LLM 프롬프트에서 failure_type 힌트 완전 제거:
  - `## FAILURE CLASSIFICATION: {failure_type}` 라인 삭제
  - "Fix strategies by failure type" 섹션 삭제 (타입→전략 간접 힌트)
  - `attempts_text`의 `Type:` 라인 삭제

**이유**: LLM이 failure_type 힌트를 보면 수정 방향이 힌트 기반인지 SVO 기반인지 구분 불가.
순수하게 "SVO + 에러 메시지만으로 자가복구"하는 상황을 만들어야 연구 주제 성립.
failure_type은 실험 결과 사후 분석(성공률, SVO요소 변화)에 활용.

### 미매칭 패턴 (관찰됨, 개선 여지)
| 에러 메시지 | 올바른 분류 | 현재 분류 |
|-----------|-----------|---------|
| `'File key was not provided'` | object_failure | unknown |
| `'Access to the path ... is denied'` | subject_failure | unknown |
| `ZipArchiveHelper: The process cannot access the file` | object_failure | unknown |
| `fork/exec ...WindowsPowerShell...` | env_failure | unknown |
| `Timeout reached` | env_failure | unknown |
| 한국어 에러 (`경로가 없거나 유효한 파일 시스템 경로가 아닙니다`) | object_failure | unknown |

---

## 주요 관찰 사례 (논문용)

### T1588.003 — 동사 전환 사례 (002017 Round 3)
- 원래 SVO: agent **obtain** code-signing certificate (from C2 download)
- Round 1~2: file_key 파라미터명 추측 반복 실패
- Round 3: `New-SelfSignedCertificate` 로컬 생성으로 전환
- SVO 분석: V(obtain)의 수단 변화(download→generate), O(certificate)는 유지
- **의의**: SVO 의미 보존하면서 도구 수준에서 자가 적응. failure_type 힌트 없이 달성.

### T1543.003 — 빈 fix 패턴 (구조적 한계)
- subject_failure: 서비스 생성은 admin 필수
- Round 1: LocalService 계정으로 우회 시도 → 실패
- Round 2~3: `fixed_command: ""` → LLM이 한계 인식하고 포기
- **의의**: ReAct가 무한 시도하지 않고 포기하는 메커니즘 필요 (현재 빈 문자열로 implicit)

### failure_type 힌트 제거 효과 (233432 vs 002017)
| | 힌트 있음(233432) | 힌트 없음(002017) |
|-|-----------------|-----------------|
| 초기 성공률 | 17% | 33% |
| 최종 성공률 | 75% | 67% |
| T1053.005 | ✓ (Round 3) | ✗ (3라운드 실패) |
| T1588.003 | ✓ | ✓ (Round 3, 동사 전환) |
- **해석**: 힌트 없으면 subject_failure 기법(T1053.005)에서 경로가 길어짐.
  반면 초기 성공률은 높음(ability 생성 품질 개선 효과 중첩 가능).
  T1588.003은 힌트 없이도 Round 3에서 창의적 V 전환으로 성공.

---

## 다음 실험 과제
- [ ] failure_type 분류 개선 (패턴 보강 or LLM 위임 결정)
- [ ] false positive 감지 로직 (빈 루프, 존재하지 않는 파일 처리)
- [ ] APT29 시나리오 실험
- [ ] --force-generate 모드(SVO 전용) vs 기존 ability 혼합 비교 실험
- [ ] SVO focus별 명령어 특성 정량 분석
- [ ] 빈 fix(`""`) 처리 로직 추가 (파이프라인이 조기 종료하도록)
- [ ] T1053.005 반복 실패 원인 규명 (태스크명 충돌 vs 힌트 부재)
