## 연구 질문

> *동일한 CTI 시나리오를 반복 실행할 때 LLM 기반 SVO 추출 결과가 달라지고,
> 그 차이가 초기 Ability 실행 성공률과 ReAct 자가복구 성공률을 결정하는가?*

---

## 배경 및 동기

### 파이프라인 구조

```
CTI 시나리오 (.md)
  → Phase 1: LLM 파싱 (ATT&CK 기법 추출)
  → Phase 2.5: SVO 추출 (Subject-Verb-Object 트리플릿)
  → Phase 3: Ability 생성 (SVO → Caldera PowerShell 명령어)
  → Phase 4~5: Operation 실행
  → Phase 6: ReAct Loop (실패 시 자율 명령어 수정, 최대 3라운드)
```

### 관찰된 문제

동일 시나리오를 반복 실행했을 때 SVO 추출 결과가 달라지고(LLM 비결정성), 그 결과 생성되는 명령어 전략이 달라져 성공률에 차이가 발생한다. 특히:

- **초기 성공률**: 63% ~ 87% (동일 시나리오, APT29 30기법)
- **최종 성공률**: 87% ~ 97% (ReAct 3라운드 후)

단순히 "처음에 실패해도 ReAct가 고친다"가 아니라, SVO V 방향이 ReAct로도 복구 불가능한 명령어 구조를 만들어내는 경우가 있다.

---

## 실험 환경

| 항목 | 값 |
|------|-----|
| 시나리오 | APT29 시나리오1 (30 MITRE ATT&CK 기법, T1529 제외) |
| LLM | gpt-oss:120b |
| ReAct 라운드 | 최대 3회 |
| 옵션 | SVO 기반 신규 생성, Caldera 기존 ability 무시 |

---

## 세션별 결과 (APT29, 동일 시나리오 3회)

| 세션 | 초기 성공 | R1 후 | R2 후 | R3 후 (최종) | 영구 실패 기법 |
|------|---------|------|------|------------|--------------|
| 143322 | 26/30 (87%) | — | — | **29/30 (97%)** | T1003 |
| 171757 | 19/30 (63%) | 23/30 | 26/30 | **26/30 (87%)** | T1036.002, T1134.001, T1055, T1056.001 |
| 141217 | 23/30 (77%) | 24/30 | 25/30 | **26/30 (87%)** | T1036.002, T1055, T1012, T1056.001 |

---

## SVO 추출 비교 (전 기법, 3세션)

| TID | 143322 V / O | 171757 V / O | 141217 V / O | 유형 |
|-----|-------------|-------------|-------------|------|
| T1036.002 | execute / cod.3aka3.scr payload | execute / cod.3aka3.scr | **rename** / cod.3aka3.scr | A |
| T1059.001 | execute / malicious module | execute / malicious payload | invoke / powershell | C |
| T1547.009 | create / shortcut | create / shortcut | create / shortcut file | D |
| T1037.005 | install / startup item | install / startup folder | **register / service** | A |
| T1548.002 | steal / high-privilege token | bypass / user account control | **execute / sdclt.exe** | A |
| T1134.001 | **steal** / access token | **inject** / privileged process | **duplicate** / privileged token | A |
| T1036.005 | rename / malicious utilities | rename / malicious utilities | rename / malicious tools | D |
| T1055 | inject / legitimate processes | inject / trusted windows process | inject / trusted process | D |
| T1070.004 | delete / staging files | delete / staging files | delete / staging files | — |
| T1112 | remove / registry keys | remove / registry keys | **modify** / registry keys | C |
| T1134 | reuse / stolen tokens | impersonate / access token | **query / remote file share** | A (오추출) |
| T1016 | enumerate / network config | enumerate / network config | enumerate / network config details | D |
| T1082 | collect / system info | gather / system info | collect / system info | D |
| T1033 | echo / username | echo / %username% | identify / currently logged-in user | C |
| T1057 | enumerate / processes | enumerate / processes | enumerate / processes | — |
| T1007 | list / services | enumerate / services | enumerate / installed and running services | D |
| T1069 | enumerate / admin groups | enumerate / admin groups | query / admin groups | D |
| T1087 | list / domain users | list / account names | enumerate / user accounts | D |
| T1012 | query / registry keys | read / registry values | query / registry keys | C |
| T1018 | identify / domain controllers | identify / domain controllers | enumerate / domain controllers | D |
| T1049 | enumerate / active connections | enumerate / network connections | list / active network connections | D |
| T1083 | search / documents | search / document files | search / files and directories | D |
| T1003 | dump / credentials | dump / credentials | dump / credential data | D |
| T1552.004 | copy / .pfx file | copy / private key files | copy / private key files | B |
| T1119 | create / archive | compress / collected files | archive / documents | C |
| T1113 | capture / screenshot image | capture / screenshots | capture / desktop screenshot | D |
| T1115 | copy / clipboard | copy / clipboard contents | read / clipboard contents | C |
| T1056.001 | record / keystrokes | record / keystrokes | log / keystrokes | D |
| T1105 | copy / **psexec and sysinternals binaries** | copy / payloads | copy / payloads | B |
| T1041 | upload / compressed archive | upload / **draft.zip** | upload / compressed archives | B |

---

## SVO 변동 유형 분류

### Type A — V 방향 분기 (기법 의미 해석 차이 → 명령어 전략 완전히 달라짐)

**T1134.001 (Access Token Manipulation: Impersonation)**

| 세션 | V | 생성 명령어 계열 | 결과 |
|------|---|--------------|------|
| 143322 | **steal** | `whoami /all > token.txt` + 업로드 | **초기 성공** |
| 141217 | **duplicate** | `[WindowsIdentity]::GetCurrent().Impersonate()` | quoting 실패 → **R1 수정 성공** |
| 171757 | **inject** | invoke-mimi.ps1 다운로드 + Invoke-Mimikatz | 네트워크 장벽 → **3라운드 모두 실패** |

V 선택이 명령어의 네트워크 의존성을 결정한다:

- steal/duplicate → 로컬 API 호출 → ReAct 수정 가능
- inject → 외부 페이로드 의존 → ReAct 수정 불능

**T1036.002 (Masquerading: Right-to-Left Override)**

| 세션 | V | 생성 명령어 | 결과 |
|------|---|-----------|------|
| 143322 | **execute** | `New-Item cod.scr; Rename(RTLO); & $file` — 생성+rename+실행 일체형 | **초기 성공** |
| 141217 | **rename** | `Rename-Item "cod.scr" -NewName "cod.scr[RTLO].txt"` — rename만 | 파일 없음 → R2 O생성 후 성공 |
| 171757 | **execute** | `Start-Process "cod.3aka3.scr"` — 실행만 | 파일 없음 → 3라운드 모두 실패 |

V=rename은 ATT&CK 기법 의미에 더 가깝지만 파일 존재를 전제함. V=execute(143322)는 의미적으로 덜 정확하지만 자기 완결 명령어를 만들었다.
**V의 ATT&CK 의미 정확도와 명령어 실행 가능성은 비례하지 않는다.**

**T1548.002 (Bypass UAC via sdclt)**

| 세션 | V / O | 전략 | 결과 |
|------|------|------|------|
| 143322 | steal / high-privilege token | `sdclt.exe /kickoffelevated` 1줄 | **초기 성공** |
| 171757 | bypass / user account control | registry 등록 + IEX payload 체인 | nested quoting 실패 → **R2 수정** |
| 141217 | execute / sdclt.exe | `Start-Process sdclt.exe` | **초기 성공** |

**T1134 (Access Token Manipulation — 오추출 사례)**

| 세션 | V / O | 해석 방향 | 결과 |
|------|------|---------|------|
| 143322 | reuse / stolen tokens | 토큰 재사용 | 초기 성공 |
| 171757 | impersonate / access token | 토큰 가장 | 초기 성공 |
| 141217 | **query / remote file share** | **기법과 무관한 오추출** | `Get-ChildItem \\host\share` → 네트워크 실패 → R3 error-capture false positive |

---

### Type B — O 추상성 분기 (객체 구체성 차이 → 전제 조건 의존 여부)

**T1041 (Exfiltration Over C2)**

| 세션 | O | 생성 전략 | 결과 |
|------|---|---------|------|
| 143322 | compressed archive (추상) | `Compress-Archive`로 파일 직접 생성 → 업로드 | **초기 성공** |
| 141217 | compressed archives (추상) | 동일 | **초기 성공** |
| 171757 | **draft.zip** (구체) | `$filePath="draft.zip"` 존재 가정 → OpenRead | 파일 없음 → R2 O생성 전략으로 해결 |

시나리오 텍스트에 등장하는 파일명이 O에 그대로 반영될 때 전제 조건이 생긴다.

**일반화**:

- 추상적 O → LLM이 자유롭게 "사용 가능한 객체" 생성 → 자기 완결 명령어
- 구체적 O → 해당 객체가 사전 존재해야 함 → 초기 실패, ReAct O생성 전략 필요

---

### Type C — V 표현 부정확 (성공률 영향 없거나 미미)

V 표현이 미묘하게 달라지지만 동일한 CLI 도구 계열로 수렴하거나, 비결정적으로 명령어 스타일만 달라지는 경우. T1012는 예외적으로 실패 유발.

**T1012 (Query Registry) — 141217에서만 타임아웃**

- V=query, O=registry keys → `reg query "HKLM\Software" /s` 생성
- `/s` recursive로 수만 개 키 → **60초 타임아웃 (status=124)**
- ReAct가 R3에서 범위 축소(`HKLM\Software\Microsoft`) 시도 → 여전히 타임아웃
- 143322·171757에서는 동일 SVO임에도 타임아웃 없이 성공
- **O 범위(scope) 초과 타임아웃**: 새로운 실패 유형

---

### Type D — V 유사 표현 (실질 차이 없음)

enumerate/list/identify 등 유사 표현 간 분기는 동일 CLI 도구(sc.exe, tasklist, net user 등)로 수렴해 성공률 차이 없음. T1057, T1070.004 등은 3세션 모두 완전 동일.

---

## 핵심 발견

### 발견 1: V 방향 = ReAct Repair Ceiling 결정

SVO의 V 선택이 명령어의 **복구 가능 공간**을 정의한다.

```
V → 로컬 CLI/API 계열    → 구문 오류 가능 → ReAct 수정 가능 (1~2라운드)
V → 네트워크 의존 계열   → 서버/네트워크 장벽 → ReAct 수정 불능
V → 자기 완결 계열       → 초기 성공 (ReAct 불필요)
```

T1134.001이 세 경우를 모두 보여주는 핵심 사례:
steal(자기완결 성공) / duplicate(수정 성공) / inject(수정 불능)

### 발견 2: O 추상성 = 초기 성공률 결정 (ReAct로 복구 가능)

| O 유형 | 명령어 전략 | 초기 성공 | ReAct 복구 |
|--------|-----------|---------|-----------|
| 추상 (compressed archive) | 객체 자기 생성 | 높음 | 불필요 |
| 구체 (draft.zip) | 객체 존재 가정 | 낮음 | R1~R2에서 O생성 전략으로 가능 |

V 오류는 ReAct 복구가 어렵거나 불가능. O 오류는 ReAct가 O생성 전략으로 대부분 복구 가능.
**→ V가 O보다 파이프라인 최종 성공률에 더 큰 영향을 미친다.**

### 발견 3: SVO 추출은 실행마다 비결정적

30기법 중 완전 동일 추출은 T1070.004, T1057 등 소수. T1134.001처럼 3회 모두 완전히 다른 V가 추출되는 경우도 있다. 이 비결정성이 성공률 분산(63%~87%)의 주요 원인이다.

### 발견 4: V의 ATT&CK 의미 정확도 ≠ 명령어 실행 가능성

T1036.002 사례: V=rename(기법 의미 정확)이 V=execute(덜 정확)보다 더 낮은 초기 성공률을 만들었다. 의미적 정확성이 실행 가능성을 보장하지 않는다.

---

## 부가 관찰

### ReAct O 생성 전략 패턴

object_failure 진단 시 "O를 먼저 생성한 후 V 실행"하는 전략. Type B 실패의 주요 복구 메커니즘.

| 세션 | 기법 | ReAct 라운드 | 적용 내용 |
|------|------|-----------|---------|
| 141217 | T1070.004 | R1 | `New-Item C:\Temp\staging.txt -Force; Remove-Item` |
| 171757 | T1041 | R2 | `if(!(Test-Path)){New-Item -Force}` 선행 후 업로드 |
| 141217 | T1036.002 | R2 | `New-Item cod.3aka3.scr -Force; Rename-Item` |

### 상태 충돌 (State Collision)

전체 Operation 재실행 구조에서 이전 라운드에서 생성된 파일/키가 잔존해 다음 라운드에서 충돌.

| 세션 | 기법 | 현상 | 결과 |
|------|------|------|------|
| 141217 | T1036.005 | Move-Item destination 이미 존재 (R0 생성 잔존) | R3 pre-clean으로 해결 |
| 141217 | T1036.002 | RTLO 파일명 이미 존재 (R2 생성 잔존) | 미해결 (영구 실패) |
| 171757 | T1036.002 | 동일 패턴 | 미해결 |

### False Positive 목록

| 유형 | 도구/패턴 | 메커니즘 |
|------|---------|---------|
| 빈 루프 | `ForEach-Object {}` | 미실행 → exit 0 |
| 조건 미충족 | `if(Test-Path){...}` | 조건 false → 블록 미실행 → exit 0 |
| 비동기 실행 | `Start-Process` | 시작만 확인 → exit 0 |
| Error capture | `net view 2>&1` | 에러 텍스트가 "결과"로 업로드 → exit 0 |
| stderr 무시 | `nltest /dclist` | DC 미발견 stderr, exit 0 (T1018 사례) |

---

## 향후 실험 계획

1. **동일 시나리오 N회 반복** → SVO 추출 분산 정량화
   - 각 기법의 V 고유값 수, O 추상성 분포 측정

2. **SVO 고정 주입 실험** → SVO↔성공률 인과 분리
   - 추상 SVO 고정 vs 구체 SVO 고정 → ability 생성 반복 → 성공률 비교

3. **V 방향 분류 체계 정립**
   - 로컬/API계 vs 네트워크/페이로드계 vs 자기완결계 분류 기준
   - 분류별 ReAct 성공률 집계

---

## 세션 목록

| 세션 ID | 시나리오 | 초기→최종 | 특이사항 |
|---------|---------|---------|---------|
| 20260311_143322 | APT29 (30기법) | 26→29/30 | V=steal 계열 다수, 고성공 세션 |
| 20260311_171757 | APT29 (30기법) | 19→26/30 | V=inject 오추출 → T1134.001 영구 실패 |
| 20260312_141217 | APT29 (30기법) | 23→26/30 | T1134 오추출, T1012 scope timeout, 상태충돌 2건 |
