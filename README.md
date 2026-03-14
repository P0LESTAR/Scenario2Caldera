# Scenario2Caldera v2

**연구 주제: LLM 기반 CTI 파이프라인에서 SVO 추출 비결정성이 공격 시뮬레이션 성공률과 ReAct 자가복구 상한선에 미치는 영향**

자연어 CTI 보고서(위협 시나리오)를 파싱하여 MITRE ATT&CK 기반 Caldera Operation으로 자동 변환하고, 실패한 명령어를 SVO(Subject-Verb-Object) 의미 제약 하에 자율적으로 수정·재실행하는 지능형 파이프라인.

## 연구 목적

동일 시나리오를 반복 실행할 때 LLM 기반 SVO 추출 결과가 비결정적으로 달라지며:

- V(Verb) 방향 선택이 ReAct Repair Ceiling을 결정한다 — 로컬 CLI계 V는 수정 가능, 네트워크 의존계 V는 수정 불가
- O(Object) 추상성이 초기 성공률을 결정한다 — 추상적 O는 자기완결 명령어, 구체적 O는 전제 조건 의존
- Phase 3 (Ability 생성)도 비결정적이어서 동일 SVO에서도 명령어 전략이 달라진다

## 파이프라인 구조

```
CTI 시나리오 (.md)
    │
    ▼ Phase 1: Scenario Parsing
    │   LLM → MITRE ATT&CK 기법 추출
    │
    ▼ Phase 2: SVO Extraction
    │   각 기법의 공격 의도를 Subject-Verb-Object 트리플릿으로 추출
    │
    ▼ Phase 3: Ability Acquisition
    │   기존 Ability 선택 or SVO 기반 커스텀 Ability 즉석 생성
    │   (--force-generate: Caldera 검증 스킵 + 항상 SVO 기반 신규 생성)
    │
    ▼ Phase 4: Attack Chain & Operation
    │   공격 체인 조립 → Caldera Adversary/Operation 생성 및 실행
    │
    ▼ Phase 5: Wait for Completion
    │   Operation 완료 폴링 (10초 간격, 타임아웃 30분)
    │
    ▼ Phase 6: ReAct Self-Fix Loop (최대 3라운드)
    │   실패한 명령어 → SVO 제약 하에 수정 → 전체 Operation 재실행
    │   수정 시 Thought / failure_type 기록
    │
    ▼ Phase 7: RetryAnalyzer Fallback
        ReAct로 해결 불가 → 대체 기법(Alternative Technique) 탐색 및 실행
```

## 핵심 모듈 (`core_v2/`)

| 파일 | 역할 |
|------|------|
| `pipeline.py` | 전체 파이프라인 오케스트레이션 |
| `scenario.py` | LLM 기반 시나리오 파싱 + Caldera 검증 |
| `svo_extractor.py` | SVO 트리플릿 추출 |
| `ability_generator.py` | SVO → Caldera Ability 생성 (LLM 명령어 생성 + API 등록) |
| `react_agent.py` | ReAct 자율 수정 에이전트 (실패 분류 → 명령어 수정) |
| `retry_analyzer.py` | 대체 기법 추론 Fallback 엔진 |
| `llm_orchestrator.py` | 공격 체인 순서 논리적 조립 |
| `caldera_client.py` | Caldera REST API 클라이언트 |

## 시스템 요구사항

- **Python 3.8+**
- **Caldera Server** (기본 포트 8888)
- **Ollama Server** (LLM 처리, temperature=0.0)
- **Target Agent** — 대상 VM에서 Caldera 에이전트 구동 중

## 환경 설정

`.env` 파일을 프로젝트 루트에 생성:

```ini
CALDERA_URL=http://192.168.x.x:8888
CALDERA_API_KEY=YOUR_CALDERA_API_TOKEN
OLLAMA_HOST=http://192.168.x.x:11434
LLM_MODEL=your-model-name
```

## 실행법

```bash
# 기본 실행 (기존 Caldera Ability 우선 사용)
python run.py scenarios/APT29_scenario.md

# SVO 기반 강제 생성 모드 (연구용 — Caldera 검증 스킵, 항상 신규 생성)
python run.py scenarios/APT29_scenario.md --force-generate

# 객체 보존 모드 (Caldera UI에서 결과 직접 확인용)
python run.py scenarios/APT29_scenario.md --force-generate --keep-objects
```

## 결과 파일 (`results/session_<timestamp>/`)

| 파일 | 내용 |
|------|------|
| `01_parsed_scenario.json` | LLM 파싱 결과 (ATT&CK 기법 추출) |
| `02_5_svo_extraction.json` | 추출된 SVO 트리플릿 (Subject / Verb / Object / Type) |
| `03_ability_acquisition.json` | Ability 확보 내역 (기존 선택 or 신규 생성) |
| `04_attack_chain.json` | 공격 체인 스텝 시퀀스 |
| `05_created_operation.json` | Operation 생성 정보 |
| `06_operation_results.json` | 초기 실행 결과 (링크별 status, command, stdout/stderr) |
| `07_react_summary.json` | ReAct 전체 요약 (라운드별 수정 내역, failure_type, thought, fixed_command) |
| `session_info.json` | 세션 메타데이터 |

## ReAct 수정 기록 스키마 (`07_react_summary.json`)

```json
{
  "total_rounds": 3,
  "rounds": [
    {
      "round": 1,
      "failed_count": 8,
      "patched_count": 8,
      "fixes": [
        {
          "technique_id": "T1041",
          "svo": { "verb": "upload", "object": "compressed archive" },
          "original_command": "...",
          "fixed_command": "...",
          "failure_type": "object_failure",
          "thought": "LLM의 실패 원인 분석 및 수정 전략"
        }
      ],
      "result_stats": { "total": 30, "success": 22, "failed": 8 }
    }
  ]
}
```

## ReAct 실패 분류 체계

| failure_type | 의미 | 수정 방향 |
|-------------|------|---------|
| `verb_failure` | 명령어/도구 미존재 또는 alias 충돌 | 동일 동작의 다른 도구로 교체 (e.g. `sc` → `sc.exe`) |
| `object_failure` | 대상 파일/경로/객체 미존재 | O-creation 전략 또는 대안 객체 탐색 |
| `subject_failure` | 권한 부족 | 권한 상승 래핑 또는 접근 가능한 경로로 전환 |
| `syntax_failure` | 플랫폼 문법 오류 (quoting, escaping 등) | 플랫폼 호환 문법으로 수정 |
| `env_failure` | 환경 도구 미설치 또는 타임아웃 | 내장 도구로 대체 또는 범위 축소 |
| `unknown` | 에러 미분류 | 전반적 재구성 (수정 불가 시 영구 실패) |

## 주요 실험 결과 (APT29 시나리오, 30기법, 7세션)

| 세션 | 초기 성공 | 최종 성공 | 비고 |
|------|---------|---------|------|
| 20260311_143322 | 26/30 (87%) | 29/30 (97%) | V=steal 계열 다수 |
| 20260311_171757 | 19/30 (63%) | 26/30 (87%) | V=inject 오추출 |
| 20260312_141217 | 23/30 (77%) | 26/30 (87%) | T1134 오추출, 상태충돌 |
| 20260312_152852 | 22/30 (73%) | 27/30 (90%) | Phase 3 비결정성 확인 |
| 20260312_162222 | 16/30 (53%) | 23/30 (77%) | Ability 매칭 실패 |
| 20260312_191016 | 22/30 (73%) | 25/30 (83%) | T1003 comsvcs.dll 드리프트 |
| 20260313_181658 | 20/30 (67%) | 26/30 (87%) | ReAct의 cod.3aka3.scr 자율 추론 |

초기 성공률 범위: **53%~87%**, 최종 성공률 범위: **77%~97%**

상세 분석은 `Research_Note.md` 참고.
