# Scenario2Caldera v2

**연구 주제: SVO 의미 제약 기반 공격 명령어 자가 복구 시 생성 명령어 특성 분석**

자연어 CTI 보고서(위협 시나리오)를 파싱하여 MITRE ATT&CK 기반 Caldera Operation으로 자동 변환하고, 실패한 명령어를 SVO(Subject-Verb-Object) 의미 제약 하에 자율적으로 수정·재실행하는 지능형 파이프라인.

## 연구 목적

실패한 공격 시뮬레이션 명령어를 ReAct 루프로 자가 복구할 때:
- SVO 의미 제약(공격 의도)이 수정 과정에서 얼마나 보존되는가
- 실패 유형(verb/object/syntax 등)에 따라 어떤 수정 패턴이 나타나는가
- 수정된 명령어의 구조적·의미적 특성은 어떻게 변화하는가

## 파이프라인 구조

```
CTI 시나리오 (.md)
    │
    ▼ Phase 1: Scenario Parsing
    │   LLM → MITRE ATT&CK 기법 추출
    │
    ▼ Phase 2: Caldera Validation
    │   기존 Ability 존재 여부 확인 (Sub-technique → Parent fallback)
    │
    ▼ Phase 2.5: SVO Extraction
    │   각 기법의 공격 의도를 Subject-Verb-Object 트리플릿으로 추출
    │
    ▼ Phase 3: Ability Acquisition
    │   기존 Ability 선택 or SVO 기반 커스텀 Ability 즉석 생성
    │   (--force-generate: 항상 SVO 기반 신규 생성)
    │
    ▼ Phase 4: Attack Chain & Operation
    │   공격 체인 조립 → Caldera Adversary/Operation 생성 및 실행
    │
    ▼ Phase 5: Wait for Completion
    │   Operation 완료 폴링 (10초 간격, 타임아웃 30분)
    │
    ▼ Phase 6: ReAct Self-Fix Loop (최대 3라운드)
    │   실패한 명령어 → SVO 제약 하에 수정 → 전체 Operation 재실행
    │   수정 시 Thought / Action / SVO Focus 기록
    │
    ▼ Phase 7: RetryAnalyzer Fallback
        ReAct로 해결 불가 → 대체 기법(Alternative Technique) 탐색 및 실행
```

## 핵심 모듈 (`core_v2/`)

| 파일 | 역할 |
|------|------|
| `pipeline.py` | 전체 파이프라인 오케스트레이션 |
| `scenario.py` | LLM 기반 시나리오 파싱 |
| `svo_extractor.py` | SVO 트리플릿 추출 |
| `ability_generator.py` | SVO → Caldera Ability 생성 (LLM 명령어 생성 + API 등록) |
| `react_agent.py` | ReAct 자율 수정 에이전트 (실패 분류 → 명령어 수정) |
| `retry_analyzer.py` | 대체 기법 추론 Fallback 엔진 |
| `llm_orchestrator.py` | 공격 체인 순서 논리적 조립 |
| `caldera_client.py` | Caldera REST API 클라이언트 |

## 시스템 요구사항

- **Python 3.8+**
- **Caldera Server** (기본 포트 8888)
  - 파일 업로드: `POST /file/upload` (form field: `data`)
  - 파일 다운로드: `GET /file/download` (header: `file: <filename>`)
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
python run.py scenarios/APT3_scenario.md

# SVO 기반 강제 생성 모드 (연구용 — 기존 Ability 무시, 항상 신규 생성)
python run.py scenarios/APT3_scenario.md --force-generate

# 객체 보존 모드 (Caldera UI에서 결과 직접 확인용)
python run.py scenarios/APT3_scenario.md --force-generate --keep-objects

# Thief 시나리오 단독 테스트
python test_thief.py
```

## 결과 파일 (`results/session_<timestamp>/`)

| 파일 | 내용 |
|------|------|
| `01_parsed_scenario.json` | LLM 파싱 결과 (ATT&CK 기법 추출) |
| `02_validated_scenario.json` | Caldera Ability 존재 여부 확인 |
| `02_5_svo_extraction.json` | 추출된 SVO 트리플릿 (Subject / Verb / Object / Type) |
| `03_ability_acquisition.json` | Ability 확보 내역 (기존 선택 or 신규 생성) |
| `04_attack_chain.json` | 공격 체인 스텝 시퀀스 |
| `05_created_operation.json` | Operation 생성 정보 |
| `06_operation_results.json` | 초기 실행 결과 |
| `07_react_round_*.json` | ReAct 라운드별 수정 결과 |
| `07_react_summary.json` | ReAct 전체 요약 (SVO, 원본·수정 명령어, thought/action/svo_focus) |
| `08_fallback_analysis.json` | RetryAnalyzer 대체 기법 권고 |
| `09_fallback_results.json` | Fallback Operation 실행 결과 |
| `session_info.json` | 세션 메타데이터 |

로그: `logs/run_<timestamp>.log` (터미널 출력 전체 기록)

## ReAct 수정 기록 스키마 (`07_react_summary.json`)

```json
{
  "technique_id": "T1041",
  "svo": {
    "subject": "agent",
    "verb": "transfer",
    "object": "zip archive",
    "object_type": "file"
  },
  "original_command": "...",
  "fixed_command": "...",
  "failure_type": "unknown | verb_failure | object_failure | ...",
  "thought": "LLM의 실패 원인 분석",
  "action": "수정 전략 설명",
  "svo_focus": "수정 시 집중한 SVO 구성요소",
  "status": "patched | skipped"
}
```

## ReAct 실패 분류 체계

| failure_type | 의미 | SVO 집중 구성요소 |
|-------------|------|----------------|
| `verb_failure` | 명령어/도구 미존재 | V — 동일 동작의 다른 도구로 교체 |
| `object_failure` | 대상 경로/파일 미존재 | O — 대상 탐색 방식 변경 |
| `subject_failure` | 권한 부족 | S — 권한 상승 래핑 시도 |
| `syntax_failure` | 플랫폼 문법 오류 | V+O — 플랫폼 호환 문법으로 수정 |
| `env_failure` | 환경 도구 미설치 | V — 내장 도구로 대체 |
| `unknown` | 에러 미분류 | V+O — 전반적 재구성 |
