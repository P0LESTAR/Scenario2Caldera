# Scenario2Caldera v2

자연어로 작성된 위협 시나리오 보고서(CTI)를 파싱하여, MITRE ATT&CK 기반의 Caldera Operation으로 자동 변환하고 스스로 에러를 수정하며 실행하는 지능형 파이프라인.

## 주요 기능 (v2 파이프라인)

1. **Scenario Parsing** — LLM을 통해 텍스트 시나리오에서 MITRE ATT&CK 기법, Tactic 파싱
2. **Technique Validation** — Caldera 내 기존 Ability 존재 유무 분석 (Sub-technique → Parent fallback)
3. **SVO Extraction** — 각 기법들의 공격 의도를 담은 주어-동사-목적어(SVO) 트리플릿 추출
4. **Ability Acquisition** — Caldera에 기존 Ability가 존재하면 우선 선택, 없으면 추출된 SVO를 참고하여 LLM이 **새로운 커스텀 Ability 및 스크립트(PowerShell 등)를 즉석 생성**
5. **Attack Chain & Operation Creation** — 분석된 순서로 공격 체인(Adversary)과 Operation을 조립 및 자동 실행 시작
6. **ReAct Self-Fix Loop (Operation-Level)** —
   - 일차 실행 후 발생한 에러를 분석(stderr/stdout 수집)하여, 실패한 Ability들의 Command 코드를 SVO 제약 하에 스스로 수정(Patch)합니다.
   - 수정이 완료되면 전체 Operation을 다시 재실행합니다 (최대 3라운드 반복).
7. **RetryAnalyzer Fallback** — ReAct 루프만으로 해결되지 않은 복구 불가 기법들을 분석하고, 비슷한 목적의 대체(Alternative) 기법을 찾아 Fallback Operation을 수행합니다.
8. **Automatic Cleanup** — 실행 과정에서 파이프라인이 임시로 생성했던 객체들(Ability, Adversary, Operation)을 실행 종료 시점에 깔끔하게 삭제합니다.

## 시스템 요구사항

- **Python 3.8+**
- **Caldera Server** (API 접근 가능, 기본 8888 포트)
- **Ollama Server** (LLM 처리용)
- **Target Agent** — 테스트하려는 타겟 VM 머신에서 Caldera 에이전트 구동 중일 것

## 로컬 환경 설정

`.env.example`을 참고하여 프로젝트 루트에 `.env` 파일을 생성합니다.

```ini
CALDERA_URL=http://192.168.x.x:8889
CALDERA_API_KEY=YOUR_CALDERA_API_TOKEN
OLLAMA_HOST=http://192.168.x.x:11434
LLM_MODEL=llama3.1:70b  # 사용할 Ollama 모델 지정
```

## 사용법

```bash
# 기본 실행 (가장 추천하는 방식 - 종료 후 임시 데이터 자동 삭제)
python run.py scenarios/APT3_scenario.md

# SVO 커스텀 생성 실험 모드 (기존 Ability 검사 무시하고 무조건 SVO 기반 신규 생성)
python run.py scenarios/APT3_scenario.md --force-generate

# 보존 모드 (임시 생성된 Ability/Adversary/Operation 내역을 Caldera UI에서 직접 보기 위해 삭제 방지)
python run.py scenarios/APT3_scenario.md --force-generate --keep-objects
```

## 실행 결과

파이프라인 실행 내용의 모든 상세 JSON 데이터 결과는 `results/session_<시간>/` 디렉토리에 저장됩니다:

| 파일명 | 내용 요약 |
|------|---------|
| `01_parsed_scenario.json` | LLM 파싱 결과 (ATT&CK 기법 추출) |
| `02_validated_scenario.json` | 추출 기법의 Caldera 등록 여부 확인 |
| `02_5_svo_extraction.json` | 추출된 공격 의도 (Subject-Verb-Object) |
| `03_ability_acquisition.json` | 사용할 기존 Ability 매핑 및 신규 Ability 생성 내역 |
| `04_attack_chain.json` | 조립된 공격 체인 스텝 시퀀스 |
| `05_created_operation.json` | 본 실행 Adversary/Operation 생성 정보 |
| `06_operation_results.json` | 1차 오퍼레이션 실행 결과 분석 |
| `07_react_round_*.json` | 에러 수정(ReAct) 루프 라운드별 재실행 결과 |
| `07_react_summary.json` | ReAct 결과 전체 요약 (수정 로그, 문법 변형 추이 등) |
| `08_fallback_analysis.json` | 남은 에러 기법들에 대한 대체 기법(Fallback) LLM 권고 사항 |
| `09_fallback_results.json` | 대안 기법 기반의 Fallback 오퍼레이션 실행 결과 분석 |
| `session_info.json` | 전체 세션 기본 메타데이터 |

## 코어 모듈 구조 (`core_v2/`)

- `pipeline.py` — Pipeline 메인 오케스트레이션 수행 및 임시 파일 삭제 등 관리
- `scenario.py` — ScenarioProcessor (텍스트 파싱)
- `llm_orchestrator.py` — 단계 얽힘 파악 및 공격 체인 순서 논리적 조립
- `caldera_client.py` — Caldera REST API 클라이언트 모듈 (삭제/등록 등 전면 컨트롤)
- `svo_extractor.py` — SVO 트리플릿 문장 기반 추출기
- `ability_generator.py` — SVO 제약 조건을 기반으로 한 Caldera Ability JSON 포맷 제작
- `react_agent.py` — 에러메시지 분류기 및 재시도 프롬프트(FixAttempt 이력 포함) 기반의 자율 수정 Agent
- `retry_analyzer.py` — 대체 기법 추론 엔진
