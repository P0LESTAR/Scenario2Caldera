# Scenario2Caldera

텍스트 시나리오를 Caldera Operation으로 자동 변환하는 파이프라인.

## 주요 기능

1. **Scenario Parsing** — LLM으로 시나리오에서 MITRE ATT&CK 기법, Tactic, 환경 요구사항 추출
2. **Technique Validation** — Caldera Ability 존재 여부 확인 + Sub→Parent Fallback
3. **Attack Chain Planning** — 실행 가능한 기법들의 논리적 공격 순서 생성
4. **Operation Creation** — Caldera Adversary + Operation 자동 생성 (Paused 상태)

## 필수 사항

- **Python 3.8+**
- **Caldera Server** (API 접근 가능, 기본 8888 포트)
- **Ollama Server** (LLM 처리, 기본 11434 포트)
- **Target Agent** — Caldera 에이전트가 타겟 머신에서 실행 중

## 설정

`.env.example`을 복사하여 `.env` 파일을 생성합니다.

```ini
CALDERA_URL=http://192.168.xx.xx:8888
CALDERA_API_KEY=ADMIN123
OLLAMA_HOST=http://192.168.xx.xx:11434
LLM_MODEL=gpt-oss:120b
```

## 사용법

```bash
pip install -r requirements.txt
python scripts/run_pipeline.py scenarios/APT3_scenario.md
```

실행 결과는 `results/session_<timestamp>/`에 저장됩니다:

| 파일 | 내용 |
|------|------|
| `01_parsed_scenario.json` | LLM 파싱 결과 |
| `02_validated_scenario.json` | Caldera 검증 결과 |
| `03_attack_chain.json` | 공격 체인 순서 |
| `04_created_operation.json` | 생성된 Operation 정보 |

## 프로젝트 구조

```
Scenario2Caldera/
├── config.py              # 환경 설정 (.env 로드)
├── core/
│   ├── scenario.py        # ScenarioProcessor — 파싱 + 검증 + Ability 선택
│   ├── caldera_client.py  # CalderaClient — API 통신, Operation 생성/분석
│   ├── llm_orchestrator.py# LLMOrchestrator — 공격 체인 순서 결정
│   └── pipeline.py        # Pipeline — 전체 파이프라인 오케스트레이션
├── scripts/
│   └── run_pipeline.py    # CLI entry point
├── scenarios/             # 시나리오 파일
└── results/               # 실행 결과
```

### Core 모듈

| 모듈 | 클래스 | 역할 |
|------|--------|------|
| `scenario.py` | `ScenarioProcessor` | LLM 파싱 → Caldera 검증 → Best Ability 선택 |
| `caldera_client.py` | `CalderaClient` | Caldera REST API 전체 (Agent, Ability, Adversary, Operation, 결과 분석) |
| `llm_orchestrator.py` | `LLMOrchestrator` | 실행 가능 기법 → 논리적 공격 순서 계획 |
| `pipeline.py` | `Pipeline` | Phase 1~4 순차 실행 및 결과 저장 |
