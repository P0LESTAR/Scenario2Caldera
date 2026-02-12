# Scenario2Caldera

시나리오를 Caldera Operation으로 자동 변환하는 파이프라인 도구입니다.

## 🛠 주요 기능

1. **Scenario Parsing**
   - LLM을 사용하여 텍스트 시나리오에서 MITRE ATT&CK 기법, Tactic, 필요 환경 등을 추출합니다.

2. **Technique Validation**
   - 추출된 기법이 현재 Caldera 서버에 존재하는지 확인합니다.
   - **Fallback 로직**: Sub-technique(예: `T1547.001`)이 없으면 Parent Technique(`T1547`)의 Ability를 검색하여 대체합니다.

3. **Attack Chain Planning**
   - 실행 가능한 기법들을 바탕으로 논리적인 공격 순서(Chain)를 생성합니다.
   - 사전 조건(Prerequisites)과 의존성을 고려하여 정렬합니다.

4. **Operation Creation**
   - Caldera에 Adversary와 Operation을 자동으로 생성합니다.
   - 생성된 Operation은 안전을 위해 **Paused** 상태로 시작됩니다.

## 📋 필수 사항 (Requirements)

- **Python 3.8+**
- **Caldera Server**: API 접근이 가능해야 함 (기본 8888 포트)
- **Ollama Server**: LLM 처리를 위한 서버 (기본 11434 포트)
- **Target Agent**: Caldera 에이전트가 타겟 머신에서 실행 중이어야 함

## ⚙️ 설정 (Configuration)

`.env` 파일을 통해 설정을 관리합니다.

```ini
# Caldera 연결 설정
CALDERA_URL=http://192.168.xx.xx:8888
CALDERA_API_KEY=ADMIN123

# LLM 설정 (Ollama)
OLLAMA_HOST=http://192.168.xx.xx:11434
LLM_MODEL=gpt-oss:120b
```

## 🚀 사용법

### 전체 파이프라인 실행

시나리오 파일을 입력받아 Caldera Operation 생성까지 한 번에 수행합니다.

```bash
python scripts/run_pipeline.py scenarios/APT3_scenario.md
```

실행 후 생성되는 파일들 (`results/session_timestamp/`):

- `01_parsed_scenario.json`: LLM 파싱 결과
- `02_validated_scenario.json`: Caldera 검증 결과 (실행 가능 여부)
- `03_attack_chain.json`: 공격 시나리오 순서도
- `04_operation_plan.json`: Operation 생성 계획
- `05_created_operation.json`: 최종 생성된 Operation 정보

## 📂 디렉토리 구조

```
Scenario2Caldera/
├── core/                  # 핵심 모듈
│   ├── parser             # LLM 시나리오 파싱
│   ├── validator          # Caldera Ability 검증
│   ├── planner            # 공격 체인 계획
│   └── client             # Caldera API 클라이언트
├── scripts/               # 실행 스크립트
├── scenarios/             # 테스트 시나리오
└── results/               # 실행 결과 저장
```
