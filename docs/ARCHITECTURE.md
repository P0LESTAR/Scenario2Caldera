# CARMA Pipeline Architecture

## System Overview

CARMA Pipeline is a hybrid LLM + code-based system that automates the conversion of cybersecurity threat scenarios into executable Caldera operations.

```
┌─────────────────┐
│  Scenario Text  │
│  (Markdown/PDF) │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────┐
│  Phase 1: Parsing (LLM)     │
│  - Extract techniques       │
│  - Identify tactics         │
│  - Parse environment reqs   │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  Phase 2: Validation (Code) │
│  - Query Caldera API        │
│  - Check ability coverage   │
│  - Apply fallback logic     │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  Phase 3: Planning (LLM)    │
│  - Generate attack chain    │
│  - Determine dependencies   │
│  - Optimize execution order │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  Phase 4: Creation (Code)   │
│  - Create Caldera adversary │
│  - Generate operation       │
│  - Configure agents         │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  Caldera Operation          │
│  (Ready for Execution)      │
└─────────────────────────────┘
```

---

## Component Architecture

### Core Modules

#### 1. `scenario_parser.py`

- **Type**: LLM-based
- **Input**: Scenario text (markdown)
- **Output**: Structured JSON with techniques, tactics, environment
- **LLM Model**: Qwen2.5:32b (or similar)
- **Key Features**:
  - Extracts MITRE ATT&CK technique IDs
  - Maps techniques to tactics
  - Identifies OS and software requirements
  - Determines VM requirements

#### 2. `caldera_client.py`

- **Type**: Code-based (API client)
- **Input**: Technique IDs
- **Output**: Available abilities, match status
- **Key Features**:
  - Queries Caldera REST API
  - Parent technique fallback
  - Best ability selection (platform, privilege, requirements)
  - Connection pooling and error handling

#### 3. `scenario_validator.py`

- **Type**: Code-based
- **Input**: Parsed scenario + Caldera client
- **Output**: Validated techniques with executability status
- **Key Features**:
  - Validates each technique against Caldera
  - Annotates with executable/non-executable
  - Provides warning messages
  - Filters executable techniques

#### 4. `llm_orchestrator.py`

- **Type**: LLM-based
- **Input**: Validated techniques + scenario context
- **Output**: Attack chain with execution order
- **LLM Model**: Qwen2.5:32b (or similar)
- **Key Features**:
  - Generates logical kill chain order
  - Determines dependencies
  - Provides reasoning for each step
  - Considers MITRE ATT&CK tactics

#### 5. `operation_creator.py`

- **Type**: Code-based (API client)
- **Input**: Attack chain + agent selection
- **Output**: Caldera operation ID
- **Key Features**:
  - Creates Caldera adversary
  - Generates operation
  - Configures agent targeting
  - Supports paused/running modes

#### 6. `results_analyzer.py`

- **Type**: Code-based
- **Input**: Operation ID
- **Output**: Execution results analysis
- **Key Features**:
  - Fetches operation results from Caldera
  - Analyzes success/failure rates
  - Groups by technique and tactic
  - Exports detailed reports

---

## Data Flow

### Phase 1: Parsing

```python
Scenario Text
    ↓ (LLM)
{
  "scenario_name": "...",
  "threat_actor": "APT3",
  "techniques": [
    {
      "technique_id": "T1195",
      "technique_name": "Supply Chain Compromise",
      "tactic": "initial-access",
      "description": "...",
      "expected_action": "..."
    }
  ],
  "environment": {...},
  "vm_requirements": [...]
}
```

### Phase 2: Validation

```python
Parsed Techniques
    ↓ (Caldera API)
{
  "techniques": [
    {
      "technique_id": "T1195",
      "technique_name": "Supply Chain Compromise",
      "caldera_validation": {
        "executable": true,
        "match_type": "exact",
        "ability_count": 1,
        "fallback_applied": false
      }
    }
  ],
  "validation": {
    "total": 12,
    "executable": 10,
    "coverage_rate": 83.3
  }
}
```

### Phase 3: Planning

```python
Validated Techniques
    ↓ (LLM)
{
  "attack_chain": [
    {
      "step": 1,
      "technique_id": "T1195",
      "ability_id": "4f0c6695...",
      "ability_name": "Octopus Scanner Malware",
      "reason": "Initial access via supply-chain",
      "dependencies": []
    },
    {
      "step": 2,
      "technique_id": "T1027.013",
      "ability_id": "6fe8f0c1...",
      "ability_name": "Decode Eicar File",
      "reason": "Evade defenses",
      "dependencies": ["T1195"]
    }
  ]
}
```

### Phase 4: Creation

```python
Attack Chain
    ↓ (Caldera API)
{
  "adversary_id": "79103912-46cb-4b5f-b235-d8cba83b9402",
  "operation_id": "8572faee-ec8e-44e3-91d1-9c7b249e165b",
  "name": "CARMA_APT3_(Gothic_Panda)_20260212_170901",
  "state": "paused",
  "agent": "ursjum"
}
```

---

## Design Decisions

### Hybrid Approach (LLM + Code)

**Why not LLM-only?**

- LLMs can hallucinate technique IDs
- Caldera API provides ground truth
- Code ensures 100% accuracy for validation

**Why not Code-only?**

- Scenario parsing requires natural language understanding
- Attack chain planning benefits from contextual reasoning
- LLMs excel at understanding threat actor behavior

### Fallback Logic

When a sub-technique isn't available:

```python
T1547.001 (Registry Run Keys) → Not found
    ↓ Fallback
T1547 (Boot or Logon Autostart Execution) → Found (25 abilities)
```

This increases coverage by ~10-20% depending on scenario.

### Best Ability Selection

When multiple abilities exist for a technique:

1. **Platform Match**: Windows > Linux > macOS
2. **Privilege Level**: User > Elevated > SYSTEM
3. **Requirements**: Fewer dependencies preferred

This ensures the most compatible and stealthy ability is selected.

---

## Performance Characteristics

### Time Complexity

| Phase | Time | Bottleneck |
|-------|------|------------|
| Parsing | O(n) | LLM inference |
| Validation | O(n) | API calls |
| Planning | O(n log n) | LLM inference + sorting |
| Creation | O(1) | API call |

Where n = number of techniques

### Space Complexity

- **Parsing**: O(n) - stores techniques
- **Validation**: O(n) - adds validation metadata
- **Planning**: O(n²) - stores dependencies
- **Creation**: O(n) - stores operation config

### Scalability

- **Techniques**: Tested up to 20 techniques per scenario
- **Scenarios**: Unlimited (stateless processing)
- **Concurrent Operations**: Limited by Caldera server capacity

---

## Error Handling

### LLM Failures

```python
try:
    parsed = llm.parse(scenario_text)
except JSONDecodeError:
    # Retry with cleaned prompt
    # Fall back to regex extraction
    pass
```

### API Failures

```python
try:
    abilities = caldera.get_abilities(technique_id)
except ConnectionError:
    # Retry with exponential backoff
    # Cache previous results
    pass
```

### Validation Failures

```python
if not executable_techniques:
    # Warn user
    # Suggest manual review
    # Export non-executable list
    pass
```

---

## Security Considerations

### API Keys

- Stored in `config.py` (gitignored)
- Never logged or printed
- Transmitted over HTTPS only

### LLM Prompts

- No sensitive data in prompts
- Scenario text sanitized
- Output validated before execution

### Caldera Operations

- Created in "paused" state by default
- Requires manual approval to start
- Agent selection explicit

---

## Future Enhancements

### Planned Features

1. **Multi-LLM Support**
   - OpenAI GPT-4
   - Anthropic Claude
   - Google Gemini

2. **Advanced Validation**
   - Environment pre-checks
   - Dependency resolution
   - Privilege escalation paths

3. **Execution Monitoring**
   - Real-time progress tracking
   - Automatic retry on failure
   - Dynamic chain adjustment

4. **Results Correlation**
   - SIEM log integration
   - EDR alert mapping
   - Timeline reconstruction

---

## References

- [MITRE Caldera Documentation](https://caldera.readthedocs.io/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Ollama Documentation](https://github.com/ollama/ollama)
