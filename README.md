# Scenario2Caldera

**Automated Cyber Attack Scenario to Caldera Operation Pipeline**

Transform cybersecurity incident response scenarios into executable Caldera operations automatically using LLM-powered parsing and intelligent technique validation.

---

## 🎯 Overview

Scenario2Caldera automates the process of converting threat scenario documents into ready-to-execute Caldera C2 operations:

1. **📄 Scenario Parsing** - LLM extracts MITRE ATT&CK techniques from scenario text
2. **✅ Caldera Validation** - Verifies which techniques are executable in Caldera
3. **🔗 Attack Chain Planning** - LLM generates logical execution order with dependencies
4. **🚀 Operation Creation** - Automatically creates Caldera adversary and operation
5. **📊 Results Analysis** - Collects and analyzes execution results

---

## ✨ Key Features

- **🤖 LLM-Powered Parsing**: Automatically extracts techniques, tactics, and environment requirements
- **🎯 Smart Validation**: Pre-validates techniques against Caldera's available abilities
- **🧠 Intelligent Planning**: LLM generates attack chains following cyber kill chain logic
- **⚡ Fast Execution**: Complete pipeline runs in ~2 minutes
- **📈 High Coverage**: Achieves 60-85% technique coverage depending on scenario type
- **🔄 Parent Fallback**: Automatically falls back to parent techniques when sub-techniques unavailable

---

## 📊 Performance

### APT29 (Finance/Banking Scenario)

- **Techniques**: 13 total
- **Coverage**: 61.5% (8/13 executable)
- **Attack Chain**: 8 steps
- **Time**: ~2 minutes

### APT3 (Aerospace/Defence Scenario)

- **Techniques**: 12 total
- **Coverage**: 83.3% (10/12 executable)
- **Attack Chain**: 10 steps
- **Time**: ~1.5 minutes

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- [Caldera C2](https://github.com/mitre/caldera) server running
- [Ollama](https://ollama.ai/) with a model (e.g., `qwen2.5:32b`)
- Caldera agent deployed on target VM

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/Scenario2Caldera.git
cd Scenario2Caldera

# Install dependencies
pip install -r requirements.txt

# Configure settings
cp config.example.py config.py
# Edit config.py with your Caldera and LLM settings
```

### Configuration

Edit `config.py`:

```python
# Caldera Configuration
CALDERA_CONFIG = {
    "url": "http://192.168.50.31:8888",
    "api_key": "your-api-key-here"
}

# LLM Configuration
LLM_CONFIG = {
    "host": "http://localhost:11434",
    "model": "qwen2.5:32b",
    "temperature": 0.1
}
```

### Usage

#### Full Pipeline (Recommended)

```bash
# Run complete pipeline on a scenario
python run_pipeline.py scenarios/APT3_scenario.md
```

This will:

1. Parse the scenario
2. Validate techniques with Caldera
3. Generate attack chain
4. Create Caldera operation
5. Save all results to `results/session_TIMESTAMP/`

#### Step-by-Step

```bash
# 1. Parse scenario
python parse_scenario.py scenarios/APT3_scenario.md

# 2. Validate techniques
python validate_techniques.py results/parsed_scenario.json

# 3. Plan attack chain
python plan_attack_chain.py results/validated_scenario.json

# 4. Create Caldera operation
python create_operation.py results/attack_chain.json

# 5. Analyze results (after execution in Caldera UI)
python analyze_results.py <operation_id>
```

---

## 📁 Project Structure

```
Scenario2Caldera/
├── README.md                      # This file
├── requirements.txt               # Python dependencies
├── config.py                      # Configuration (create from config.example.py)
├── config.example.py              # Configuration template
│
├── core/                          # Core modules
│   ├── scenario_parser.py         # LLM-based scenario parser
│   ├── caldera_client.py          # Caldera API client with fallback
│   ├── llm_orchestrator.py        # LLM-based attack chain planner
│   └── operation_creator.py       # Caldera operation creator
│
├── scripts/                       # Executable scripts
│   ├── run_pipeline.py            # Full pipeline runner
│   ├── parse_scenario.py          # Scenario parsing only
│   ├── validate_techniques.py     # Technique validation only
│   ├── plan_attack_chain.py       # Attack chain planning only
│   ├── create_operation.py        # Operation creation only
│   └── analyze_results.py         # Results analysis
│
├── scenarios/                     # Example scenarios
│   ├── APT29_scenario.md          # APT29 Finance/Banking
│   └── APT3_scenario.md           # APT3 Aerospace/Defence
│
├── results/                       # Output directory (auto-created)
│   └── session_TIMESTAMP/         # Per-session results
│       ├── parsed_scenario.json
│       ├── validated_scenario.json
│       ├── attack_chain.json
│       ├── operation_plan.json
│       └── created_operation.json
│
└── docs/                          # Documentation
    ├── ARCHITECTURE.md            # System architecture
    ├── API.md                     # API reference
    └── EXAMPLES.md                # Usage examples
```

---

## 🔧 How It Works

### 1. Scenario Parsing (LLM)

The LLM extracts structured data from scenario text:

```json
{
  "scenario_name": "Incident Response Testing",
  "threat_actor": "APT3 (Gothic Panda)",
  "techniques": [
    {
      "technique_id": "T1195",
      "technique_name": "Supply Chain Compromise",
      "tactic": "initial-access",
      "description": "...",
      "expected_action": "..."
    }
  ]
}
```

### 2. Caldera Validation (Code)

Each technique is validated against Caldera:

```
✓ T1195  Supply Chain Compromise  → 1 ability
✓ T1053.005  Scheduled Task       → 16 abilities
✗ T1588.003  Code Signing Certs   → Resource Development (out of scope)
```

### 3. Attack Chain Planning (LLM)

LLM generates logical execution order:

```json
{
  "step": 1,
  "technique_id": "T1195",
  "ability_id": "4f0c66956fc56e1ab11f4a1e394a4fd0",
  "reason": "Supply-chain compromise provides initial foothold",
  "dependencies": []
}
```

### 4. Operation Creation (Code)

Automatically creates Caldera adversary and operation:

- **Adversary**: Collection of abilities in execution order
- **Operation**: Ready-to-run with selected agent

---

## 📊 Example Output

### Validation Summary

```
Total Techniques:     12
✓ Executable:         10 (83.3%)
  - Exact Match:      9
  - Parent Fallback:  1
✗ Non-Executable:     2 (16.7%)
```

### Attack Chain

```
Step 1: T1195 (initial-access) → Supply Chain Compromise
Step 2: T1027.013 (defense-evasion) → Encoded File
Step 3: T1053.005 (execution) → Scheduled Task
Step 4: T1543.003 (persistence) → Windows Service
Step 5: T1556.002 (credential-access) → Password Filter DLL
...
```

### Created Operation

```
Operation ID: 8572faee-ec8e-44e3-91d1-9c7b249e165b
Name: CARMA_APT3_(Gothic_Panda)_20260212_170901
State: paused
Target Agent: ursjum (DESKTOP-PMT6NT9)
```

---

## 🎓 Advanced Usage

### Custom Scenario Format

Your scenario should include:

- **Threat Actor**: APT group or threat actor name
- **Target Organization**: Type and size
- **MITRE ATT&CK Techniques**: With IDs (T1234.567)
- **Expected Actions**: What each technique does
- **Environment**: OS, software, network requirements

See `scenarios/` for examples.

### Fallback Logic

When a sub-technique isn't available, the system automatically tries the parent:

```python
# T1547.001 (Registry Run Keys) not found
# → Falls back to T1547 (Boot or Logon Autostart Execution)
```

### Best Ability Selection

When multiple abilities exist, the system selects based on:

1. **Platform match** (Windows, Linux, macOS)
2. **Privilege level** (prefers User over Elevated)
3. **Requirements** (prefers fewer dependencies)

---

## 📈 Performance Metrics

### Time Breakdown

| Phase | Duration | Type |
|-------|----------|------|
| Parsing | ~30s | LLM |
| Validation | ~10s | Code |
| Planning | ~40s | LLM |
| Creation | ~5s | Code |
| **Total** | **~1.5min** | - |

### Coverage by Scenario Type

| Scenario Type | Coverage | Reason |
|---------------|----------|--------|
| Post-Exploitation | 80-85% | Caldera excels here |
| Reconnaissance | 40-50% | Out of Caldera scope |
| Mixed | 60-70% | Depends on mix |

---

## 🔍 Troubleshooting

### "No executable techniques found"

- Check if scenario includes MITRE ATT&CK technique IDs
- Verify Caldera server is running and accessible
- Try scenarios with post-exploitation techniques

### "LLM parsing failed"

- Verify Ollama is running: `ollama list`
- Check model is downloaded: `ollama pull qwen2.5:32b`
- Increase LLM timeout in config.py

### "No agents available"

- Deploy Caldera agent on target VM
- Verify agent connection in Caldera UI
- Check agent group matches operation settings

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

---

## 📄 License

MIT License - see LICENSE file for details

---

## 🙏 Acknowledgments

- [MITRE Caldera](https://github.com/mitre/caldera) - C2 framework
- [MITRE ATT&CK](https://attack.mitre.org/) - Threat intelligence framework
- [Ollama](https://ollama.ai/) - Local LLM runtime

---

## 📞 Contact

- **Issues**: [GitHub Issues](https://github.com/yourusername/CARMA-Pipeline/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/CARMA-Pipeline/discussions)

---

**Made with ❤️ for the cybersecurity community**
