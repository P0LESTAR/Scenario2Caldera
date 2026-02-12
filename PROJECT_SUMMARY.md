# CARMA Pipeline - Project Summary

## 📦 What's Included

This standalone GitHub repository contains the complete CARMA Pipeline system for automating cybersecurity scenario execution in Caldera.

### Directory Structure

```
CARMA-Pipeline/
├── README.md                      # Main documentation
├── LICENSE                        # MIT License
├── requirements.txt               # Python dependencies
├── config.example.py              # Configuration template
├── .gitignore                     # Git ignore rules
│
├── core/                          # Core modules (6 files)
│   ├── scenario_parser.py         # LLM-based scenario parser
│   ├── caldera_client.py          # Enhanced Caldera API client
│   ├── scenario_validator.py      # Technique validation
│   ├── llm_orchestrator.py        # Attack chain planner
│   ├── operation_creator.py       # Caldera operation creator
│   └── results_analyzer.py        # Results analysis
│
├── scripts/                       # Executable scripts (2 files)
│   ├── run_pipeline.py            # Full pipeline runner
│   └── parse_scenario.py          # Scenario parser only
│
├── scenarios/                     # Example scenarios (2 files)
│   ├── APT29_scenario.md          # Finance/Banking scenario
│   └── APT3_scenario.md           # Aerospace/Defence scenario
│
└── docs/                          # Documentation (2 files)
    ├── ARCHITECTURE.md            # System architecture
    └── QUICKSTART.md              # Quick start guide
```

---

## 🎯 Features Included

### ✅ Core Functionality

1. **LLM-Based Scenario Parsing**
   - Extracts MITRE ATT&CK techniques
   - Identifies tactics and environment requirements
   - Supports markdown format

2. **Caldera Validation**
   - Queries Caldera API for available abilities
   - Parent technique fallback logic
   - Best ability selection algorithm

3. **Attack Chain Planning**
   - LLM generates logical execution order
   - Dependency resolution
   - Kill chain reasoning

4. **Operation Creation**
   - Automatic Caldera adversary creation
   - Operation generation with agent targeting
   - Paused/running mode support

5. **Results Analysis**
   - Execution results collection
   - Success/failure rate analysis
   - Technique and tactic breakdown

### ✅ Example Scenarios

1. **APT29 (Finance/Banking)**
   - 13 techniques
   - 61.5% coverage
   - 8-step attack chain

2. **APT3 (Aerospace/Defence)**
   - 12 techniques
   - 83.3% coverage
   - 10-step attack chain

### ✅ Documentation

1. **README.md** - Main documentation with:
   - Overview and features
   - Quick start guide
   - Usage examples
   - Performance metrics

2. **ARCHITECTURE.md** - Technical details:
   - System architecture
   - Component design
   - Data flow
   - Design decisions

3. **QUICKSTART.md** - Getting started:
   - 5-minute setup
   - Example runs
   - Troubleshooting

---

## 🚀 Quick Start

```bash
# 1. Clone repository
git clone https://github.com/yourusername/CARMA-Pipeline.git
cd CARMA-Pipeline

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure
cp config.example.py config.py
# Edit config.py with your Caldera URL and API key

# 4. Run pipeline
python scripts/run_pipeline.py scenarios/APT3_scenario.md
```

---

## 📊 Performance

### APT29 Scenario

- **Time**: ~2 minutes
- **Coverage**: 61.5% (8/13)
- **Attack Chain**: 8 steps

### APT3 Scenario

- **Time**: ~1.5 minutes
- **Coverage**: 83.3% (10/12)
- **Attack Chain**: 10 steps

---

## 🔧 Dependencies

### Required

- **Python 3.8+**
- **Ollama** (for LLM)
- **Caldera C2** (running server)
- **Caldera Agent** (deployed on target)

### Python Packages

- `ollama>=0.1.0` - LLM client
- `requests>=2.31.0` - HTTP requests

---

## 📝 Configuration

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

---

## 🎓 Usage Examples

### Full Pipeline

```bash
python scripts/run_pipeline.py scenarios/APT3_scenario.md
```

### Parse Only

```bash
python scripts/parse_scenario.py scenarios/APT3_scenario.md
```

---

## 📁 Output Files

All results saved to `results/session_TIMESTAMP/`:

1. `parsed_scenario.json` - LLM parsing results
2. `validated_scenario.json` - Caldera validation
3. `attack_chain.json` - LLM attack chain
4. `operation_plan.json` - Operation plan
5. `created_operation.json` - Caldera operation details

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## 📄 License

MIT License - see LICENSE file

---

## 🙏 Acknowledgments

- [MITRE Caldera](https://github.com/mitre/caldera)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Ollama](https://ollama.ai/)

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/CARMA-Pipeline/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/CARMA-Pipeline/discussions)

---

**Ready to automate your red team operations! 🎯**
