# CARMA Pipeline - Quick Start Guide

## 🚀 5-Minute Setup

### 1. Prerequisites

```bash
# Install Python 3.8+
python --version

# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull LLM model
ollama pull qwen2.5:32b

# Start Caldera (in separate terminal)
cd /path/to/caldera
python server.py --insecure
```

### 2. Install CARMA Pipeline

```bash
# Clone repository
git clone https://github.com/yourusername/CARMA-Pipeline.git
cd CARMA-Pipeline

# Install dependencies
pip install -r requirements.txt

# Configure
cp config.example.py config.py
# Edit config.py with your Caldera URL and API key
```

### 3. Run Your First Pipeline

```bash
# Full pipeline on APT3 scenario
python scripts/run_pipeline.py scenarios/APT3_scenario.md
```

Expected output:

```
================================================================================
CARMA FULL PIPELINE EXECUTION
================================================================================

[*] Scenario: scenarios/APT3_scenario.md

================================================================================
PHASE 1: Scenario Parsing
================================================================================
[*] Parsing scenario...
  ✓ Extracted 12 techniques
  ✓ Scenario: Incident Response Testing Scenario
  ✓ Threat Actor: APT3 (Gothic Panda)

================================================================================
PHASE 2: Caldera Validation
================================================================================
[*] Validating techniques with Caldera...
  ✓ T1195  Supply Chain Compromise  → 1 ability
  ✓ T1053.005  Scheduled Task  → 16 abilities
  ...
  ✓ Total: 10/12 executable (83.3%)

================================================================================
PHASE 3: Attack Chain Planning
================================================================================
[*] Planning attack chain with LLM...
  ✓ Attack chain generated: 10 steps

================================================================================
PHASE 4: Caldera Operation Creation
================================================================================
[*] Creating operation...
  ✓ Operation created: 8572faee-ec8e-44e3-91d1-9c7b249e165b

================================================================================
✅ READY FOR EXECUTION!
================================================================================

💡 Next Steps:
    1. Open Caldera UI: http://192.168.50.31:8888/#/operations/...
    2. Review the attack chain
    3. Click 'Start' to begin execution
```

### 4. Execute in Caldera

1. Open the Caldera UI link from output
2. Review the generated attack chain
3. Click "Start" button
4. Monitor execution progress

### 5. Analyze Results

```bash
# After execution completes
python scripts/analyze_results.py <operation_id>
```

---

## 📚 Example Scenarios

### APT29 (Finance/Banking)

```bash
python scripts/run_pipeline.py scenarios/APT29_scenario.md
```

**Expected Coverage**: ~61.5% (8/13 techniques)

**Attack Chain**:

1. Phishing (T1566.001)
2. PowerShell (T1059.001)
3. Registry Run Keys (T1547.001)
4. DCSync (T1003.006)
5. Archive Collection (T1560.001)
6. Exfiltration over HTTPS (T1048.002)

### APT3 (Aerospace/Defence)

```bash
python scripts/run_pipeline.py scenarios/APT3_scenario.md
```

**Expected Coverage**: ~83.3% (10/12 techniques)

**Attack Chain**:

1. Supply Chain Compromise (T1195)
2. Encoded File (T1027.013)
3. Scheduled Task (T1053.005)
4. Windows Service (T1543.003)
5. Password Filter DLL (T1556.002)
6. Process Discovery (T1057)
7. RDP (T1021.001)
8. Automated Collection (T1119)
9. OpenSSL C2 (T1573.002)
10. FTP Exfiltration (T1048.003)

---

## 🔧 Step-by-Step Execution

### Option 1: Individual Steps

```bash
# Step 1: Parse scenario
python scripts/parse_scenario.py scenarios/APT3_scenario.md
# Output: results/parsed_scenario.json

# Step 2: Validate techniques
python scripts/validate_techniques.py results/parsed_scenario.json
# Output: results/validated_scenario.json

# Step 3: Plan attack chain
python scripts/plan_attack_chain.py results/validated_scenario.json
# Output: results/attack_chain.json

# Step 4: Create operation
python scripts/create_operation.py results/attack_chain.json
# Output: results/created_operation.json

# Step 5: Analyze results (after execution)
python scripts/analyze_results.py <operation_id>
# Output: results/operation_results.json
```

### Option 2: Full Pipeline

```bash
# All steps in one command
python scripts/run_pipeline.py scenarios/APT3_scenario.md
```

---

## 📊 Understanding Results

### Validation Summary

```json
{
  "total": 12,
  "executable": 10,
  "non_executable": 2,
  "coverage_rate": 83.3
}
```

- **total**: Total techniques in scenario
- **executable**: Techniques available in Caldera
- **non_executable**: Techniques not available
- **coverage_rate**: Percentage of executable techniques

### Attack Chain

```json
{
  "step": 1,
  "technique_id": "T1195",
  "technique_name": "Supply Chain Compromise",
  "tactic": "initial-access",
  "ability_id": "4f0c66956fc56e1ab11f4a1e394a4fd0",
  "ability_name": "Octopus Scanner Malware",
  "reason": "Initial access via supply-chain",
  "dependencies": []
}
```

- **step**: Execution order
- **technique_id**: MITRE ATT&CK ID
- **ability_id**: Caldera ability to execute
- **reason**: Why this step is needed
- **dependencies**: Previous steps required

### Operation Results

```json
{
  "total": 14,
  "success": 8,
  "failed": 0,
  "running": 6,
  "by_technique": {...},
  "by_tactic": {...}
}
```

- **total**: Total commands executed
- **success**: Successfully completed
- **failed**: Failed to execute
- **running**: Still running or timed out

---

## 🎓 Advanced Usage

### Custom Scenario

Create `my_scenario.md`:

```markdown
# My Custom Scenario

**Company:** Tech Startup (10-50 employees)
**Threat Actor:** Custom APT

## Attack Phases

| Phase | Technique | Description |
|-------|-----------|-------------|
| Initial Access | T1566.001 | Spearphishing Attachment |
| Execution | T1059.001 | PowerShell |
| Persistence | T1547.001 | Registry Run Keys |
```

Run pipeline:

```bash
python scripts/run_pipeline.py my_scenario.md
```

### Agent Selection

```python
# In scripts/create_operation.py
operation = creator.create_operation_from_plan(
    operation_plan,
    agent_paw="specific_agent_paw",  # Specify agent
    auto_start=False  # Paused mode
)
```

### LLM Model Selection

Edit `config.py`:

```python
LLM_CONFIG = {
    "model": "llama3.1:70b",  # Use different model
    "temperature": 0.0  # More deterministic
}
```

---

## 🐛 Troubleshooting

### "No executable techniques found"

**Cause**: Scenario contains only reconnaissance or pre-attack techniques

**Solution**:

- Use scenarios with post-exploitation techniques
- Check Caldera has abilities loaded
- Verify Caldera server is running

### "LLM timeout"

**Cause**: Large scenario or slow LLM

**Solution**:

- Use smaller/faster LLM model
- Reduce scenario size
- Increase timeout in code

### "No agents available"

**Cause**: No Caldera agents deployed

**Solution**:

1. Deploy agent on target VM
2. Verify agent connection in Caldera UI
3. Check agent group matches operation

### "API connection failed"

**Cause**: Caldera server not accessible

**Solution**:

- Verify Caldera is running
- Check URL in config.py
- Test: `curl http://your-caldera-url/api/v2/health`

---

## 📖 Next Steps

1. **Read Documentation**
   - [Architecture](docs/ARCHITECTURE.md)
   - [API Reference](docs/API.md)
   - [Examples](docs/EXAMPLES.md)

2. **Try Different Scenarios**
   - APT29 (Finance)
   - APT3 (Aerospace)
   - Create your own

3. **Customize Pipeline**
   - Modify LLM prompts
   - Add custom validation logic
   - Extend results analysis

4. **Contribute**
   - Report issues
   - Submit pull requests
   - Share scenarios

---

**Happy Hacking! 🎯**
