#!/usr/bin/env python3
"""
LLM 기반 시나리오 파서
AttackGen 시나리오에서 MITRE ATT&CK 기법 및 환경 정보 추출
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from ollama import Client as OllamaClient
from config import LLM_CONFIG, SCENARIOS_DIR


class ScenarioParser:
    """LLM을 활용한 시나리오 파서"""

    def __init__(self):
        self.client = OllamaClient(host=LLM_CONFIG["host"])
        self.model = LLM_CONFIG["model"]

    def parse_scenario_file(self, scenario_path: str) -> Dict:
        """
        시나리오 파일을 읽고 LLM으로 파싱

        Args:
            scenario_path: 시나리오 파일 경로

        Returns:
            {
                "scenario_name": str,
                "target_org": str,
                "threat_actor": str,
                "techniques": [
                    {
                        "technique_id": "T1190",
                        "technique_name": "Exploit Public-Facing Application",
                        "tactic": "initial-access",
                        "description": "...",
                        "expected_action": "..."
                    },
                    ...
                ],
                "environment": {
                    "os_requirements": ["Windows Server 2019", "Ubuntu 22.04"],
                    "software": ["IIS", "MySQL", "Active Directory"],
                    "network_config": {...}
                }
            }
        """
        # 시나리오 파일 읽기
        scenario_path = Path(scenario_path)
        if not scenario_path.exists():
            scenario_path = SCENARIOS_DIR / scenario_path

        with open(scenario_path, "r", encoding="utf-8") as f:
            scenario_text = f.read()

        print(f"[*] Parsing scenario: {scenario_path.name}")

        # LLM 프롬프트
        system_prompt = """You are an expert in MITRE ATT&CK framework and cybersecurity scenario analysis.
Your task is to extract structured information from incident response scenarios.

Output ONLY valid JSON with this exact structure:
{
  "scenario_name": "string",
  "target_org": "string",
  "threat_actor": "string",
  "techniques": [
    {
      "technique_id": "T1234.567",
      "technique_name": "Technique Name",
      "tactic": "tactic-name",
      "phase": "Phase Name",
      "description": "Brief description",
      "expected_action": "What the attacker does"
    }
  ],
  "environment": {
    "os_requirements": ["OS1", "OS2"],
    "software": ["Software1", "Software2"],
    "network_segments": ["DMZ", "Internal"],
    "required_services": ["Service1", "Service2"]
  },
  "vm_requirements": [
    {"type": "workstation", "count": 1, "os": "Windows 10"},
    {"type": "server", "count": 1, "os": "Windows Server 2019"}
  ]
}

IMPORTANT:
1. Extract ALL MITRE ATT&CK technique IDs (format: T1234 or T1234.567)
2. Map each technique to its MITRE tactic (e.g., initial-access, execution, persistence)
3. Identify OS and software requirements from the scenario
4. Determine VM requirements based on scope (workstation, server, domain-controller, web-server, database-server)
5. Output ONLY the JSON, no explanations or markdown"""

        user_prompt = f"""Extract structured data from this scenario:

{scenario_text[:8000]}

Output the JSON structure."""

        try:
            response = self.client.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                options={"temperature": LLM_CONFIG["temperature"]}
            )

            result_text = response["message"]["content"].strip()

            # JSON 추출 (마크다운 코드블록 제거)
            result_text = re.sub(r"```json\s*", "", result_text)
            result_text = re.sub(r"```\s*", "", result_text)

            # JSON 파싱
            parsed_data = json.loads(result_text)

            print(f"  OK Extracted {len(parsed_data.get('techniques', []))} techniques")
            print(f"  OK Target: {parsed_data.get('target_org', 'N/A')}")
            print(f"  OK Threat Actor: {parsed_data.get('threat_actor', 'N/A')}")

            return parsed_data

        except json.JSONDecodeError as e:
            print(f"  [!] JSON parsing failed: {e}")
            print(f"  [!] Raw response: {result_text[:500]}")
            return None
        except Exception as e:
            print(f"  [!] Error: {e}")
            return None

    def get_techniques_by_tactic(self, parsed_data: Dict, tactic: str) -> List[Dict]:
        """특정 전술(tactic)에 해당하는 기법들만 반환"""
        techniques = parsed_data.get("techniques", [])
        return [t for t in techniques if t.get("tactic") == tactic]

    def extract_technique_ids(self, parsed_data: Dict) -> List[str]:
        """기법 ID 목록만 추출"""
        return [t["technique_id"] for t in parsed_data.get("techniques", [])]


if __name__ == "__main__":
    # 테스트
    parser = ScenarioParser()

    # APT29 시나리오 파싱
    result = parser.parse_scenario_file("APT29_Enterprise_financeBanking.md")

    if result:
        print("\n" + "="*60)
        print("Parsed Scenario:")
        print("="*60)
        print(json.dumps(result, indent=2, ensure_ascii=False))

        # 기법 ID 목록
        tech_ids = parser.extract_technique_ids(result)
        print(f"\n[*] Technique IDs: {', '.join(tech_ids)}")

        # Initial Access 기법들
        initial_access = parser.get_techniques_by_tactic(result, "initial-access")
        print(f"\n[*] Initial Access techniques: {len(initial_access)}")
        for t in initial_access:
            print(f"    - {t['technique_id']}: {t['technique_name']}")
