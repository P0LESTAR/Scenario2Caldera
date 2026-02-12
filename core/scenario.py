#!/usr/bin/env python3
"""
Scenario Processor
시나리오 파싱 (LLM) + Caldera 검증 + Best Ability 선택
"""

import sys
import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from ollama import Client as OllamaClient

# 상위 디렉토리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import LLM_CONFIG, SCENARIOS_DIR
from core.caldera_client import CalderaClient


class ScenarioProcessor:
    """시나리오 파싱 + Caldera 검증 + Ability 선택"""

    def __init__(self):
        self.llm_client = OllamaClient(host=LLM_CONFIG["host"])
        self.model = LLM_CONFIG["model"]
        self.caldera_client = CalderaClient()

    # =========================================================================
    # Phase 1: LLM 시나리오 파싱
    # =========================================================================
    def parse(self, scenario_path: str) -> Optional[Dict]:
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
                    }, ...
                ],
                "environment": {
                    "os_requirements": [...],
                    "software": [...],
                    "network_segments": [...],
                    "required_services": [...]
                }
            }
        """
        scenario_path = Path(scenario_path)
        if not scenario_path.exists():
            scenario_path = SCENARIOS_DIR / scenario_path

        with open(scenario_path, "r", encoding="utf-8") as f:
            scenario_text = f.read()

        print(f"[*] Parsing scenario: {scenario_path.name}")

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
4. Determine VM requirements based on scope
5. Output ONLY the JSON, no explanations or markdown"""

        user_prompt = f"""Extract structured data from this scenario:

{scenario_text[:8000]}

Output the JSON structure."""

        try:
            response = self.llm_client.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                options={"temperature": LLM_CONFIG["temperature"]}
            )

            result_text = response["message"]["content"].strip()
            result_text = re.sub(r"```json\s*", "", result_text)
            result_text = re.sub(r"```\s*", "", result_text)

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

    # =========================================================================
    # Phase 2: Caldera 검증 + Best Ability 선택
    # =========================================================================
    def validate(self, parsed_data: Dict) -> Dict:
        """
        파싱된 techniques를 Caldera로 검증하고 Best Ability 선택

        Args:
            parsed_data: parse()의 결과

        Returns:
            검증 정보 + 선택된 ability가 추가된 parsed_data
        """
        print("\n[*] Validating techniques with Caldera...")

        techniques = parsed_data.get("techniques", [])

        stats = {
            "total": len(techniques),
            "executable": 0,
            "non_executable": 0,
            "exact_match": 0,
            "parent_fallback": 0
        }

        for tech in techniques:
            tech_id = tech["technique_id"]

            # Caldera에서 ability 조회 (fallback 포함)
            result = self.caldera_client.get_abilities_with_fallback(tech_id)

            # 검증 정보 추가
            tech["caldera_validation"] = {
                "executable": result['match_type'] != 'none',
                "match_type": result['match_type'],
                "ability_count": len(result['abilities']),
                "fallback_applied": result['fallback_applied']
            }

            # 실행 가능하면 Best Ability 선택
            if result['match_type'] != 'none' and result['abilities']:
                best = self.caldera_client.select_best_ability(
                    result['abilities'],
                    prefer_low_privilege=True,
                    platform="windows"
                )
                if best:
                    tech["caldera_validation"]["selected_ability"] = {
                        "ability_id": best.get("ability_id"),
                        "name": best.get("name"),
                        "privilege": best.get("privilege", "User"),
                        "tactic": best.get("tactic", ""),
                    }

            # 통계 및 출력
            reason = ""
            status = ""

            if result['match_type'] == 'exact':
                stats['executable'] += 1
                stats['exact_match'] += 1
                status = "✓"
                reason = f"{len(result['abilities'])} abilities"
            elif result['match_type'] == 'parent':
                stats['executable'] += 1
                stats['parent_fallback'] += 1
                status = "⚠"
                reason = f"Parent fallback ({result['technique_id']})"
            else:
                stats['non_executable'] += 1
                status = "✗"
                tactic = tech.get('tactic', '')
                tech_name_lower = tech.get('technique_name', '').lower()

                if tactic == 'reconnaissance':
                    reason = "Reconnaissance (Caldera 범위 밖)"
                elif tactic == 'resource-development':
                    reason = "Resource Development (Caldera 범위 밖)"
                elif 'exploit' in tech_name_lower:
                    reason = "CVE 의존적 (환경 특정)"
                else:
                    reason = "Caldera ability 없음"

                tech["caldera_validation"]["warning"] = reason

            print(f"  {status} {tech_id:12} {tech.get('technique_name', 'N/A'):50} → {reason}")

        # 검증 요약
        stats['coverage_rate'] = (stats['executable'] / stats['total'] * 100) if stats['total'] > 0 else 0
        parsed_data["validation"] = stats

        print(f"\n[*] Validation Summary:")
        print(f"    Total Techniques:     {stats['total']}")
        print(f"    ✓ Executable:         {stats['executable']} ({stats['coverage_rate']:.1f}%)")
        print(f"      - Exact Match:      {stats['exact_match']}")
        print(f"      - Parent Fallback:  {stats['parent_fallback']}")
        print(f"    ✗ Non-Executable:     {stats['non_executable']}")

        return parsed_data

    # =========================================================================
    # Helpers
    # =========================================================================
    def get_executable_techniques(self, parsed_data: Dict) -> List[Dict]:
        """실행 가능한 techniques만 필터링"""
        techniques = parsed_data.get("techniques", [])
        executable = [
            t for t in techniques
            if t.get("caldera_validation", {}).get("executable", False)
        ]
        print(f"\n[*] Filtered executable techniques: {len(executable)}/{len(techniques)}")
        return executable

    def get_techniques_by_tactic(self, parsed_data: Dict, tactic: str) -> List[Dict]:
        """특정 전술(tactic)에 해당하는 기법들만 반환"""
        return [t for t in parsed_data.get("techniques", []) if t.get("tactic") == tactic]

    def extract_technique_ids(self, parsed_data: Dict) -> List[str]:
        """기법 ID 목록만 추출"""
        return [t["technique_id"] for t in parsed_data.get("techniques", [])]

    def process(self, scenario_path: str) -> Optional[Dict]:
        """parse → validate를 한번에 실행"""
        parsed = self.parse(scenario_path)
        if not parsed:
            return None
        return self.validate(parsed)
