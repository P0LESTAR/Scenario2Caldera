#!/usr/bin/env python3
"""
LLM Orchestrator
검증 완료된 기법들을 LLM을 통해 논리적인 공격 순서로 정렬
"""

import sys
import json
import re
from pathlib import Path
from typing import Dict, List
from ollama import Client as OllamaClient

# 상위 디렉토리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import LLM_CONFIG


class LLMOrchestrator:
    """
    LLM을 활용한 공격 체인 순서 결정
    (Caldera ability 조회는 ScenarioValidator에서 이미 완료됨)
    """

    def __init__(self):
        self.client = OllamaClient(host=LLM_CONFIG["host"])
        self.model = LLM_CONFIG["model"]

    def plan_executable_attack_chain(self, validated_techniques: List[Dict],
                                     scenario_context: Dict = None) -> List[Dict]:
        """
        검증 완료된 techniques를 논리적인 공격 순서로 정렬
        
        Args:
            validated_techniques: ScenarioValidator에서 검증 완료된 technique 목록
                (각 technique에 caldera_validation.selected_ability가 포함됨)
            scenario_context: 시나리오 컨텍스트
        
        Returns:
            공격 순서가 정해진 step 목록
        """
        print("\n[*] Planning executable attack chain with LLM...")
        
        # 실행 가능 + ability가 선택된 techniques만 필터링
        executable_techs = []
        for t in validated_techniques:
            validation = t.get("caldera_validation", {})
            if validation.get("executable") and validation.get("selected_ability"):
                executable_techs.append(t)
        
        if not executable_techs:
            print("  [!] No executable techniques with selected abilities found!")
            return []
        
        print(f"  OK Using {len(executable_techs)} executable techniques")
        
        # LLM 프롬프트
        system_prompt = """You are a red team operations planner expert in MITRE ATT&CK.
Your task is to create a logical, executable attack chain.

Rules:
1. Follow the cyber kill chain order when possible
2. Consider dependencies between techniques
3. Each technique has a specific Caldera ability already selected
4. Provide clear reasoning for the execution order

Output ONLY valid JSON array:
[
  {
    "step": 1,
    "technique_id": "T1234",
    "reason": "Why this step comes first",
    "dependencies": []
  }
]"""
        
        # Techniques 요약
        techniques_summary = "\n".join([
            f"""  {i+1}. {t['technique_id']}: {t['technique_name']}
     Tactic: {t['tactic']}
     Ability: {t['caldera_validation']['selected_ability']['name']} (Privilege: {t['caldera_validation']['selected_ability']['privilege']})
     Expected: {t.get('expected_action', 'N/A')[:100]}..."""
            for i, t in enumerate(executable_techs)
        ])
        
        # 시나리오 컨텍스트
        context_str = ""
        if scenario_context:
            context_str = f"""
Scenario: {scenario_context.get('scenario_name', 'N/A')}
Target: {scenario_context.get('target_org', 'N/A')}
Threat Actor: {scenario_context.get('threat_actor', 'N/A')}
"""
        
        user_prompt = f"""Create an optimal attack chain execution order.

{context_str}

Available Executable Techniques (with Caldera Abilities):
{techniques_summary}

IMPORTANT:
- All techniques above are executable in Caldera
- Each has a pre-selected ability
- Order them logically following the attack lifecycle
- Consider dependencies (e.g., need credentials before lateral movement)

Generate the execution plan as JSON array with step numbers and reasons."""
        
        try:
            response = self.client.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                options={"temperature": 0.1}
            )
            
            result_text = response["message"]["content"].strip()
            
            # JSON 추출
            result_text = re.sub(r"```json\s*", "", result_text)
            result_text = re.sub(r"```\s*", "", result_text)
            
            plan = json.loads(result_text)
            
            # LLM 결과에 ability 정보 병합
            enriched_plan = []
            for step in plan:
                tech_id = step.get("technique_id")
                
                tech_info = next(
                    (t for t in executable_techs if t["technique_id"] == tech_id),
                    None
                )
                
                if tech_info:
                    selected = tech_info["caldera_validation"]["selected_ability"]
                    enriched_plan.append({
                        "step": int(step.get("step", 0)),
                        "technique_id": tech_id,
                        "technique_name": tech_info["technique_name"],
                        "tactic": tech_info["tactic"],
                        "ability_id": selected["ability_id"],
                        "ability_name": selected["name"],
                        "reason": step.get("reason", ""),
                        "dependencies": step.get("dependencies", [])
                    })
            
            print(f"  OK Generated attack chain with {len(enriched_plan)} steps")
            
            print(f"\n[*] Attack Chain Summary:")
            for step in enriched_plan:
                print(f"    {step['step']}. {step['technique_id']} ({step['tactic']})")
                print(f"       → {step['ability_name']}")
                print(f"       Reason: {step.get('reason', 'N/A')}")
            
            return enriched_plan
        
        except json.JSONDecodeError as e:
            print(f"  [!] JSON parsing failed: {e}")
            print(f"  [!] Raw response: {result_text[:500]}")
            return []
        except Exception as e:
            print(f"  [!] Error: {e}")
            return []
