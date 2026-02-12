#!/usr/bin/env python3
"""
LLM Orchestrator
실행 가능한 techniques만 사용하여 최적화된 공격 체인 생성
"""

import sys
import json
from pathlib import Path
from typing import Dict, List, Optional
from ollama import Client as OllamaClient

# 상위 디렉토리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import LLM_CONFIG
from core.caldera_client import CalderaClient


class LLMOrchestrator:
    """
    LLM을 활용한 공격 체인 오케스트레이션
    Caldera에서 검증된 기법들을 논리적인 순서로 정렬
    """

    def __init__(self):
        self.client = OllamaClient(host=LLM_CONFIG["host"])
        self.model = LLM_CONFIG["model"]
        self.caldera_client = CalderaClient()

    def plan_executable_attack_chain(self, validated_techniques: List[Dict],
                                     scenario_context: Dict = None) -> List[Dict]:
        """
        실행 가능한 techniques만 사용하여 최적화된 공격 체인 생성
        
        Args:
            validated_techniques: Caldera 검증이 완료된 technique 목록
            scenario_context: 시나리오 컨텍스트 (이름, 타겟, 위협 행위자 등)
        
        Returns:
            List of attack steps
        """
        print("\n[*] Planning executable attack chain with LLM...")
        
        # 실행 가능한 techniques만 필터링
        executable_techs = [
            t for t in validated_techniques
            if t.get("caldera_validation", {}).get("executable", False)
        ]
        
        if not executable_techs:
            print("  [!] No executable techniques found!")
            return []
        
        print(f"  OK Using {len(executable_techs)} executable techniques")
        
        # 각 technique의 best ability 선택
        techniques_with_abilities = []
        
        for tech in executable_techs:
            tech_id = tech["technique_id"]
            
            # Caldera에서 abilities 조회
            result = self.caldera_client.get_abilities_with_fallback(tech_id)
            
            if result['abilities']:
                # Best ability 선택
                best_ability = self.caldera_client.select_best_ability(
                    result['abilities'],
                    prefer_low_privilege=True,  # 낮은 권한 선호
                    platform="windows"          # 윈도우 타겟 가정 (추후 동적 처리 가능)
                )
                
                if best_ability:
                    techniques_with_abilities.append({
                        "technique_id": tech_id,
                        "technique_name": tech.get("technique_name"),
                        "tactic": tech.get("tactic"),
                        "description": tech.get("description"),
                        "expected_action": tech.get("expected_action"),
                        "ability_id": best_ability.get("ability_id"),
                        "ability_name": best_ability.get("name"),
                        "ability_privilege": best_ability.get("privilege", "User"),
                        "ability_count": len(result['abilities'])
                    })
        
        print(f"  OK Matched {len(techniques_with_abilities)} techniques with abilities")
        
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
        
        # Techniques 요약 (ability 정보 포함)
        techniques_summary = "\n".join([
            f"""  {i+1}. {t['technique_id']}: {t['technique_name']}
     Tactic: {t['tactic']}
     Ability: {t['ability_name']} (Privilege: {t['ability_privilege']})
     Expected: {t['expected_action'][:100]}..."""
            for i, t in enumerate(techniques_with_abilities)
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
            import re
            result_text = re.sub(r"```json\s*", "", result_text)
            result_text = re.sub(r"```\s*", "", result_text)
            
            # JSON 파싱
            plan = json.loads(result_text)
            
            # Technique 정보와 ability 정보 병합
            enriched_plan = []
            for step in plan:
                tech_id = step.get("technique_id")
                
                # 해당 technique 찾기
                tech_info = next(
                    (t for t in techniques_with_abilities if t["technique_id"] == tech_id),
                    None
                )
                
                if tech_info:
                    enriched_step = {
                        # 기존 step 정보 (reason, dependencies 등)
                        **step,
                        # 추가 정보 (이름, ability 등)
                        "technique_name": tech_info["technique_name"],
                        "tactic": tech_info["tactic"],
                        "ability_id": tech_info["ability_id"],
                        "ability_name": tech_info["ability_name"]
                    }
                    
                    # Ensure step is int
                    if "step" in enriched_step:
                         enriched_step["step"] = int(enriched_step["step"])

                    enriched_plan.append(enriched_step)
            
            print(f"  OK Generated attack chain with {len(enriched_plan)} steps")
            
            # 요약 출력
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


# Alias for backward compatibility
EnhancedLLMOrchestrator = LLMOrchestrator

if __name__ == "__main__":
    print("="*80)
    print("LLM Orchestrator Test")
    print("="*80)
    # 테스트 코드 생략
