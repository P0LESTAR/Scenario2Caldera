#!/usr/bin/env python3
"""
LLM 기반 TTP 실행 오케스트레이터
공격 순서 결정 및 실행 전략 수립
"""

import json
from typing import Dict, List, Optional
from ollama import Client as OllamaClient
from config import LLM_CONFIG


class LLMOrchestrator:
    """LLM을 활용한 공격 체인 오케스트레이션"""

    def __init__(self):
        self.client = OllamaClient(host=LLM_CONFIG["host"])
        self.model = LLM_CONFIG["model"]

    def plan_attack_chain(self, techniques: List[Dict],
                         available_abilities: List[Dict],
                         target_info: Optional[Dict] = None) -> List[Dict]:
        """
        주어진 기법들을 실행 가능한 순서로 정렬

        Args:
            techniques: 시나리오에서 추출한 MITRE 기법 목록
            available_abilities: Caldera에서 사용 가능한 Ability 목록
            target_info: 타겟 환경 정보 (OS, 네트워크 등)

        Returns:
            [
                {
                    "step": 1,
                    "technique_id": "T1190",
                    "ability_id": "abc-123",
                    "reason": "Initial access through public-facing app",
                    "dependencies": []
                },
                ...
            ]
        """
        print("[*] Planning attack chain with LLM...")

        # LLM 프롬프트
        system_prompt = """You are a red team operations planner expert in MITRE ATT&CK.
Your task is to create a logical attack chain execution plan.

Rules:
1. Follow the cyber kill chain: Reconnaissance → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → Exfiltration
2. Ensure each step's prerequisites are met by previous steps
3. Match techniques to available Caldera abilities
4. Consider target environment constraints

Output ONLY valid JSON array:
[
  {
    "step": 1,
    "technique_id": "T1234",
    "ability_id": "ability-uuid",
    "reason": "Why this step is needed now",
    "dependencies": ["T1111", "T1222"]
  }
]"""

        # 기법 및 Ability 정보 요약
        techniques_summary = "\n".join([
            f"  - {t['technique_id']}: {t.get('technique_name', 'N/A')} ({t.get('tactic', 'unknown')})"
            for t in techniques
        ])

        abilities_summary = "\n".join([
            f"  - {a['ability_id']}: {a.get('name', 'N/A')} (Technique: {a.get('technique_id', 'N/A')}, Platform: {a.get('executors', [{}])[0].get('platform', 'any') if a.get('executors') else 'any'})"
            for a in available_abilities[:50]  # 너무 많으면 잘라냄
        ])

        user_prompt = f"""Create an attack chain execution plan.

MITRE Techniques Required:
{techniques_summary}

Available Caldera Abilities:
{abilities_summary}

Target Environment:
{json.dumps(target_info, indent=2) if target_info else 'Not specified'}

Generate the execution plan as JSON array."""

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

            print(f"  OK Generated attack chain with {len(plan)} steps")

            for step in plan[:5]:
                print(f"    {step['step']}. {step['technique_id']} → {step.get('ability_id', 'N/A')}")

            return plan

        except json.JSONDecodeError as e:
            print(f"  [!] JSON parsing failed: {e}")
            print(f"  [!] Raw response: {result_text[:500]}")
            return []
        except Exception as e:
            print(f"  [!] Error: {e}")
            return []

    def select_ability_for_technique(self, technique_id: str,
                                    available_abilities: List[Dict],
                                    target_platform: str = "linux") -> Optional[str]:
        """
        특정 기법에 가장 적합한 Ability 선택

        Args:
            technique_id: MITRE 기법 ID
            available_abilities: 사용 가능한 Ability 목록
            target_platform: 타겟 플랫폼 (linux, windows, darwin)

        Returns:
            선택된 ability_id
        """
        # 해당 기법에 매칭되는 abilities 필터링
        matching = [
            a for a in available_abilities
            if a.get("technique_id") == technique_id
        ]

        if not matching:
            print(f"  [!] No ability found for {technique_id}")
            return None

        # 플랫폼 필터링
        platform_matched = [
            a for a in matching
            if any(
                ex.get("platform") == target_platform
                for ex in a.get("executors", [])
            )
        ]

        if platform_matched:
            # 가장 첫 번째 것 선택
            selected = platform_matched[0]
            print(f"  OK Selected {selected['ability_id']} for {technique_id} ({target_platform})")
            return selected["ability_id"]
        else:
            # 플랫폼 상관없이 첫 번째 것
            selected = matching[0]
            print(f"  OK Selected {selected['ability_id']} for {technique_id} (any platform)")
            return selected["ability_id"]

    


if __name__ == "__main__":
    # 테스트
    orchestrator = LLMOrchestrator()

    # 샘플 기법
    sample_techniques = [
        {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "initial-access"},
        {"technique_id": "T1047", "technique_name": "Windows Management Instrumentation", "tactic": "execution"},
        {"technique_id": "T1003.006", "technique_name": "DCSync", "tactic": "credential-access"},
    ]

    # 샘플 abilities (실제로는 Caldera에서 가져와야 함)
    sample_abilities = [
        {"ability_id": "exploit-web-001", "name": "Web Exploit", "technique_id": "T1190", "executors": [{"platform": "linux"}]},
        {"ability_id": "wmi-exec-001", "name": "WMI Execution", "technique_id": "T1047", "executors": [{"platform": "windows"}]},
    ]

    # 공격 체인 계획
    plan = orchestrator.plan_attack_chain(sample_techniques, sample_abilities)

    if plan:
        print("\n" + "="*60)
        print("Attack Chain Plan:")
        print("="*60)
        print(json.dumps(plan, indent=2, ensure_ascii=False))
