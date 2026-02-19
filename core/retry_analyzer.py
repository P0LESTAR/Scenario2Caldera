#!/usr/bin/env python3
"""
Retry Analyzer
실패한 Operation의 원인을 LLM으로 분석하고, 대체 기법으로 보완 Operation 실행
"""

import sys
import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from ollama import Client as OllamaClient

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import LLM_CONFIG
from core.caldera_client import CalderaClient


class RetryAnalyzer:
    """실패 분석 → 대체 추천 → 보완 Operation"""

    def __init__(self):
        self.llm_client = OllamaClient(host=LLM_CONFIG["host"])
        self.model = LLM_CONFIG["model"]
        self.caldera = CalderaClient()

    # =========================================================================
    # 1. LLM 실패 분석
    # =========================================================================
    def analyze_failures(self, failed_links: List[Dict],
                         agent_info: Dict) -> List[Dict]:
        """
        LLM으로 실패 원인 분류 + 대체 기법 추천

        Args:
            failed_links: status != 0인 링크 목록
            agent_info: {"platform": "windows", "privilege": "Elevated"}

        Returns:
            [
                {
                    "failed_technique_id": "T1543.003",
                    "failure_reason": "permission_denied",
                    "recoverable": true,
                    "recommendation": {
                        "action": "replace_technique" | "replace_ability" | "skip",
                        "alternative_technique_id": "T1547.001",
                        "alternative_tactic": "persistence",
                        "reason": "..."
                    }
                }
            ]
        """
        print("\n[*] Analyzing failures with LLM...")

        if not failed_links:
            print("  No failures to analyze")
            return []

        # 실패 정보 요약 (중복 technique 제거)
        seen_techniques = set()
        failure_summary = []

        for link in failed_links:
            ability = link.get('ability', {})
            tech_id = ability.get('technique_id', 'Unknown')

            if tech_id in seen_techniques:
                continue
            seen_techniques.add(tech_id)

            failure_summary.append({
                "technique_id": tech_id,
                "technique_name": ability.get('technique_name',
                                              ability.get('name', 'Unknown')),
                "tactic": ability.get('tactic', 'Unknown'),
                "ability_name": ability.get('name', 'Unknown'),
                "status": link.get('status', -999),
                "output_preview": str(link.get('output', ''))[:200]
            })

        print(f"  Failed techniques (unique): {len(failure_summary)}")

        system_prompt = """You are a red team operations analyst expert in MITRE ATT&CK and Caldera.
Your task is to analyze why attack techniques failed and recommend alternatives.

Failure reason categories:
- "permission_denied": Needs higher privilege than available
- "tool_not_installed": Required tool/binary not present on target
- "parameter_error": Wrong path, filename, or configuration
- "environment_mismatch": OS version, missing service, or config difference
- "network_error": Connectivity or firewall issue
- "unknown": Cannot determine from available info

For recommendations, choose ONE action:
- "replace_technique": Use a DIFFERENT technique ID from the same tactic
- "replace_ability": Use a different ability for the SAME technique ID
- "skip": Not recoverable in current environment

Output ONLY valid JSON array. No explanations outside JSON."""

        user_prompt = f"""Analyze these failed attack steps and recommend alternatives.

Agent Info:
  Platform: {agent_info.get('platform', 'windows')}
  Privilege: {agent_info.get('privilege', 'Unknown')}

Failed Steps:
{json.dumps(failure_summary, indent=2)}

For each failure, provide:
1. Root cause classification (failure_reason)
2. Whether it's recoverable (true/false)
3. If recoverable, recommend a specific alternative MITRE technique ID

Output JSON array:
[
  {{
    "failed_technique_id": "T1234.567",
    "failure_reason": "category",
    "recoverable": true,
    "recommendation": {{
      "action": "replace_technique",
      "alternative_technique_id": "T1234",
      "alternative_tactic": "tactic-name",
      "reason": "brief explanation"
    }}
  }}
]"""

        try:
            response = self.llm_client.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                options={"temperature": 0.0}
            )

            result_text = response["message"]["content"].strip()
            result_text = re.sub(r"```json\s*", "", result_text)
            result_text = re.sub(r"```\s*", "", result_text)

            recommendations = json.loads(result_text)

            # 결과 출력
            recoverable_count = sum(1 for r in recommendations if r.get('recoverable'))
            print(f"\n[*] LLM Analysis Results:")
            print(f"    Total failures:  {len(recommendations)}")
            print(f"    Recoverable:     {recoverable_count}")
            print(f"    Non-recoverable: {len(recommendations) - recoverable_count}")

            for rec in recommendations:
                icon = "✓" if rec.get('recoverable') else "✗"
                action = rec.get('recommendation', {}).get('action', 'skip')
                alt_id = rec.get('recommendation', {}).get('alternative_technique_id', '-')
                reason = rec.get('recommendation', {}).get('reason', '')

                print(f"\n    {icon} {rec['failed_technique_id']}")
                print(f"      Reason:  {rec.get('failure_reason')}")
                print(f"      Action:  {action}")
                if action != 'skip':
                    print(f"      Alt:     {alt_id}")
                print(f"      Detail:  {reason[:100]}")

            return recommendations

        except json.JSONDecodeError as e:
            print(f"  [!] JSON parsing failed: {e}")
            return []
        except Exception as e:
            print(f"  [!] LLM analysis error: {e}")
            return []

    # =========================================================================
    # 2. Caldera에서 대체 ability 검색 + 검증
    # =========================================================================
    def find_alternative_abilities(self, recommendations: List[Dict],
                                    platform: str = "windows",
                                    failed_ability_ids: List[str] = None) -> List[Dict]:
        """
        LLM 추천을 Caldera에서 검증하고 실제 ability 확보

        Args:
            recommendations: analyze_failures()의 결과
            platform: 타겟 플랫폼
            failed_ability_ids: 이전에 실패한 ability ID 목록 (제외 대상)

        Returns:
            실행 가능한 대체 step 목록
        """
        print("\n[*] Searching for alternative abilities in Caldera...")
        if failed_ability_ids:
            print(f"    Excluding {len(failed_ability_ids)} previously failed ability(s)")

        alternatives = []

        for rec in recommendations:
            if not rec.get('recoverable'):
                continue

            action = rec.get('recommendation', {}).get('action', 'skip')
            if action == 'skip':
                continue

            failed_id = rec['failed_technique_id']

            if action == 'replace_technique':
                # 다른 technique의 ability 검색
                alt_tech_id = rec['recommendation'].get('alternative_technique_id', '')
                if not alt_tech_id:
                    continue

                print(f"\n  Searching {alt_tech_id} (replacing {failed_id})...")
                result = self.caldera.get_abilities_with_fallback(alt_tech_id)

            elif action == 'replace_ability':
                # 같은 technique의 다른 ability 검색
                print(f"\n  Searching alternative ability for {failed_id}...")
                result = self.caldera.get_abilities_with_fallback(failed_id)

            else:
                continue

            if result['match_type'] == 'none' or not result['abilities']:
                print(f"    ✗ No abilities found")
                continue

            # Best ability 선택 (실패한 것 제외)
            best = self.caldera.select_best_ability(
                result['abilities'],
                prefer_low_privilege=False,  # 관리자 Agent 전제
                platform=platform,
                exclude_ids=failed_ability_ids
            )

            if best:
                alt_tech_id = rec['recommendation'].get(
                    'alternative_technique_id', failed_id
                )
                alternatives.append({
                    "original_technique_id": failed_id,
                    "technique_id": alt_tech_id,
                    "technique_name": best.get('technique_name',
                                               best.get('name', 'Unknown')),
                    "tactic": best.get('tactic',
                                       rec['recommendation'].get('alternative_tactic', '')),
                    "ability_id": best.get('ability_id'),
                    "ability_name": best.get('name', 'Unknown'),
                    "action": action,
                    "reason": rec['recommendation'].get('reason', '')
                })
                print(f"    ✓ Found: {best.get('name')} ({best.get('ability_id')})")
            else:
                print(f"    ✗ No suitable ability for {platform} (all excluded or unavailable)")

        print(f"\n[*] Alternative abilities found: {len(alternatives)}")
        return alternatives

    # =========================================================================
    # 3. 보완 Operation 생성 + 실행
    # =========================================================================
    def create_retry_operation(self, alternatives: List[Dict],
                                agent_paw: str,
                                operation_name: str = "S2C_Retry") -> Optional[Dict]:
        """
        대체 ability들로 보완 Operation 생성

        Args:
            alternatives: find_alternative_abilities()의 결과
            agent_paw: 타겟 Agent PAW
            operation_name: Operation 이름

        Returns:
            생성된 Operation 정보
        """
        if not alternatives:
            print("\n[*] No alternatives to retry. Skipping retry operation.")
            return None

        # attack_chain 형식으로 변환
        attack_chain = []
        for i, alt in enumerate(alternatives, 1):
            attack_chain.append({
                "step": i,
                "technique_id": alt['technique_id'],
                "technique_name": alt['technique_name'],
                "tactic": alt['tactic'],
                "ability_id": alt['ability_id'],
                "ability_name": alt['ability_name'],
                "reason": f"Retry: {alt['action']} — {alt['reason']}"
            })

        # Operation Plan 생성
        operation_plan = {
            "name": operation_name,
            "description": f"Auto-retry operation with {len(attack_chain)} alternative abilities",
            "steps": attack_chain
        }

        print(f"\n[*] Creating retry operation with {len(attack_chain)} steps:")
        for step in attack_chain:
            print(f"    {step['step']}. {step['technique_id']}: {step['ability_name']}")
            print(f"       (replaces {alternatives[step['step']-1]['original_technique_id']})")

        # Operation 생성 및 실행
        operation = self.caldera.create_operation_from_plan(
            operation_plan,
            agent_paw=agent_paw,
            auto_start=True
        )

        return operation

    # =========================================================================
    # 통합 실행
    # =========================================================================
    def run(self, operation_results: Dict, agent_info: Dict,
            agent_paw: str, retry_name: str = "S2C_Retry") -> Optional[Dict]:
        """
        실패 분석 → 대체 검색 → 보완 Operation 전체 흐름

        Args:
            operation_results: Phase 5의 결과 (stats + links)
            agent_info: {"platform": "windows", "privilege": "Elevated"}
            agent_paw: Agent PAW
            retry_name: 보완 Operation 이름

        Returns:
            {
                "recommendations": [...],
                "alternatives": [...],
                "retry_operation": {...}
            }
        """
        links = operation_results.get('links', [])

        # 1. 실패한 링크만 추출
        failed_links = [l for l in links if l.get('status', -1) != 0]

        if not failed_links:
            print("\n[*] All steps succeeded! No retry needed.")
            return None

        print(f"\n[*] Found {len(failed_links)} failed link(s)")

        # 2. LLM 실패 분석
        recommendations = self.analyze_failures(failed_links, agent_info)

        if not recommendations:
            print("[!] LLM analysis returned no results")
            return None

        # 실패한 ability ID 수집 (exclude 목록)
        failed_ability_ids = list(set(
            l.get('ability', {}).get('ability_id')
            for l in failed_links
            if l.get('ability', {}).get('ability_id')
        ))
        print(f"[*] Excluding {len(failed_ability_ids)} failed ability ID(s)")

        # 3. Caldera에서 대체 ability 검색
        alternatives = self.find_alternative_abilities(
            recommendations,
            platform=agent_info.get('platform', 'windows'),
            failed_ability_ids=failed_ability_ids
        )

        # 4. 보완 Operation 생성
        retry_operation = None
        if alternatives:
            retry_operation = self.create_retry_operation(
                alternatives,
                agent_paw=agent_paw,
                operation_name=retry_name
            )

        return {
            "recommendations": recommendations,
            "alternatives": alternatives,
            "retry_operation": retry_operation
        }
