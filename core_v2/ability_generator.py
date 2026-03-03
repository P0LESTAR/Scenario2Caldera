#!/usr/bin/env python3
"""
SVO-based Ability Generator
SVO 트리플릿을 기반으로 Caldera Ability를 직접 생성한다.
기존 ability가 없는 technique을 커버하기 위한 핵심 모듈.
"""

import sys
import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from ollama import Client as OllamaClient

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import LLM_CONFIG
from core_v2.svo_extractor import AttackSVO
from core_v2.caldera_client import CalderaClient


class AbilityGenerator:
    """SVO에서 Caldera Ability를 생성"""

    # 플랫폼별 executor 매핑
    PLATFORM_EXECUTORS = {
        "windows": "psh",     # PowerShell
        "linux": "sh",        # Bash/sh
        "darwin": "sh",       # macOS sh
    }

    def __init__(self):
        self.llm_client = OllamaClient(host=LLM_CONFIG["host"])
        self.model = LLM_CONFIG["model"]
        self.caldera = CalderaClient()

    def generate_command(self, svo: AttackSVO, platform: str = "windows") -> Optional[str]:
        """
        SVO → 실행 가능한 쉘 커맨드 생성

        Args:
            svo: AttackSVO 트리플릿
            platform: 타겟 플랫폼

        Returns:
            생성된 커맨드 문자열 or None
        """
        executor = self.PLATFORM_EXECUTORS.get(platform, "psh")

        system_prompt = f"""You are an expert red team operator generating commands for attack simulation.

CONTEXT:
- Platform: {platform}
- Executor: {"PowerShell" if executor == "psh" else "Bash/sh" if executor == "sh" else "cmd"}
- This is for a CONTROLLED security test environment with an authorized Caldera agent

YOUR TASK:
Generate a SINGLE executable command that performs the described attack action.

RULES:
1. The command must be directly executable — no placeholders, no comments
2. Use ONLY built-in OS tools or common utilities (no custom binaries)
3. The command should be a single line (use semicolons or && for chaining)
4. For PowerShell: do NOT use Write-Host for output, use actual operational commands
5. For sh: ensure POSIX compatibility
6. Prefer "Living off the Land" (LotL) techniques — use native OS tools
7. Output ONLY the command, nothing else — no explanation, no markdown"""

        user_prompt = f"""Generate a {platform} command for this attack action:

Intent: {svo.subject} performs "{svo.verb}" on {svo.object} ({svo.object_type})
MITRE Technique: {svo.technique_id} — {svo.technique_name}
Tactic: {svo.tactic}

Output ONLY the command:"""

        try:
            response = self.llm_client.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                options={"temperature": 0.0}
            )

            command = response["message"]["content"].strip()

            # 마크다운 코드 블록 제거
            command = re.sub(r"```(?:powershell|bash|sh|cmd)?\s*", "", command)
            command = re.sub(r"```\s*$", "", command)
            command = command.strip()

            # 빈 명령어 검증
            if not command or len(command) < 3:
                print(f"  [!] Generated command too short: '{command}'")
                return None

            return command

        except Exception as e:
            print(f"  [!] Command generation error: {e}")
            return None

    def validate_command(self, command: str, svo: AttackSVO, platform: str = "windows") -> Dict:
        """
        생성된 커맨드가 SVO 의도에 부합하는지 LLM으로 검증

        Returns:
            {
                "valid": bool,
                "reason": str,
                "risk_level": "low" | "medium" | "high"
            }
        """
        system_prompt = """You are a security command validator. Analyze if the given command
correctly implements the intended attack action described by the SVO triplet.

Output ONLY valid JSON:
{
    "valid": true/false,
    "reason": "brief explanation",
    "risk_level": "low" | "medium" | "high"
}

Validation criteria:
1. The command must actually perform the verb action (not just echo or print)
2. The command must target the described object type
3. The command must be syntactically valid for the platform
4. risk_level: "low" = read-only/enumeration, "medium" = creates/modifies files, "high" = destructive/persistence"""

        user_prompt = f"""Validate this command against the intended SVO:

SVO Intent: ({svo.subject}, {svo.verb}, {svo.object})
Object Type: {svo.object_type}
Technique: {svo.technique_id} — {svo.technique_name}
Platform: {platform}

Generated Command: {command}

Is this command valid for the intent?"""

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

            return json.loads(result_text)

        except Exception as e:
            print(f"  [!] Validation error: {e}")
            return {"valid": True, "reason": "Validation skipped due to error", "risk_level": "medium"}

    def generate_ability(self, svo: AttackSVO, platform: str = "windows",
                         max_attempts: int = 3) -> Optional[Dict]:
        """
        SVO → Caldera Ability 생성 (API 등록까지)

        Args:
            svo: AttackSVO
            platform: 타겟 플랫폼
            max_attempts: 최대 생성 시도 횟수

        Returns:
            생성된 Caldera ability 정보 or None
        """
        print(f"\n{'='*60}")
        print(f"GENERATING ABILITY: {svo.technique_id}")
        print(f"  SVO: {svo.intent_summary()}")
        print(f"  Platform: {platform}")
        print(f"{'='*60}")

        executor = self.PLATFORM_EXECUTORS.get(platform, "psh")

        for attempt in range(1, max_attempts + 1):
            print(f"\n  [Attempt {attempt}/{max_attempts}]")

            # 1. 커맨드 생성
            command = self.generate_command(svo, platform)
            if not command:
                print(f"  [!] Command generation failed")
                continue

            print(f"  → Command: {command[:100]}{'...' if len(command) > 100 else ''}")

            # 2. SVO 준수 검증
            validation = self.validate_command(command, svo, platform)
            print(f"  → Valid: {validation.get('valid')}, Risk: {validation.get('risk_level')}")
            print(f"  → Reason: {validation.get('reason', 'N/A')}")

            if not validation.get("valid", False):
                print(f"  [!] Validation failed — retrying")
                continue

            # 3. Caldera에 ability 등록
            ability_name = f"S2C_{svo.technique_id}_{svo.verb}_{svo.object_type}"
            ability_desc = (
                f"[Auto-generated] {svo.intent_summary()} | "
                f"Technique: {svo.technique_id} {svo.technique_name}"
            )

            result = self.caldera.create_ability(
                name=ability_name,
                description=ability_desc,
                tactic=svo.tactic,
                technique_id=svo.technique_id,
                technique_name=svo.technique_name,
                executor=executor,
                platform=platform,
                command=command,
                privilege="",  # 처음에는 일반 권한으로 시도
                timeout=60,
            )

            if result:
                ability_id = result.get("ability_id")
                print(f"\n  ✓ Ability registered: {ability_id}")

                return {
                    "ability_id": ability_id,
                    "name": ability_name,
                    "command": command,
                    "svo": svo.to_dict(),
                    "validation": validation,
                    "source": "generated",
                    "attempt": attempt,
                }

        print(f"\n  [!] Ability generation failed after {max_attempts} attempts")
        return None

    def generate_abilities_for_plan(self, techniques: List[Dict],
                                     platform: str = "windows") -> List[Dict]:
        """
        공격 체인 전체에 대해 ability를 확보 (기존 선택 or 신규 생성)

        Args:
            techniques: validated_data의 techniques 목록
                        각 technique에 caldera_validation.selected_ability 또는 svo가 있음
            platform: 타겟 플랫폼

        Returns:
            각 technique에 대한 ability 정보 리스트
            [{"technique_id": ..., "ability_id": ..., "ability_name": ..., "source": "existing"|"generated", ...}]
        """
        print(f"\n{'='*80}")
        print(f"ABILITY ACQUISITION: {len(techniques)} techniques")
        print(f"{'='*80}")

        results = []
        stats = {"existing": 0, "generated": 0, "failed": 0}

        for i, tech in enumerate(techniques, 1):
            tech_id = tech.get("technique_id", "?")
            tech_name = tech.get("technique_name", "N/A")
            validation = tech.get("caldera_validation", {})

            print(f"\n[{i}/{len(techniques)}] {tech_id}: {tech_name}")

            # Case 1: 기존 ability가 있으면 그대로 사용
            selected = validation.get("selected_ability")
            if selected:
                print(f"  → Using existing ability: {selected.get('name')}")
                results.append({
                    "technique_id": tech_id,
                    "technique_name": tech_name,
                    "ability_id": selected.get("ability_id"),
                    "ability_name": selected.get("name"),
                    "source": "existing",
                })
                stats["existing"] += 1
                continue

            # Case 2: SVO가 있으면 ability 생성 시도
            svo_data = tech.get("svo")
            if svo_data:
                svo = AttackSVO(**svo_data)
                generated = self.generate_ability(svo, platform)

                if generated:
                    results.append({
                        "technique_id": tech_id,
                        "technique_name": tech_name,
                        **generated,
                    })
                    stats["generated"] += 1
                    continue

            # Case 3: 둘 다 실패
            print(f"  [!] No ability available — skipping")
            stats["failed"] += 1

        print(f"\n{'='*80}")
        print(f"ABILITY ACQUISITION SUMMARY")
        print(f"  ✓ Existing: {stats['existing']}")
        print(f"  ✓ Generated: {stats['generated']}")
        print(f"  ✗ Failed: {stats['failed']}")
        print(f"  Total: {len(results)}/{len(techniques)}")
        print(f"{'='*80}")

        return results
