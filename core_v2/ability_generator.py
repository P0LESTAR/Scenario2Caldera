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

    def generate_command(self, svo: AttackSVO, platform: str = "windows",
                         env_context: Dict = None) -> Optional[str]:
        """
        SVO → 실행 가능한 쉘 커맨드 생성

        Args:
            svo: AttackSVO 트리플릿
            platform: 타겟 플랫폼
            env_context: 환경 컨텍스트 (C2 서버 주소, Agent 권한 등)

        Returns:
            생성된 커맨드 문자열 or None
        """
        executor = self.PLATFORM_EXECUTORS.get(platform, "psh")
        env = env_context or {}

        # ── 환경 정보 블록 구성 ──────────────────────────────────
        env_block = ""
        c2_url = env.get("c2_server_url", "")
        agent_host = env.get("agent_host", "")
        agent_privilege = env.get("agent_privilege", "User")
        target_hosts = env.get("target_hosts", [])

        payloads = env.get("payloads", [])
        payload_url_fmt = env.get("payload_download_url_format", "")

        # payload 목록 요약 (exe/bat/ps1/dll 등 실행 가능한 것만 표시, 최대 15개)
        useful_payloads = [p for p in payloads if any(p.endswith(ext) for ext in
            ('.exe', '.bat', '.ps1', '.dll', '.vbs', '.py', '.xml', '.sh', '.txt'))]
        payload_hint = ''
        if useful_payloads:
            sample = useful_payloads[:15]
            payload_hint = f"""
- Available Caldera Payloads (REAL files you can reference):
  Download URL format: {payload_url_fmt}
  Files: {', '.join(sample)}{' ...' if len(useful_payloads) > 15 else ''}
  → If the command needs to download a file, USE ONE OF THESE real filenames above!"""

        if c2_url or agent_host:
            env_block = f"""

ENVIRONMENT (use these REAL values in the command — do NOT invent addresses):
- C2 / Attacker Server: {c2_url}  ← use this for ANY download, upload, or exfiltration URL
- Agent Host: {agent_host}
- Agent Privilege: {agent_privilege}
- Target Hosts for lateral movement: {', '.join(target_hosts) if target_hosts else 'none available'}{payload_hint}

CRITICAL ADDRESS RULES:
- When downloading files from attacker: use {c2_url} as the base URL (NOT 127.0.0.1, NOT example.com)
- When exfiltrating/uploading data: upload to {c2_url} (NOT random IPs)
- For lateral movement targets: use one of the Target Hosts listed above
- If you need to download a file: use the payload download URL format above with a REAL filename from the list
- If a file is needed locally but doesn't exist, CREATE it first (e.g. echo/New-Item) before using it
- If privilege is 'User', do NOT use commands requiring admin/SYSTEM (no sc.exe create, no schtasks /RU SYSTEM)"""

        system_prompt = f"""You are an expert red team operator generating commands for attack simulation.

CONTEXT:
- Platform: {platform}
- Executor: {"PowerShell" if executor == "psh" else "Bash/sh" if executor == "sh" else "cmd"}
- This is for a CONTROLLED security test environment with an authorized Caldera agent
{env_block}

YOUR TASK:
Generate a SINGLE executable command that performs the described attack action.

RULES:
1. The command must be directly executable — no placeholders, no comments
2. Use ONLY built-in OS tools or common utilities (no custom binaries)
3. The command should be a single line (use semicolons or && for chaining)
4. For PowerShell: do NOT use Write-Host for output, use actual operational commands
5. For sh: ensure POSIX compatibility
6. Prefer "Living off the Land" (LotL) techniques — use native OS tools
7. Output ONLY the command, nothing else — no explanation, no markdown
8. ALL network addresses must come from the ENVIRONMENT section above — never invent IPs or hostnames"""

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
                         max_attempts: int = 3,
                         env_context: Dict = None) -> Optional[Dict]:
        """
        SVO → Caldera Ability 생성 (API 등록까지)

        Args:
            svo: AttackSVO
            platform: 타겟 플랫폼
            max_attempts: 최대 생성 시도 횟수
            env_context: 환경 컨텍스트 (C2 서버 URL, Agent 정보 등)

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
            command = self.generate_command(svo, platform, env_context=env_context)
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

    def _build_env_context(self, agent_info: Optional[Dict]) -> Dict:
        """
        agent_info로부터 LLM 프롬프트에 사용할 환경 컨텍스트를 구성
        """
        if not agent_info:
            return {}

        env_context = {
            "c2_server_url": agent_info.get("c2_server_url", ""),
            "agent_host": agent_info.get("host", ""),
            "agent_privilege": agent_info.get("privilege", "User"),
            "target_hosts": agent_info.get("target_hosts", []),
            "payloads": agent_info.get("payloads", []),
            "payload_download_url_format": agent_info.get("payload_download_url_format", ""),
        }
        return env_context

    def generate_abilities_for_plan(self, techniques: List[Dict],
                                     platform: str = "windows",
                                     force_generate: bool = False,
                                     agent_info: Dict = None) -> List[Dict]:
        """
        공격 체인 전체에 대해 ability를 확보 (기존 선택 or 신규 생성)

        Args:
            techniques: validated_data의 techniques 목록
                        각 technique에 caldera_validation.selected_ability 또는 svo가 있음
            platform: 타겟 플랫폼
            force_generate: True이면 기존 Caldera ability를 무시하고 항상 SVO로 새 ability 생성
                            (SVO 기여도 실험용)
            agent_info: 현재 공격에 사용될 agent의 정보 (C2 서버, 호스트, 권한 등)

        Returns:
            각 technique에 대한 ability 정보 리스트
            [{"technique_id": ..., "ability_id": ..., "ability_name": ..., "source": "existing"|"generated", ...}]
        """
        print(f"\n{'='*80}")
        print(f"ABILITY ACQUISITION: {len(techniques)} techniques")
        if force_generate:
            print(f"  ⚡ FORCE GENERATE MODE — skipping existing abilities")
        print(f"{'='*80}")

        # ── 환경 컨텍스트 구성 ───────────────────────────────────
        env_context = self._build_env_context(agent_info)
        if env_context.get("c2_server_url"):
            print(f"  🌐 C2 Server: {env_context['c2_server_url']}")
            print(f"  🖥️  Agent: {env_context.get('agent_host', '?')} (privilege: {env_context.get('agent_privilege', '?')})")

        results = []
        stats = {"existing": 0, "generated": 0, "failed": 0}

        for i, tech in enumerate(techniques, 1):
            tech_id = tech.get("technique_id", "?")
            tech_name = tech.get("technique_name", "N/A")
            validation = tech.get("caldera_validation", {})

            print(f"\n[{i}/{len(techniques)}] {tech_id}: {tech_name}")

            # Case 1: 기존 ability 사용 (force_generate이면 skip)
            selected = validation.get("selected_ability")
            if selected and not force_generate:
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

            if selected and force_generate:
                print(f"  → [SKIP] existing '{selected.get('name')}' — force generating from SVO")

            # Case 2: SVO가 있으면 ability 생성 시도
            svo_data = tech.get("svo")
            if svo_data:
                svo = AttackSVO(**svo_data)
                generated = self.generate_ability(svo, platform, env_context=env_context)

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
