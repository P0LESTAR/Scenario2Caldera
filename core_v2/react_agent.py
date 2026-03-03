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

from config import LLM_CONFIG
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

    # 에러 패턴 → 실패 유형 매핑
    FAILURE_PATTERNS = {
        "verb_failure": [
            "command not found", "not recognized as", "is not recognized",
            "not operable", "unable to find", "could not be found"
        ],
        "object_failure": [
            "file not found", "path not found", "no such file",
            "cannot find path", "does not exist", "itemnotfoundexception",
            "the system cannot find"
        ],
        "subject_failure": [
            "access denied", "access is denied", "permission denied",
            "operation not permitted", "requires elevation",
            "not have enough privilege", "run as administrator",
            "unauthorizedaccessexception"
        ],
        "syntax_failure": [
            "syntax error", "unexpected token", "bad substitution",
            "missing operand", "parse error", "incomplete command",
            "is not valid"
        ],
        "env_failure": [
            "not installed", "module not found", "no module named",
            "import error", "dll not found", "assembly not found",
            "cmdlet not found"
        ]
    }

    MAX_REACT_ROUNDS = 3

    def __init__(self):
        self.llm_client = OllamaClient(host=LLM_CONFIG["host"])
        self.model = LLM_CONFIG["model"]
        self.caldera = CalderaClient()

    def classify_failure(self, error_output: str) -> str:
        """에러 메시지를 SVO 실패 유형으로 분류"""
        error_lower = error_output.lower()

        for failure_type, patterns in self.FAILURE_PATTERNS.items():
            for pattern in patterns:
                if pattern in error_lower:
                    return failure_type

        return "unknown"

    def react_fix(self, svo: AttackSVO, failed_command: str,
                  error_output: str, platform: str = "windows",
                  previous_attempts: List[FixAttempt] = None) -> Optional[str]:
        """
        ReAct 패턴으로 실패한 command를 수정

        Args:
            svo: 원래 의도 (Subject-Verb-Object)
            failed_command: 실패한 커맨드
            error_output: 에러 출력
            platform: 타겟 플랫폼
            previous_attempts: 이전 시도 기록 (같은 수정 반복 방지)

        Returns:
            수정된 커맨드 or None (수정 불가)
        """
        failure_type = self.classify_failure(error_output)
        attempts_history = previous_attempts or []

        # subject_failure는 ReAct로 해결 불가 (권한 문제) → 바로 None
        if failure_type == "subject_failure" and not self._has_elevation_fix(attempts_history):
            # 첫 번째 시도에서는 권한 상승 래핑을 시도
            pass
        elif failure_type == "subject_failure":
            print(f"  [!] Permission issue — ReAct cannot resolve, needs ability-level change")
            return None

        # 이전 시도 기록 정리
        attempts_text = ""
        if attempts_history:
            attempts_text = "\n\nPrevious failed attempts:\n"
            for a in attempts_history:
                attempts_text += f"  Attempt {a.attempt}: {a.command}\n"
                attempts_text += f"    Error: {a.error[:200]}\n"
                attempts_text += f"    Type: {a.failure_type}\n"

        executor = "PowerShell" if platform == "windows" else "Bash/sh"

        # ReAct 프롬프트
        system_prompt = f"""You are an expert red team operator using the ReAct framework.

A command has FAILED during an attack simulation. You must fix it while preserving the original intent.

## ORIGINAL INTENT (SVO — DO NOT CHANGE THE INTENT)
- Subject: {svo.subject}
- Verb: {svo.verb}  (the ACTION must remain the same — e.g. don't change "dump" to "create")
- Object: {svo.object}  (the TARGET type must remain the same)
- Object Type: {svo.object_type}
- Technique: {svo.technique_id} — {svo.technique_name}

## FAILURE CLASSIFICATION: {failure_type}

## RULES
1. Output your response in this EXACT format:
   Thought: [your analysis of why the command failed]
   Action: [your fix strategy in one sentence]
   Command: [the fixed command — ONLY the command, nothing else]

2. The fixed command must:
   - Still perform "{svo.verb}" on "{svo.object}"
   - Be valid {executor} syntax
   - Use built-in OS tools (Living off the Land)
   - Be different from all previous attempts
   - Be a single line

3. Fix strategies by failure type:
   - verb_failure: Use a different tool/command that does the same action
   - object_failure: Try alternative paths or discovery first
   - subject_failure: Wrap with elevation (runas / sudo) if possible
   - syntax_failure: Fix syntax for {platform} compatibility
   - env_failure: Use an alternative tool that's built-in"""

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
            thought, action, command = self._parse_react_output(result_text)

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
            print(f"  → Fixed: {command[:100]}{'...' if len(command) > 100 else ''}")

            return command

        except Exception as e:
            print(f"  [!] ReAct fix error: {e}")
            return None

    def run_react_loop(self, svo: AttackSVO, initial_command: str,
                       initial_error: str, platform: str = "windows") -> Dict:
        """
        ReAct 루프 실행 (최대 MAX_REACT_ROUNDS회)

        이 메서드는 command 수정만 하고 실제 실행은 하지 않는다.
        실행은 pipeline이 담당한다.

        Args:
            svo: 원래 의도
            initial_command: 처음 실패한 커맨드
            initial_error: 첫 에러 메시지
            platform: 타겟 플랫폼

        Returns:
            {
                "fixed_commands": [{"command": str, "thought": str, "action": str, "failure_type": str}],
                "attempts": int,
                "exhausted": bool  # True이면 RetryAnalyzer로 fallback
            }
        """
        print(f"\n{'='*60}")
        print(f"ReAct LOOP: {svo.technique_id}")
        print(f"  SVO: {svo.intent_summary()}")
        print(f"  Initial error: {initial_error[:100]}")
        print(f"{'='*60}")

        attempts: List[FixAttempt] = []
        fixed_commands = []
        current_command = initial_command
        current_error = initial_error

        for round_num in range(1, self.MAX_REACT_ROUNDS + 1):
            print(f"\n  --- Round {round_num}/{self.MAX_REACT_ROUNDS} ---")

            failure_type = self.classify_failure(current_error)
            print(f"  Failure type: {failure_type}")

            # ReAct 수정 시도
            fixed_command = self.react_fix(
                svo=svo,
                failed_command=current_command,
                error_output=current_error,
                platform=platform,
                previous_attempts=attempts
            )

            if not fixed_command:
                print(f"  [!] ReAct could not produce a fix — exhausted")
                break

            # 수정 기록 저장
            attempt = FixAttempt(
                attempt=round_num,
                command=current_command,
                error=current_error[:300],
                failure_type=failure_type,
                thought="",  # _parse_react_output에서 이미 출력함
                action=""
            )
            attempts.append(attempt)

            fixed_commands.append({
                "round": round_num,
                "command": fixed_command,
                "failure_type": failure_type,
                "original_error": current_error[:300],
            })

            # 다음 라운드를 위해 current를 업데이트
            # (실제 실행 + 성공/실패 판단은 pipeline에서)
            current_command = fixed_command

            # 여기서는 첫 번째 수정 커맨드만 반환하고,
            # pipeline이 실행 후 다시 이 메서드를 호출하는 구조
            break

        return {
            "fixed_commands": fixed_commands,
            "attempts": len(attempts),
            "exhausted": len(fixed_commands) == 0,
            "svo": svo.to_dict(),
        }

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
            Command: ...

        Returns:
            (thought, action, command)
        """
        thought = ""
        action = ""
        command = ""

        # Thought 추출
        thought_match = re.search(r"Thought:\s*(.+?)(?=Action:|Command:|$)", text, re.DOTALL | re.IGNORECASE)
        if thought_match:
            thought = thought_match.group(1).strip()

        # Action 추출
        action_match = re.search(r"Action:\s*(.+?)(?=Command:|$)", text, re.DOTALL | re.IGNORECASE)
        if action_match:
            action = action_match.group(1).strip()

        # Command 추출
        command_match = re.search(r"Command:\s*(.+?)$", text, re.DOTALL | re.IGNORECASE)
        if command_match:
            command = command_match.group(1).strip()
            # 마크다운 코드블록 제거
            command = re.sub(r"```(?:powershell|bash|sh|cmd)?\s*", "", command)
            command = re.sub(r"```\s*$", "", command)
            command = command.strip()
            # 여러 줄이면 첫 줄만
            if "\n" in command:
                command = command.split("\n")[0].strip()

        return thought, action, command

    def _has_elevation_fix(self, attempts: List[FixAttempt]) -> bool:
        """이전에 권한 상승 수정을 시도했는지 확인"""
        return any(a.failure_type == "subject_failure" for a in attempts)
