#!/usr/bin/env python3
"""
SVO Extractor
시나리오의 expected_action에서 (Subject, Verb, Object) 트리플릿을 추출한다.
KnowHow 논문의 gIoC 개념을 LLM 기반으로 구현.
"""

import sys
import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from ollama import Client as OllamaClient

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import LLM_CONFIG


@dataclass
class AttackSVO:
    """공격 행위의 SVO(Subject-Verb-Object) 구조화 표현"""
    subject: str          # 도구/프로세스 (예: "mimikatz", "powershell", "agent")
    verb: str             # 추상 행위 (예: "dump", "copy", "download", "enumerate")
    object: str           # 대상 (예: "credential", "browser history", "network share")
    object_type: str      # file | process | network | registry | service | memory
    technique_id: str     # T1003.001
    technique_name: str   # OS Credential Dumping: LSASS Memory
    tactic: str           # credential-access

    def to_dict(self) -> Dict:
        return asdict(self)

    def intent_summary(self) -> str:
        """사람이 읽을 수 있는 intent 요약"""
        return f"{self.subject} → {self.verb} → {self.object} ({self.object_type})"

    def __str__(self):
        return f"SVO({self.subject}, {self.verb}, {self.object})"


class SVOExtractor:
    """시나리오 technique에서 SVO 트리플릿을 추출"""

    # object_type 분류 기준
    OBJECT_TYPE_HINTS = {
        "file": ["file", "document", "config", "log", "script", "binary", "dll",
                 "credential file", "password file", "key file", "certificate"],
        "process": ["process", "service", "daemon", "thread", "task", "application"],
        "network": ["connection", "port", "socket", "traffic", "packet", "dns",
                    "http", "url", "ip", "domain", "proxy", "tunnel"],
        "registry": ["registry", "hive", "reg key", "reg value", "regedit"],
        "service": ["service", "systemd", "scheduled task", "cron", "startup"],
        "memory": ["memory", "lsass", "sam", "credential", "hash", "token",
                   "password", "cache", "dump"]
    }

    def __init__(self):
        self.llm_client = OllamaClient(host=LLM_CONFIG["host"])
        self.model = LLM_CONFIG["model"]

    def extract_svo(self, technique: Dict) -> Optional[AttackSVO]:
        """
        단일 technique에서 SVO를 추출

        Args:
            technique: {
                "technique_id": "T1003.001",
                "technique_name": "OS Credential Dumping: LSASS Memory",
                "tactic": "credential-access",
                "description": "...",
                "expected_action": "The attacker dumps credentials from LSASS memory"
            }

        Returns:
            AttackSVO or None
        """
        tech_id = technique.get("technique_id", "")
        tech_name = technique.get("technique_name", "")
        tactic = technique.get("tactic", "")
        description = technique.get("description", "")
        expected_action = technique.get("expected_action", "")

        # LLM에게 SVO 추출 요청
        system_prompt = """You are an expert in cybersecurity attack behavior analysis.
Your task is to extract a structured SVO (Subject-Verb-Object) triplet from an attack technique description.

Output ONLY valid JSON with this exact structure:
{
    "subject": "the tool, process, or actor performing the action",
    "verb": "the core action verb (one word, lowercase, e.g. dump, copy, download, enumerate, create, modify, delete, execute, inject, scan)",
    "object": "the target of the action (concise, e.g. credential, registry key, network share)",
    "object_type": "one of: file | process | network | registry | service | memory"
}

Rules:
1. subject should be the TOOL or PROCESS name if mentioned (e.g. mimikatz, powershell, certutil), otherwise use "agent"
2. verb should be a single ABSTRACT action word — not a full phrase
3. object should be the SPECIFIC target, not a general category
4. object_type must be exactly one of: file, process, network, registry, service, memory
5. Output ONLY the JSON, no explanation"""

        user_prompt = f"""Extract SVO from this attack technique:

Technique ID: {tech_id}
Technique Name: {tech_name}
Tactic: {tactic}
Description: {description}
Expected Action: {expected_action}

Output the JSON structure."""

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

            svo_data = json.loads(result_text)

            # object_type 검증/보정
            object_type = svo_data.get("object_type", "file")
            if object_type not in self.OBJECT_TYPE_HINTS:
                object_type = self._infer_object_type(svo_data.get("object", ""))

            svo = AttackSVO(
                subject=svo_data.get("subject", "agent").lower().strip(),
                verb=svo_data.get("verb", "execute").lower().strip(),
                object=svo_data.get("object", "target").lower().strip(),
                object_type=object_type,
                technique_id=tech_id,
                technique_name=tech_name,
                tactic=tactic,
            )

            print(f"  ✓ SVO: {svo.intent_summary()}")
            return svo

        except json.JSONDecodeError as e:
            print(f"  [!] SVO extraction JSON error for {tech_id}: {e}")
            return None
        except Exception as e:
            print(f"  [!] SVO extraction error for {tech_id}: {e}")
            return None

    def extract_all_svos(self, techniques: List[Dict]) -> List[AttackSVO]:
        """
        모든 technique에서 SVO를 일괄 추출

        Args:
            techniques: scenario.parse()의 techniques 목록

        Returns:
            AttackSVO 리스트 (추출 실패한 것은 제외)
        """
        print(f"\n[*] Extracting SVOs from {len(techniques)} techniques...")

        svos = []
        for i, tech in enumerate(techniques, 1):
            tech_id = tech.get("technique_id", "?")
            print(f"\n  [{i}/{len(techniques)}] {tech_id}: {tech.get('technique_name', 'N/A')}")

            svo = self.extract_svo(tech)
            if svo:
                svos.append(svo)
                # SVO를 technique dict에도 보존 (downstream에서 참조)
                tech["svo"] = svo.to_dict()
            else:
                print(f"  [!] Skipped — SVO extraction failed")

        print(f"\n[*] SVO extraction complete: {len(svos)}/{len(techniques)} extracted")
        return svos

    def _infer_object_type(self, object_str: str) -> str:
        """object 문자열에서 object_type을 추론"""
        object_lower = object_str.lower()
        best_type = "file"
        best_score = 0

        for obj_type, hints in self.OBJECT_TYPE_HINTS.items():
            score = sum(1 for hint in hints if hint in object_lower)
            if score > best_score:
                best_score = score
                best_type = obj_type

        return best_type
