#!/usr/bin/env python3
"""
Caldera C2 API Client
Agent 관리 및 Ability 실행
"""

import requests
import time
import json
from typing import Dict, List, Optional
from config import CALDERA_CONFIG


class CalderaClient:
    """Caldera REST API 클라이언트"""

    def __init__(self):
        self.base_url = CALDERA_CONFIG["url"]
        self.api_key = CALDERA_CONFIG["api_key"]
        self.timeout = CALDERA_CONFIG["timeout"]

        self.headers = {
            "KEY": self.api_key,
            "Content-Type": "application/json"
        }

        print(f"[*] Caldera client initialized: {self.base_url}")

    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict]:
        """API 요청 헬퍼"""
        url = f"{self.base_url}/api/v2/{endpoint}"

        try:
            resp = requests.request(
                method,
                url,
                headers=self.headers,
                timeout=self.timeout,
                **kwargs
            )
            resp.raise_for_status()

            # JSON 응답이 아닐 수 있음
            try:
                return resp.json()
            except:
                return {"raw": resp.text}

        except requests.exceptions.RequestException as e:
            print(f"  [!] API request failed: {e}")
            return None

    # ==================== Agents ====================

    def get_agents(self) -> List[Dict]:
        """모든 에이전트 목록"""
        result = self._request("GET", "agents")
        return result if isinstance(result, list) else []

    def get_agent(self, paw: str) -> Optional[Dict]:
        """특정 에이전트 조회"""
        agents = self.get_agents()
        for agent in agents:
            if agent.get("paw") == paw:
                return agent
        return None

    def wait_for_agent(self, timeout: int = 300, platform: Optional[str] = None) -> Optional[Dict]:
        """
        새 에이전트 연결 대기

        Args:
            timeout: 대기 시간 (초)
            platform: 플랫폼 필터 (linux, windows, darwin)

        Returns:
            연결된 에이전트 정보
        """
        print(f"[*] Waiting for agent (timeout={timeout}s, platform={platform})...")

        initial_agents = {a["paw"] for a in self.get_agents()}
        start = time.time()

        while time.time() - start < timeout:
            current_agents = self.get_agents()

            for agent in current_agents:
                # 새 에이전트 체크
                if agent["paw"] not in initial_agents:
                    # 플랫폼 필터
                    if platform and agent.get("platform") != platform:
                        continue

                    print(f"  OK New agent: {agent['paw']} ({agent.get('platform')}) @ {agent.get('host')}")
                    return agent

            time.sleep(3)

        print(f"  [!] No new agent found after {timeout}s")
        return None

    # ==================== Abilities ====================

    def get_abilities(self, technique_id: Optional[str] = None) -> List[Dict]:
        """
        Ability 목록 조회

        Args:
            technique_id: MITRE ATT&CK 기법 ID로 필터링 (예: T1190)

        Returns:
            Ability 목록
        """
        abilities = self._request("GET", "abilities")
        if not isinstance(abilities, list):
            return []

        # Technique ID 필터링
        if technique_id:
            abilities = [
                a for a in abilities
                if a.get("technique_id") == technique_id
            ]

        return abilities

    def get_ability(self, ability_id: str) -> Optional[Dict]:
        """특정 Ability 조회"""
        abilities = self.get_abilities()
        for ability in abilities:
            if ability.get("ability_id") == ability_id:
                return ability
        return None

    # ==================== Operations ====================

    def create_operation(self, name: str, adversary_id: str,
                        group: str = "", state: str = "running") -> Optional[Dict]:
        """
        새 오퍼레이션 생성

        Args:
            name: 오퍼레이션 이름
            adversary_id: Adversary ID
            group: 타겟 에이전트 그룹 (비어있으면 모든 에이전트)
            state: 시작 상태 (running, paused)

        Returns:
            생성된 오퍼레이션 정보
        """
        print(f"[*] Creating operation: {name}")

        payload = {
            "name": name,
            "adversary": {"adversary_id": adversary_id},
            "group": group,
            "state": state,
            "autonomous": 1,
            "planner": {"id": "atomic"}
        }

        result = self._request("POST", "operations", json=payload)

        if result:
            print(f"  OK Operation created: {result.get('id')}")

        return result

    def get_operations(self) -> List[Dict]:
        """모든 오퍼레이션 목록"""
        result = self._request("GET", "operations")
        return result if isinstance(result, list) else []

    def get_operation(self, operation_id: str) -> Optional[Dict]:
        """특정 오퍼레이션 조회"""
        result = self._request("GET", f"operations/{operation_id}")
        return result

    def delete_operation(self, operation_id: str) -> bool:
        """오퍼레이션 삭제"""
        print(f"[*] Deleting operation: {operation_id}")
        result = self._request("DELETE", f"operations/{operation_id}")
        return result is not None

    # ==================== Links (Commands) ====================

    def get_operation_links(self, operation_id: str) -> List[Dict]:
        """오퍼레이션의 실행된 링크(명령) 목록"""
        op = self.get_operation(operation_id)
        if op:
            return op.get("chain", [])
        return []

    def wait_for_links_completion(self, operation_id: str, timeout: int = 600) -> bool:
        """
        오퍼레이션의 모든 링크가 완료될 때까지 대기

        Returns:
            True if all links finished, False if timeout
        """
        print(f"[*] Waiting for operation {operation_id} to complete...")

        start = time.time()
        while time.time() - start < timeout:
            links = self.get_operation_links(operation_id)

            if not links:
                time.sleep(3)
                continue

            # 모든 링크가 완료되었는지 확인
            pending = [l for l in links if l.get("status") not in [0, -2]]  # 0=success, -2=discarded

            if not pending:
                print(f"  OK All {len(links)} links completed")
                return True

            time.sleep(5)

        print(f"  [!] Timeout after {timeout}s")
        return False

    # ==================== Adversaries ====================

    def get_adversaries(self) -> List[Dict]:
        """모든 Adversary 목록"""
        result = self._request("GET", "adversaries")
        return result if isinstance(result, list) else []

    def create_adversary(self, name: str, description: str,
                        atomic_ordering: List[str]) -> Optional[Dict]:
        """
        새 Adversary 생성

        Args:
            name: 이름
            description: 설명
            atomic_ordering: Ability ID 목록 (실행 순서)

        Returns:
            생성된 Adversary 정보
        """
        print(f"[*] Creating adversary: {name}")

        payload = {
            "name": name,
            "description": description,
            "atomic_ordering": atomic_ordering,
            "tags": ["carma-generated"]
        }

        result = self._request("POST", "adversaries", json=payload)

        if result:
            print(f"  OK Adversary created: {result.get('adversary_id')}")

        return result


if __name__ == "__main__":
    # 테스트
    client = CalderaClient()

    # 에이전트 목록
    print("\n[*] Connected agents:")
    agents = client.get_agents()
    for agent in agents:
        print(f"  - {agent['paw']}: {agent.get('platform')} @ {agent.get('host')}")

    # T1190 관련 abilities
    print("\n[*] Abilities for T1190:")
    abilities = client.get_abilities(technique_id="T1190")
    for ability in abilities[:3]:
        print(f"  - {ability['ability_id']}: {ability.get('name')}")

    # 오퍼레이션 목록
    print("\n[*] Active operations:")
    operations = client.get_operations()
    for op in operations[:3]:
        print(f"  - {op['id']}: {op.get('name')} ({op.get('state')})")
