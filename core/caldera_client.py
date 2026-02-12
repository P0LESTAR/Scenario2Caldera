#!/usr/bin/env python3
"""
Caldera C2 API Client
Agent 관리, Ability 실행 및 Fallback Logic 제공
"""

import requests
import time
import json
from typing import Dict, List, Optional
from pathlib import Path
import sys

# 상위 디렉토리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import CALDERA_CONFIG


class CalderaClient:
    """Caldera REST API 클라이언트 with Enhanced Features"""

    def __init__(self):
        self.base_url = CALDERA_CONFIG["url"]
        self.api_key = CALDERA_CONFIG["api_key"]
        self.timeout = CALDERA_CONFIG.get("timeout", 30)

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

            try:
                return resp.json()
            except:
                return {"raw": resp.text}

        except requests.exceptions.RequestException as e:
            print(f"  [!] API request failed: {url} - {e}")
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

    # ==================== Abilities ====================

    def get_abilities(self, technique_id: Optional[str] = None) -> List[Dict]:
        """Ability 목록 조회"""
        abilities = self._request("GET", "abilities")
        if not isinstance(abilities, list):
            return []

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
        """새 오퍼레이션 생성"""
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
        
    def get_operation_links(self, operation_id: str) -> List[Dict]:
        """오퍼레이션의 실행된 링크(명령) 목록"""
        op = self.get_operation(operation_id)
        if op:
            return op.get("chain", [])
        return []

    # ==================== Adversaries ====================

    def get_adversaries(self) -> List[Dict]:
        """모든 Adversary 목록"""
        result = self._request("GET", "adversaries")
        return result if isinstance(result, list) else []

    def create_adversary(self, name: str, description: str,
                        atomic_ordering: List[str]) -> Optional[Dict]:
        """새 Adversary 생성"""
        print(f"[*] Creating adversary: {name}")

        payload = {
            "name": name,
            "description": description,
            "atomic_ordering": atomic_ordering,
            "tags": ["S2C-generated"]
        }

        result = self._request("POST", "adversaries", json=payload)

        if result:
            print(f"  OK Adversary created: {result.get('adversary_id')}")

        return result

    # ==================== Enhanced Features ====================

    def get_abilities_with_fallback(self, technique_id: str, enable_fallback: bool = True) -> Dict:
        """
        Technique ID로 Ability 조회 (Parent Technique Fallback 지원)
        """
        result = {
            "technique_id": technique_id,
            "match_type": "none",
            "abilities": [],
            "fallback_applied": False
        }
        
        # 1. 정확한 매칭 시도
        abilities = self.get_abilities(technique_id=technique_id)
        
        if abilities:
            result["match_type"] = "exact"
            result["abilities"] = abilities
            return result
        
        # 2. Parent Technique Fallback (Sub-technique인 경우)
        if enable_fallback and '.' in technique_id:
            parent_id = technique_id.split('.')[0]
            parent_abilities = self.get_abilities(technique_id=parent_id)
            
            if parent_abilities:
                result["technique_id"] = parent_id
                result["match_type"] = "parent"
                result["abilities"] = parent_abilities
                result["fallback_applied"] = True
                return result
        
        # 3. 매칭 실패
        return result

    def select_best_ability(self, abilities: List[Dict], 
                           prefer_low_privilege: bool = True,
                           platform: Optional[str] = None) -> Optional[Dict]:
        """여러 Ability 중 최적의 것을 선택"""
        if not abilities:
            return None
        
        # 플랫폼 필터링
        if platform:
            filtered = []
            for ability in abilities:
                executors = ability.get("executors", [])
                for executor in executors:
                    if executor.get("platform") == platform:
                        filtered.append(ability)
                        break
            
            if filtered:
                abilities = filtered
        
        # 권한 기반 정렬
        if prefer_low_privilege:
            def privilege_score(ability):
                priv = ability.get("privilege", "")
                if not priv or priv == "":
                    return 0  # 일반 권한
                elif priv.lower() == "user":
                    return 1
                elif priv.lower() == "elevated":
                    return 2
                else:
                    return 3
            abilities = sorted(abilities, key=privilege_score)
        
        # 요구사항이 적은 것 우선
        abilities = sorted(abilities, key=lambda a: len(a.get("requirements", [])))
        
        return abilities[0] if abilities else None


# Alias for backward compatibility (if needed)
EnhancedCalderaClient = CalderaClient

if __name__ == "__main__":
    client = CalderaClient()
    print("\n[*] Connected agents:")
    agents = client.get_agents()
    for agent in agents:
        print(f"  - {agent['paw']}: {agent.get('platform')} @ {agent.get('host')}")
