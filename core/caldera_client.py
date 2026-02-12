#!/usr/bin/env python3
"""
Caldera C2 API Client
Agent/Ability/Operation/Adversary 관리 + Operation 생성 및 결과 분석
"""

import requests
import json
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
import sys

# 상위 디렉토리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import CALDERA_CONFIG


class CalderaClient:
    """Caldera REST API 클라이언트 — 모든 Caldera 상호작용 담당"""

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
            except Exception:
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

    def list_agents(self) -> List[Dict]:
        """
        연결된 Agent 목록 조회 및 출력

        Returns:
            Agent 목록
        """
        print("\n[*] Listing available agents...")

        agents = self.get_agents()

        if not agents:
            print("  [!] No agents found!")
            return []

        print(f"  Found {len(agents)} agent(s):")
        for i, agent in enumerate(agents, 1):
            print(f"\n    {i}. PAW: {agent.get('paw')}")
            print(f"       Host: {agent.get('host')}")
            print(f"       Platform: {agent.get('platform')}")
            print(f"       Privilege: {agent.get('privilege', 'User')}")
            print(f"       Group: {agent.get('group', 'N/A')}")
            print(f"       Last Seen: {agent.get('last_seen', 'N/A')}")

        return agents

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

    def get_abilities_with_fallback(self, technique_id: str, enable_fallback: bool = True) -> Dict:
        """Technique ID로 Ability 조회 (Parent Technique Fallback 지원)"""
        result = {
            "technique_id": technique_id,
            "match_type": "none",
            "abilities": [],
            "fallback_applied": False
        }

        # 1. 정확한 매칭
        abilities = self.get_abilities(technique_id=technique_id)

        if abilities:
            result["match_type"] = "exact"
            result["abilities"] = abilities
            return result

        # 2. Parent Technique Fallback
        if enable_fallback and '.' in technique_id:
            parent_id = technique_id.split('.')[0]
            parent_abilities = self.get_abilities(technique_id=parent_id)

            if parent_abilities:
                result["technique_id"] = parent_id
                result["match_type"] = "parent"
                result["abilities"] = parent_abilities
                result["fallback_applied"] = True
                return result

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
                    return 0
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
        return self._request("GET", f"operations/{operation_id}")

    def get_operation_links(self, operation_id: str) -> List[Dict]:
        """오퍼레이션의 실행된 링크(명령) 목록"""
        op = self.get_operation(operation_id)
        if op:
            return op.get("chain", [])
        return []

    # ==================== Operation 생성 (from plan) ====================

    def create_operation_from_plan(self, operation_plan: Dict,
                                   agent_paw: Optional[str] = None,
                                   auto_start: bool = False) -> Optional[Dict]:
        """
        공격 체인 계획 → Caldera Operation 생성

        Args:
            operation_plan: {"name": str, "description": str, "steps": [...]}
            agent_paw: 타겟 Agent PAW
            auto_start: 자동 시작 여부

        Returns:
            생성된 Operation 정보
        """
        print("\n" + "="*80)
        print("CREATING CALDERA OPERATION")
        print("="*80)

        # 1. Adversary 생성
        adversary_name = operation_plan.get('name', 'S2C_Operation')
        description = operation_plan.get('description', '')
        attack_chain = operation_plan.get('steps', [])

        print(f"\n[*] Creating Adversary: {adversary_name}")

        ability_ids = [step['ability_id'] for step in attack_chain]

        print(f"  Abilities: {len(ability_ids)}")
        for i, step in enumerate(attack_chain, 1):
            print(f"    {i}. {step['technique_id']}: {step['ability_name']}")

        payload = {
            "name": adversary_name,
            "description": description or f"Auto-generated adversary for {adversary_name}",
            "atomic_ordering": ability_ids,
            "objective": "495a9828-cab1-44dd-a0ca-66e58177d8cc"
        }

        try:
            result = self._request("POST", "adversaries", json=payload)
            if not result or 'adversary_id' not in result:
                print(f"  [!] Failed to create adversary")
                return None
            adversary_id = result['adversary_id']
            print(f"  ✓ Adversary created: {adversary_id}")
        except Exception as e:
            print(f"  [!] Error creating adversary: {e}")
            return None

        # 2. Operation 생성
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        operation_name = f"{adversary_name}_{timestamp}"

        print(f"\n[*] Creating Operation: {operation_name}")

        # Agent 그룹 설정
        group = ""
        if agent_paw:
            print(f"  Target Agent: {agent_paw}")
            agent = self.get_agent(agent_paw)
            if agent:
                group = agent.get('group', '')
                print(f"  Agent Group: {group or 'default'}")
        else:
            print(f"  Target: All agents")

        state = "running" if auto_start else "paused"

        operation = self.create_operation(
            name=operation_name,
            adversary_id=adversary_id,
            group=group,
            state=state
        )

        if operation:
            print(f"\n✓ Operation created successfully!")
            print(f"  Operation ID: {operation.get('id')}")
            print(f"  Name: {operation.get('name')}")
            print(f"  State: {operation.get('state')}")
            print(f"  Adversary: {adversary_id}")

            if not auto_start:
                print(f"\n💡 Operation is PAUSED. Start it manually in Caldera UI:")
                print(f"   {self.base_url}/#/operations/{operation.get('id')}")

        return operation

    # ==================== 결과 분석 ====================

    def get_operation_results(self, operation_id: str) -> Optional[Dict]:
        """Operation 결과 조회"""
        print(f"\n[*] Fetching operation results: {operation_id}")

        operation = self.get_operation(operation_id)

        if not operation:
            print(f"  [!] Operation not found: {operation_id}")
            return None

        print(f"  OK Operation: {operation.get('name')}")
        print(f"     State: {operation.get('state')}")
        print(f"     Start: {operation.get('start')}")

        links = operation.get('chain', [])
        print(f"  OK Links: {len(links)} commands executed")

        return {
            "operation": operation,
            "links": links
        }

    def analyze_links(self, links: List[Dict]) -> Dict:
        """Links 통계 분석"""
        print(f"\n[*] Analyzing {len(links)} links...")

        stats = {
            "total": len(links),
            "success": 0,
            "failed": 0,
            "running": 0,
            "by_technique": {},
            "by_tactic": {},
            "by_status": {}
        }

        for link in links:
            status = link.get('status', -999)

            if status == 0:
                stats['success'] += 1
                status_str = "success"
            elif status == 1:
                stats['running'] += 1
                status_str = "running"
            else:
                stats['failed'] += 1
                status_str = f"failed ({status})"

            stats['by_status'][status_str] = stats['by_status'].get(status_str, 0) + 1

            # Technique 분석
            ability = link.get('ability', {})
            technique_id = ability.get('technique_id', 'Unknown')
            tactic = ability.get('tactic', 'Unknown')

            if technique_id not in stats['by_technique']:
                stats['by_technique'][technique_id] = {
                    "count": 0, "success": 0, "failed": 0,
                    "name": ability.get('technique_name', 'Unknown')
                }

            stats['by_technique'][technique_id]['count'] += 1
            if status == 0:
                stats['by_technique'][technique_id]['success'] += 1
            else:
                stats['by_technique'][technique_id]['failed'] += 1

            # Tactic 분석
            if tactic not in stats['by_tactic']:
                stats['by_tactic'][tactic] = {"count": 0, "success": 0, "failed": 0}

            stats['by_tactic'][tactic]['count'] += 1
            if status == 0:
                stats['by_tactic'][tactic]['success'] += 1
            else:
                stats['by_tactic'][tactic]['failed'] += 1

        return stats

    def print_analysis(self, operation: Dict, links: List[Dict], stats: Dict):
        """분석 결과 출력"""

        print("\n" + "="*80)
        print("OPERATION EXECUTION RESULTS")
        print("="*80)

        print(f"\n📋 Operation Information:")
        print(f"    ID: {operation.get('id')}")
        print(f"    Name: {operation.get('name')}")
        print(f"    State: {operation.get('state')}")
        print(f"    Start: {operation.get('start')}")
        print(f"    Adversary: {operation.get('adversary', {}).get('name')}")

        print(f"\n📊 Execution Summary:")
        total = stats['total']
        if total > 0:
            print(f"    Total Commands: {total}")
            print(f"    ✓ Success:      {stats['success']} ({stats['success']/total*100:.1f}%)")
            print(f"    ✗ Failed:       {stats['failed']} ({stats['failed']/total*100:.1f}%)")
            if stats['running'] > 0:
                print(f"    ⏳ Running:      {stats['running']}")

        print(f"\n🎯 Results by Technique:")
        for tech_id, ts in sorted(stats['by_technique'].items()):
            rate = (ts['success'] / ts['count'] * 100) if ts['count'] > 0 else 0
            icon = "✓" if ts['failed'] == 0 else "✗"
            print(f"    {icon} {tech_id:12} {ts['name']:50} {ts['success']}/{ts['count']} ({rate:.0f}%)")

        print(f"\n🎭 Results by Tactic:")
        for tactic, ts in sorted(stats['by_tactic'].items()):
            rate = (ts['success'] / ts['count'] * 100) if ts['count'] > 0 else 0
            icon = "✓" if ts['failed'] == 0 else "✗"
            print(f"    {icon} {tactic:25} {ts['success']}/{ts['count']} ({rate:.0f}%)")

        print(f"\n📝 Executed Commands:")
        for i, link in enumerate(links, 1):
            ability = link.get('ability', {})
            status = link.get('status', -999)
            icon = "✓" if status == 0 else ("⏳" if status == 1 else "✗")

            print(f"\n    {i}. {icon} {ability.get('technique_id', 'N/A')}: {ability.get('name', 'Unknown')}")
            print(f"       Tactic: {ability.get('tactic', 'N/A')}")
            print(f"       Status: {status}")
            print(f"       PID: {link.get('pid', 'N/A')}")

            output = link.get('output', '')
            if output and output != 'False':
                print(f"       Output: {output[:100]}...")
