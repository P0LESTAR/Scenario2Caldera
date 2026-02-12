#!/usr/bin/env python3
"""
Caldera Operation 생성기
공격 체인 계획을 Caldera Operation으로 변환
"""

import sys
import json
from pathlib import Path
from typing import Dict, List, Optional

# 상위 디렉토리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.caldera_client import CalderaClient


class OperationCreator:
    """
    공격 체인 계획을 Caldera Operation으로 생성
    """
    
    def __init__(self):
        self.client = CalderaClient()
    
    def create_adversary_from_attack_chain(self, attack_chain: List[Dict], 
                                          adversary_name: str,
                                          description: str = "") -> Optional[str]:
        """
        공격 체인에서 Adversary 생성
        
        Args:
            attack_chain: 공격 체인 (ability_id 포함)
            adversary_name: Adversary 이름
            description: 설명
        
        Returns:
            생성된 adversary_id
        """
        print(f"\n[*] Creating Adversary: {adversary_name}")
        
        # Ability ID 목록 추출
        ability_ids = [step['ability_id'] for step in attack_chain]
        
        print(f"  Abilities: {len(ability_ids)}")
        for i, step in enumerate(attack_chain, 1):
            print(f"    {i}. {step['technique_id']}: {step['ability_name']}")
        
        # Adversary 생성 payload
        payload = {
            "name": adversary_name,
            "description": description or f"Auto-generated adversary for {adversary_name}",
            "atomic_ordering": ability_ids,  # 순서대로 실행
            "objective": "495a9828-cab1-44dd-a0ca-66e58177d8cc"  # Default objective
        }
        
        try:
            result = self.client._request("POST", "adversaries", json=payload)
            
            if result and 'adversary_id' in result:
                adversary_id = result['adversary_id']
                print(f"  ✓ Adversary created: {adversary_id}")
                return adversary_id
            else:
                print(f"  [!] Failed to create adversary")
                print(f"  Response: {result}")
                return None
        
        except Exception as e:
            print(f"  [!] Error creating adversary: {e}")
            return None
    
    def list_agents(self) -> List[Dict]:
        """
        현재 연결된 Agent 목록 조회
        
        Returns:
            Agent 목록
        """
        print("\n[*] Listing available agents...")
        
        agents = self.client.get_agents()
        
        if not agents:
            print("  [!] No agents found!")
            print("  Please deploy Caldera agent manually on target VM")
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
    
    def create_operation_from_plan(self, operation_plan: Dict,
                                   agent_paw: Optional[str] = None,
                                   auto_start: bool = False) -> Optional[Dict]:
        """
        Operation Plan에서 Caldera Operation 생성
        
        Args:
            operation_plan: caldera_operation_plan.json 내용
            agent_paw: 타겟 Agent PAW (None이면 모든 agent)
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
        
        adversary_id = self.create_adversary_from_attack_chain(
            attack_chain,
            adversary_name,
            description
        )
        
        if not adversary_id:
            print("\n[!] Failed to create adversary. Cannot create operation.")
            return None
        
        # 2. Operation 생성
        operation_name = f"{adversary_name}_{self._get_timestamp()}"
        
        print(f"\n[*] Creating Operation: {operation_name}")
        
        # Agent 그룹 설정
        group = ""
        if agent_paw:
            print(f"  Target Agent: {agent_paw}")
            # Caldera는 group으로 필터링하므로, agent의 group 확인 필요
            agent = self.client.get_agent(agent_paw)
            if agent:
                group = agent.get('group', '')
                print(f"  Agent Group: {group or 'default'}")
        else:
            print(f"  Target: All agents")
        
        # Operation 생성
        state = "running" if auto_start else "paused"
        
        operation = self.client.create_operation(
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
                print(f"   http://192.168.50.31:8888/#/operations/{operation.get('id')}")
        
        return operation
    
    def _get_timestamp(self) -> str:
        """현재 타임스탬프"""
        from datetime import datetime
        return datetime.now().strftime("%Y%m%d_%H%M%S")


def main():
    print("="*80)
    print("CALDERA OPERATION CREATOR")
    print("="*80)
    
    creator = OperationCreator()
    
    # 1. Operation Plan 로드
    plan_path = Path(__file__).parent / "execution_ready" / "caldera_operation_plan.json"
    
    if not plan_path.exists():
        print(f"\n[!] Operation plan not found: {plan_path}")
        print("Please run test_full_pipeline.py first")
        return
    
    with open(plan_path, 'r', encoding='utf-8') as f:
        operation_plan = json.load(f)
    
    print(f"\n[*] Loaded operation plan:")
    print(f"    Name: {operation_plan.get('name')}")
    print(f"    Description: {operation_plan.get('description')}")
    print(f"    Steps: {len(operation_plan.get('steps', []))}")
    
    # 2. Agent 목록 확인
    agents = creator.list_agents()
    
    if not agents:
        print("\n" + "="*80)
        print("⚠️  NO AGENTS AVAILABLE")
        print("="*80)
        print("\n📋 Manual Steps Required:")
        print("  1. Deploy Caldera agent on target VM")
        print("  2. Verify agent connection in Caldera UI")
        print("  3. Run this script again")
        print("\n💡 Agent Deployment:")
        print("  Windows: server/payloads/sandcat.go-windows")
        print("  Linux:   server/payloads/sandcat.go-linux")
        return
    
    # 3. Agent 선택 (사용자 입력)
    print("\n" + "="*80)
    print("SELECT TARGET AGENT")
    print("="*80)
    
    print("\nOptions:")
    print("  0. All agents (default)")
    for i, agent in enumerate(agents, 1):
        print(f"  {i}. {agent.get('paw')} ({agent.get('platform')}) @ {agent.get('host')}")
    
    try:
        choice = input("\nSelect agent (0-{}): ".format(len(agents)))
        
        if not choice or choice == "0":
            selected_agent = None
            print("  → Using all agents")
        else:
            idx = int(choice) - 1
            if 0 <= idx < len(agents):
                selected_agent = agents[idx].get('paw')
                print(f"  → Selected: {selected_agent}")
            else:
                print("  [!] Invalid choice. Using all agents.")
                selected_agent = None
    
    except (ValueError, KeyboardInterrupt):
        print("\n  → Using all agents (default)")
        selected_agent = None
    
    # 4. Auto-start 여부
    print("\n" + "="*80)
    print("OPERATION START MODE")
    print("="*80)
    
    print("\nOptions:")
    print("  1. Paused (manual start in Caldera UI) - RECOMMENDED")
    print("  2. Running (auto-start immediately)")
    
    try:
        start_choice = input("\nSelect mode (1-2, default=1): ")
        auto_start = (start_choice == "2")
        
        if auto_start:
            print("  → Auto-start enabled")
        else:
            print("  → Paused (manual start)")
    
    except (ValueError, KeyboardInterrupt):
        print("\n  → Paused (default)")
        auto_start = False
    
    # 5. Operation 생성
    operation = creator.create_operation_from_plan(
        operation_plan,
        agent_paw=selected_agent,
        auto_start=auto_start
    )
    
    if operation:
        # 결과 저장
        output_path = Path(__file__).parent / "execution_ready" / "created_operation.json"
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({
                "operation": operation,
                "adversary_name": operation_plan.get('name'),
                "attack_chain": operation_plan.get('steps'),
                "selected_agent": selected_agent,
                "auto_start": auto_start
            }, f, indent=2, ensure_ascii=False)
        
        print(f"\n[*] Operation details saved to: {output_path}")
        
        print("\n" + "="*80)
        print("✅ OPERATION CREATED SUCCESSFULLY!")
        print("="*80)
        
        print("\n📋 Next Steps:")
        if auto_start:
            print("  1. Monitor operation in Caldera UI")
            print("  2. Check execution results")
        else:
            print("  1. Open Caldera UI:")
            print(f"     http://192.168.50.31:8888/#/operations/{operation.get('id')}")
            print("  2. Review the attack chain")
            print("  3. Click 'Start' to begin execution")
            print("  4. Monitor progress and results")


if __name__ == "__main__":
    main()
