#!/usr/bin/env python3
"""
Scenario2Caldera 전체 파이프라인 실행기
시나리오 파일 → Operation 생성 → 실행 → 결과 분석
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# 상위 디렉토리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.scenario_parser import ScenarioParser
from core.scenario_validator import ScenarioValidator
from core.llm_orchestrator import LLMOrchestrator
from core.operation_creator import OperationCreator


def print_header(title):
    """헤더 출력"""
    print("\n" + "="*80)
    print(title)
    print("="*80)


def main(scenario_file: str):
    """
    전체 파이프라인 실행
    
    Args:
        scenario_file: 시나리오 파일 경로 (상대 경로 또는 절대 경로)
    """
    print_header("SCENARIO2CALDERA FULL PIPELINE EXECUTION")
    
    # 파일 경로 처리
    scenario_path = Path(scenario_file)
    if not scenario_path.is_absolute():
        # 상대 경로면 프로젝트 루트 기준
        scenario_path = Path(__file__).parent.parent / scenario_file
    
    if not scenario_path.exists():
        print(f"[!] Scenario file not found: {scenario_path}")
        return None, None
    
    print(f"\n[*] Scenario: {scenario_path}")
    
    # 출력 디렉토리 생성 (프로젝트 루트의 results/)
    output_dir = Path(__file__).parent.parent / "results"
    output_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = output_dir / f"session_{timestamp}"
    session_dir.mkdir(exist_ok=True)
    
    print(f"[*] Output directory: {session_dir}")
    
    # ========================================================================
    # PHASE 1: 시나리오 파싱
    # ========================================================================
    print_header("PHASE 1: Scenario Parsing")
    
    parser = ScenarioParser()
    
    print(f"\n[*] Parsing scenario...")
    parsed_data = parser.parse_scenario_file(scenario_path)
    
    if not parsed_data:
        print("[!] Failed to parse scenario")
        return
    
    print(f"  ✓ Scenario: {parsed_data.get('scenario_name')}")
    print(f"  ✓ Target: {parsed_data.get('target_org')}")
    print(f"  ✓ Threat Actor: {parsed_data.get('threat_actor')}")
    print(f"  ✓ Techniques: {len(parsed_data.get('techniques', []))}")
    
    # 파싱 결과 저장
    parsed_path = session_dir / "01_parsed_scenario.json"
    with open(parsed_path, 'w', encoding='utf-8') as f:
        json.dump(parsed_data, f, indent=2, ensure_ascii=False)
    print(f"\n[*] Saved: {parsed_path.name}")
    
    # ========================================================================
    # PHASE 2: Caldera 검증
    # ========================================================================
    print_header("PHASE 2: Caldera Validation")
    
    validator = ScenarioValidator()
    
    print(f"\n[*] Validating techniques with Caldera...")
    validated_data = validator.validate_techniques_with_caldera(parsed_data)
    
    validation = validated_data.get('validation', {})
    print(f"\n  ✓ Total Techniques:     {validation.get('total')}")
    print(f"  ✓ Executable:           {validation.get('executable')} ({validation.get('coverage_rate', 0):.1f}%)")
    print(f"  ✗ Non-Executable:       {validation.get('non_executable')}")
    
    # 검증 결과 저장
    validated_path = session_dir / "02_validated_scenario.json"
    with open(validated_path, 'w', encoding='utf-8') as f:
        json.dump(validated_data, f, indent=2, ensure_ascii=False)
    print(f"\n[*] Saved: {validated_path.name}")
    
    # 실행 가능한 techniques 확인
    executable_techs = validator.get_executable_techniques(validated_data)
    
    if not executable_techs:
        print("\n[!] No executable techniques found!")
        print("Cannot proceed with operation creation.")
        return
    
    print(f"\n[*] Executable techniques:")
    for tech in executable_techs:
        print(f"  ✓ {tech['technique_id']}: {tech['technique_name']}")
    
    # ========================================================================
    # PHASE 3: 공격 체인 계획
    # ========================================================================
    print_header("PHASE 3: Attack Chain Planning")
    
    scenario_context = {
        "scenario_name": validated_data.get("scenario_name"),
        "target_org": validated_data.get("target_org"),
        "threat_actor": validated_data.get("threat_actor")
    }
    
    orchestrator = LLMOrchestrator()
    
    print(f"\n[*] Planning attack chain with LLM...")
    attack_chain = orchestrator.plan_executable_attack_chain(
        validated_data.get("techniques", []),
        scenario_context
    )
    
    if not attack_chain:
        print("\n[!] Failed to generate attack chain")
        return
    
    print(f"\n  ✓ Attack chain generated: {len(attack_chain)} steps")
    
    # 공격 체인 저장
    chain_path = session_dir / "03_attack_chain.json"
    with open(chain_path, 'w', encoding='utf-8') as f:
        json.dump({
            "scenario": scenario_context,
            "validation": validation,
            "attack_chain": attack_chain
        }, f, indent=2, ensure_ascii=False)
    print(f"\n[*] Saved: {chain_path.name}")
    
    # ========================================================================
    # PHASE 4: Caldera Operation 생성
    # ========================================================================
    print_header("PHASE 4: Caldera Operation Creation")
    
    # Operation Plan 생성
    operation_plan = {
        "name": f"S2C_{validated_data.get('threat_actor', 'Unknown').replace(' ', '_')}",
        "description": f"Automated attack chain for {validated_data.get('scenario_name')}",
        "steps": []
    }
    
    for step in attack_chain:
        operation_step = {
            "order": step["step"],
            "technique_id": step["technique_id"],
            "technique_name": step["technique_name"],
            "tactic": step["tactic"],
            "ability_id": step["ability_id"],
            "ability_name": step["ability_name"],
            "reason": step.get("reason", ""),
            "dependencies": step.get("dependencies", [])
        }
        operation_plan["steps"].append(operation_step)
    
    # Operation Plan 저장
    plan_path = session_dir / "04_operation_plan.json"
    with open(plan_path, 'w', encoding='utf-8') as f:
        json.dump(operation_plan, f, indent=2, ensure_ascii=False)
    print(f"\n[*] Saved: {plan_path.name}")
    
    # Caldera Operation 생성
    creator = OperationCreator()
    
    # Agent 목록 확인
    agents = creator.list_agents()
    
    if not agents:
        print("\n" + "="*80)
        print("⚠️  NO AGENTS AVAILABLE")
        print("="*80)
        print("\n📋 Manual Steps Required:")
        print("  1. Deploy Caldera agent on target VM")
        print("  2. Verify agent connection in Caldera UI")
        print("  3. Run this script again or use create_operation.py")
        print("\n💡 Operation plan is ready at:")
        print(f"   {plan_path}")
        return
    
    # 첫 번째 agent 자동 선택
    selected_agent = agents[0].get('paw')
    
    print(f"\n[*] Auto-selecting first agent: {selected_agent}")
    
    # Operation 생성 (Paused 모드)
    operation = creator.create_operation_from_plan(
        operation_plan,
        agent_paw=selected_agent,
        auto_start=False
    )
    
    if operation:
        # Operation 정보 저장
        operation_path = session_dir / "05_created_operation.json"
        with open(operation_path, 'w', encoding='utf-8') as f:
            json.dump({
                "operation": operation,
                "adversary_name": operation_plan.get('name'),
                "attack_chain": operation_plan.get('steps'),
                "selected_agent": selected_agent,
                "auto_start": False
            }, f, indent=2, ensure_ascii=False)
        print(f"\n[*] Saved: {operation_path.name}")
        
        # ========================================================================
        # 최종 요약
        # ========================================================================
        print_header("PIPELINE EXECUTION COMPLETE")
        
        print(f"\n📊 Summary:")
        print(f"    Scenario:             {validated_data.get('scenario_name')}")
        print(f"    Threat Actor:         {validated_data.get('threat_actor')}")
        print(f"    Total Techniques:     {validation.get('total')}")
        print(f"    Executable:           {validation.get('executable')} ({validation.get('coverage_rate', 0):.1f}%)")
        print(f"    Attack Chain Steps:   {len(attack_chain)}")
        print(f"    Operation ID:         {operation.get('id')}")
        print(f"    Target Agent:         {selected_agent}")
        
        print(f"\n📁 Generated Files:")
        print(f"    {session_dir}/")
        print(f"    ├── 01_parsed_scenario.json")
        print(f"    ├── 02_validated_scenario.json")
        print(f"    ├── 03_attack_chain.json")
        print(f"    ├── 04_operation_plan.json")
        print(f"    └── 05_created_operation.json")
        
        print(f"\n💡 Next Steps:")
        print(f"    1. Open Caldera UI:")
        print(f"       http://192.168.50.31:8888/#/operations/{operation.get('id')}")
        print(f"    2. Review the attack chain")
        print(f"    3. Click 'Start' to begin execution")
        print(f"    4. Monitor progress")
        print(f"    5. Run analyze_results.py to collect results")
        
        print("\n" + "="*80)
        print("✅ READY FOR EXECUTION!")
        print("="*80)
        
        return session_dir, operation.get('id')
    
    else:
        print("\n[!] Failed to create operation")
        return None, None


if __name__ == "__main__":
    if len(sys.argv) > 1:
        scenario_path = sys.argv[1]
    else:
        # 기본값: APT3 시나리오
        scenario_path = Path(__file__).parent.parent / "scenarios" / "APT3_threat_group_scenario.md"
    
    if not Path(scenario_path).exists():
        print(f"[!] Scenario file not found: {scenario_path}")
        sys.exit(1)
    
    session_dir, operation_id = main(str(scenario_path))
    
    if session_dir and operation_id:
        # 세션 정보 저장
        session_info = {
            "session_dir": str(session_dir),
            "operation_id": operation_id,
            "timestamp": datetime.now().isoformat()
        }
        
        with open(session_dir / "session_info.json", 'w', encoding='utf-8') as f:
            json.dump(session_info, f, indent=2)
