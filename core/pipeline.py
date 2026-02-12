#!/usr/bin/env python3
"""
Pipeline
시나리오 파싱 → Caldera 검증 → 공격 체인 계획 → Operation 생성
"""

import sys
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, Tuple

# 상위 디렉토리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.scenario import ScenarioProcessor
from core.llm_orchestrator import LLMOrchestrator
from core.caldera_client import CalderaClient


class Pipeline:
    """Scenario2Caldera 전체 파이프라인"""

    def __init__(self):
        self.scenario = ScenarioProcessor()
        self.orchestrator = LLMOrchestrator()
        self.caldera = CalderaClient()

    def run(self, scenario_file: str, output_dir: str = None) -> Optional[Tuple[Path, str]]:
        """
        전체 파이프라인 실행

        Args:
            scenario_file: 시나리오 파일 경로
            output_dir: 결과 저장 디렉토리 (기본: results/)

        Returns:
            (session_dir, operation_id) 또는 None
        """
        self._print_header("SCENARIO2CALDERA FULL PIPELINE EXECUTION")

        # 파일 경로 처리
        scenario_path = Path(scenario_file)
        if not scenario_path.is_absolute():
            scenario_path = Path(__file__).parent.parent / scenario_file

        if not scenario_path.exists():
            print(f"[!] Scenario file not found: {scenario_path}")
            return None

        print(f"\n[*] Scenario: {scenario_path}")

        # 출력 디렉토리 생성
        if output_dir:
            base_dir = Path(output_dir)
        else:
            base_dir = Path(__file__).parent.parent / "results"
        base_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_dir = base_dir / f"session_{timestamp}"
        session_dir.mkdir(exist_ok=True)

        print(f"[*] Output directory: {session_dir}")

        # ==================================================================
        # PHASE 1: 시나리오 파싱
        # ==================================================================
        self._print_header("PHASE 1: Scenario Parsing")

        parsed_data = self.scenario.parse(scenario_path)

        if not parsed_data:
            print("[!] Failed to parse scenario")
            return None

        print(f"  ✓ Scenario: {parsed_data.get('scenario_name')}")
        print(f"  ✓ Target: {parsed_data.get('target_org')}")
        print(f"  ✓ Threat Actor: {parsed_data.get('threat_actor')}")
        print(f"  ✓ Techniques: {len(parsed_data.get('techniques', []))}")

        self._save_json(session_dir / "01_parsed_scenario.json", parsed_data)

        # ==================================================================
        # PHASE 2: Caldera 검증
        # ==================================================================
        self._print_header("PHASE 2: Caldera Validation")

        validated_data = self.scenario.validate(parsed_data)

        validation = validated_data.get('validation', {})
        print(f"\n  ✓ Total Techniques:     {validation.get('total')}")
        print(f"  ✓ Executable:           {validation.get('executable')} ({validation.get('coverage_rate', 0):.1f}%)")
        print(f"  ✗ Non-Executable:       {validation.get('non_executable')}")

        self._save_json(session_dir / "02_validated_scenario.json", validated_data)

        executable_techs = self.scenario.get_executable_techniques(validated_data)

        if not executable_techs:
            print("\n[!] No executable techniques found!")
            return None

        print(f"\n[*] Executable techniques:")
        for tech in executable_techs:
            print(f"  ✓ {tech['technique_id']}: {tech['technique_name']}")

        # ==================================================================
        # PHASE 3: 공격 체인 계획
        # ==================================================================
        self._print_header("PHASE 3: Attack Chain Planning")

        scenario_context = {
            "scenario_name": validated_data.get("scenario_name"),
            "target_org": validated_data.get("target_org"),
            "threat_actor": validated_data.get("threat_actor")
        }

        attack_chain = self.orchestrator.plan_executable_attack_chain(
            validated_data.get("techniques", []),
            scenario_context
        )

        if not attack_chain:
            print("\n[!] Failed to generate attack chain")
            return None

        print(f"\n  ✓ Attack chain generated: {len(attack_chain)} steps")

        self._save_json(session_dir / "03_attack_chain.json", {
            "scenario": scenario_context,
            "validation": validation,
            "attack_chain": attack_chain
        })

        # ==================================================================
        # PHASE 4: Caldera Operation 생성
        # ==================================================================
        self._print_header("PHASE 4: Caldera Operation Creation")

        operation_plan = {
            "name": f"S2C_{validated_data.get('threat_actor', 'Unknown').replace(' ', '_')}",
            "description": f"Automated attack chain for {validated_data.get('scenario_name')}",
            "steps": attack_chain
        }

        # Agent 확인
        agents = self.caldera.list_agents()

        if not agents:
            print("\n" + "="*80)
            print("⚠️  NO AGENTS AVAILABLE")
            print("="*80)
            print("\n📋 Deploy Caldera agent on target VM, then run again.")
            return None

        selected_agent = agents[0].get('paw')
        print(f"\n[*] Auto-selecting first agent: {selected_agent}")

        # Operation 생성 및 실행
        operation = self.caldera.create_operation_from_plan(
            operation_plan,
            agent_paw=selected_agent,
            auto_start=True
        )

        if not operation:
            print("\n[!] Failed to create operation")
            return None

        self._save_json(session_dir / "04_created_operation.json", {
            "operation": operation,
            "adversary_name": operation_plan.get('name'),
            "attack_chain": attack_chain,
            "selected_agent": selected_agent,
        })

        operation_id = operation.get('id')

        # ==================================================================
        # PHASE 5: Operation 완료 대기 + 결과 수집
        # ==================================================================
        self._print_header("PHASE 5: Waiting for Operation to Complete")

        results = self._wait_and_collect(operation_id, session_dir)

        # ==================================================================
        # 최종 요약
        # ==================================================================
        self._print_header("PIPELINE COMPLETE")

        print(f"\n📊 Summary:")
        print(f"    Scenario:             {validated_data.get('scenario_name')}")
        print(f"    Threat Actor:         {validated_data.get('threat_actor')}")
        print(f"    Total Techniques:     {validation.get('total')}")
        print(f"    Executable:           {validation.get('executable')} ({validation.get('coverage_rate', 0):.1f}%)")
        print(f"    Attack Chain Steps:   {len(attack_chain)}")
        print(f"    Operation ID:         {operation_id}")
        print(f"    Target Agent:         {selected_agent}")

        if results:
            stats = results.get('stats', {})
            total = stats.get('total', 0)
            success = stats.get('success', 0)
            failed = stats.get('failed', 0)
            rate = (success / total * 100) if total > 0 else 0
            print(f"    Commands Executed:     {total}")
            print(f"    ✓ Success:            {success} ({rate:.1f}%)")
            print(f"    ✗ Failed:             {failed}")

        print(f"\n📁 Generated Files:")
        print(f"    {session_dir}/")
        print(f"    ├── 01_parsed_scenario.json")
        print(f"    ├── 02_validated_scenario.json")
        print(f"    ├── 03_attack_chain.json")
        print(f"    ├── 04_created_operation.json")
        print(f"    └── 05_operation_results.json")

        print(f"\n🔗 Caldera UI:")
        print(f"    {self.caldera.base_url}/#/operations/{operation_id}")

        print("\n" + "="*80)
        print("✅ DONE")
        print("="*80)

        self._save_json(session_dir / "session_info.json", {
            "session_dir": str(session_dir),
            "operation_id": operation_id,
            "timestamp": datetime.now().isoformat()
        })

        return session_dir, operation_id

    def _wait_and_collect(self, operation_id: str, session_dir: Path,
                          poll_interval: int = 10, timeout: int = 1800) -> Optional[Dict]:
        """
        Operation 완료까지 폴링 후 결과 수집

        Args:
            operation_id: Operation ID
            session_dir: 결과 저장 디렉토리
            poll_interval: 폴링 간격 (초, 기본 10)
            timeout: 최대 대기 시간 (초, 기본 1800 = 30분)

        Returns:
            분석 결과 dict
        """
        start_time = time.time()
        last_link_count = 0

        print(f"[*] Polling every {poll_interval}s (timeout: {timeout//60}min)")

        while True:
            elapsed = time.time() - start_time

            if elapsed > timeout:
                print(f"\n[!] Timeout after {timeout//60} minutes")
                break

            op = self.caldera.get_operation(operation_id)
            if not op:
                print(f"  [!] Failed to fetch operation")
                time.sleep(poll_interval)
                continue

            state = op.get('state', 'unknown')
            links = op.get('chain', [])
            link_count = len(links)

            # 진행 상황 표시 (새 link가 추가될 때만)
            if link_count != last_link_count:
                mins = int(elapsed // 60)
                secs = int(elapsed % 60)
                print(f"  [{mins:02d}:{secs:02d}] state={state}, links={link_count}")
                last_link_count = link_count

            if state == 'finished':
                mins = int(elapsed // 60)
                secs = int(elapsed % 60)
                print(f"\n  ✓ Operation finished in {mins}m {secs}s")
                break

            time.sleep(poll_interval)

        # 결과 수집 및 분석
        result = self.caldera.get_operation_results(operation_id)
        if not result:
            print("[!] Failed to collect results")
            return None

        op = result['operation']
        links = result['links']
        stats = self.caldera.analyze_links(links)

        # 분석 출력
        self.caldera.print_analysis(op, links, stats)

        # 결과 저장
        self._save_json(session_dir / "05_operation_results.json", {
            "operation_id": operation_id,
            "operation_name": op.get('name'),
            "state": op.get('state'),
            "summary": stats,
            "links": links,
            "analyzed_at": datetime.now().isoformat()
        })

        return {"stats": stats, "links": links}

    # ==================== Helpers ====================

    @staticmethod
    def _print_header(title: str):
        print("\n" + "="*80)
        print(title)
        print("="*80)

    @staticmethod
    def _save_json(path: Path, data: Dict):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"\n[*] Saved: {path.name}")
