#!/usr/bin/env python3
"""
Pipeline v2
시나리오 파싱 → SVO 추출 → Ability 확보(기존 선택 or 생성) → Operation → ReAct 자율 수정
"""

import sys
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# 상위 디렉토리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from core_v2.scenario import ScenarioProcessor
from core_v2.llm_orchestrator import LLMOrchestrator
from core_v2.caldera_client import CalderaClient
from core_v2.retry_analyzer import RetryAnalyzer
from core_v2.svo_extractor import SVOExtractor, AttackSVO
from core_v2.ability_generator import AbilityGenerator
from core_v2.react_agent import ReactAgent


class Pipeline:
    """Scenario2Caldera v2 파이프라인 — SVO + ReAct 아키텍처"""

    def __init__(self):
        self.scenario = ScenarioProcessor()
        self.orchestrator = LLMOrchestrator()
        self.caldera = CalderaClient()
        self.svo_extractor = SVOExtractor()
        self.ability_generator = AbilityGenerator()
        self.react_agent = ReactAgent()

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
        # PHASE 2: Caldera 검증 + SVO 추출
        # ==================================================================
        self._print_header("PHASE 2: Caldera Validation")

        validated_data = self.scenario.validate(parsed_data)

        validation = validated_data.get('validation', {})
        print(f"\n  ✓ Total Techniques:     {validation.get('total')}")
        print(f"  ✓ Executable:           {validation.get('executable')} ({validation.get('coverage_rate', 0):.1f}%)")
        print(f"  ✗ Non-Executable:       {validation.get('non_executable')}")

        self._save_json(session_dir / "02_validated_scenario.json", validated_data)

        # ------------------------------------------------------------------
        # PHASE 2.5: SVO 추출 (모든 technique에 대해)
        # ------------------------------------------------------------------
        self._print_header("PHASE 2.5: SVO Extraction")

        all_techniques = validated_data.get("techniques", [])
        svos = self.svo_extractor.extract_all_svos(all_techniques)

        self._save_json(session_dir / "02_5_svo_extraction.json", {
            "total_techniques": len(all_techniques),
            "svo_extracted": len(svos),
            "svos": [s.to_dict() for s in svos]
        })

        # ------------------------------------------------------------------
        # PHASE 3: Ability 확보 (기존 선택 or SVO 기반 생성)
        # ------------------------------------------------------------------
        self._print_header("PHASE 3: Ability Acquisition")

        # Agent 확인 (ability 생성 시 platform 파악 필요)
        agents = self.caldera.list_agents()

        if not agents:
            print("\n" + "="*80)
            print("⚠️  NO AGENTS AVAILABLE")
            print("="*80)
            print("\n📋 Deploy Caldera agent on target VM, then run again.")
            return None

        selected_agent = agents[0].get('paw')
        agent = self.caldera.get_agent(selected_agent)
        platform = agent.get('platform', 'windows') if agent else 'windows'
        print(f"\n[*] Agent: {selected_agent} (platform: {platform})")

        # 모든 technique에 대해 ability 확보 (기존 or 생성)
        ability_results = self.ability_generator.generate_abilities_for_plan(
            all_techniques, platform=platform
        )

        if not ability_results:
            print("\n[!] No abilities available for any technique!")
            return None

        self._save_json(session_dir / "03_ability_acquisition.json", {
            "total_techniques": len(all_techniques),
            "abilities_acquired": len(ability_results),
            "abilities": ability_results
        })

        # ------------------------------------------------------------------
        # PHASE 4: 공격 체인 계획 + Operation 생성
        # ------------------------------------------------------------------
        self._print_header("PHASE 4: Attack Chain Planning & Operation Creation")

        scenario_context = {
            "scenario_name": validated_data.get("scenario_name"),
            "target_org": validated_data.get("target_org"),
            "threat_actor": validated_data.get("threat_actor")
        }

        # ability_results를 attack_chain 형식으로 변환
        attack_chain = []
        for ab in ability_results:
            attack_chain.append({
                "technique_id": ab.get("technique_id"),
                "technique_name": ab.get("technique_name", ""),
                "ability_id": ab.get("ability_id"),
                "ability_name": ab.get("ability_name", ab.get("name", "")),
                "source": ab.get("source", "existing"),
            })

        print(f"\n  ✓ Attack chain: {len(attack_chain)} steps")
        for i, step in enumerate(attack_chain, 1):
            src = "🔵" if step['source'] == 'existing' else "🟢"
            print(f"    {i}. {src} {step['technique_id']}: {step['ability_name']} [{step['source']}]")

        self._save_json(session_dir / "04_attack_chain.json", {
            "scenario": scenario_context,
            "validation": validation,
            "attack_chain": attack_chain
        })

        operation_plan = {
            "name": f"S2C_{validated_data.get('threat_actor', 'Unknown').replace(' ', '_')}",
            "description": f"Automated attack chain for {validated_data.get('scenario_name')}",
            "steps": attack_chain
        }

        # Operation 생성 및 실행
        operation = self.caldera.create_operation_from_plan(
            operation_plan,
            agent_paw=selected_agent,
            auto_start=True
        )

        if not operation:
            print("\n[!] Failed to create operation")
            return None

        self._save_json(session_dir / "05_created_operation.json", {
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

        results = self._wait_and_collect(operation_id, session_dir,
                                         result_filename="06_operation_results.json")

        # ==================================================================
        # PHASE 6: ReAct 자율 수정 → RetryAnalyzer Fallback
        # ==================================================================
        retry_result = None
        react_results = []

        if results and results.get('stats', {}).get('failed', 0) > 0:
            self._print_header("PHASE 6: ReAct Self-Fix Loop")

            # 실패한 link 추출
            failed_links = [
                link for link in results.get('links', [])
                if link.get('status', -1) != 0
            ]

            print(f"\n[*] {len(failed_links)} failed commands detected")

            for i, link in enumerate(failed_links, 1):
                ability = link.get('ability', {})
                tech_id = ability.get('technique_id', 'Unknown')
                ability_id = ability.get('ability_id', '')
                error = link.get('output', '') or f"Exit code: {link.get('status', -1)}"

                # 이 technique의 SVO 찾기
                svo_data = None
                for tech in all_techniques:
                    if tech.get('technique_id') == tech_id and tech.get('svo'):
                        svo_data = tech['svo']
                        break

                if not svo_data:
                    print(f"\n  [{i}] {tech_id}: No SVO — skipping ReAct")
                    continue

                svo = AttackSVO(**svo_data)

                # 원래 command 추출
                executors = ability.get('executors', [])
                original_cmd = executors[0].get('command', '') if executors else ''

                print(f"\n  [{i}] ReAct for {tech_id}: {svo.intent_summary()}")

                react_result = self.react_agent.run_react_loop(
                    svo=svo,
                    initial_command=original_cmd,
                    initial_error=error[:500],
                    platform=platform
                )

                react_results.append({
                    "technique_id": tech_id,
                    "ability_id": ability_id,
                    **react_result
                })

                # ReAct 수정이 있으면 ability 업데이트
                if react_result.get('fixed_commands') and not react_result.get('exhausted'):
                    new_cmd = react_result['fixed_commands'][0]['command']
                    self.react_agent.update_ability_command(
                        ability_id, new_cmd, svo, platform
                    )

            self._save_json(session_dir / "07_react_fixes.json", {
                "total_failed": len(failed_links),
                "react_results": react_results,
            })

            # ReAct로 수정된 ability가 있으면 새 Operation 실행
            fixed_ability_ids = [
                r['ability_id'] for r in react_results
                if r.get('fixed_commands') and not r.get('exhausted')
            ]

            if fixed_ability_ids:
                self._print_header("PHASE 6b: Re-executing Fixed Abilities")
                print(f"\n[*] {len(fixed_ability_ids)} abilities were fixed by ReAct")

                # 수정된 ability들로 새 Operation 생성
                retry_plan = {
                    "name": f"{operation_plan.get('name', 'S2C')}_ReAct",
                    "description": "ReAct self-fixed retry operation",
                    "steps": [
                        step for step in attack_chain
                        if step.get('ability_id') in fixed_ability_ids
                    ]
                }

                if retry_plan['steps']:
                    retry_op = self.caldera.create_operation_from_plan(
                        retry_plan,
                        agent_paw=selected_agent,
                        auto_start=True
                    )

                    if retry_op:
                        retry_op_id = retry_op.get('id')
                        react_op_results = self._wait_and_collect(
                            retry_op_id, session_dir,
                            result_filename="08_react_retry_results.json"
                        )

            # ReAct로 해결 못한 건 → RetryAnalyzer fallback
            exhausted_techs = [
                r['technique_id'] for r in react_results
                if r.get('exhausted')
            ]

            if exhausted_techs:
                self._print_header("PHASE 6c: RetryAnalyzer Fallback")
                print(f"\n[*] {len(exhausted_techs)} techniques exhausted ReAct — falling back")

                agent_info = {
                    "platform": platform,
                    "privilege": agent.get('privilege', 'User') if agent else 'User'
                }

                retry_analyzer = RetryAnalyzer()
                retry_name = f"{operation_plan.get('name', 'S2C')}_Fallback"

                retry_result = retry_analyzer.run(
                    operation_results=results,
                    agent_info=agent_info,
                    agent_paw=selected_agent,
                    retry_name=retry_name
                )

                if retry_result:
                    self._save_json(session_dir / "09_fallback_analysis.json", {
                        "exhausted_techniques": exhausted_techs,
                        "recommendations": retry_result.get('recommendations', []),
                        "alternatives": retry_result.get('alternatives', []),
                    })

                    retry_op = retry_result.get('retry_operation')
                    if retry_op:
                        retry_op_id = retry_op.get('id')
                        self._print_header("PHASE 6d: Waiting for Fallback Operation")
                        fallback_results = self._wait_and_collect(
                            retry_op_id, session_dir,
                            result_filename="10_fallback_results.json"
                        )
                        if fallback_results:
                            retry_result['retry_stats'] = fallback_results.get('stats', {})
        else:
            if results:
                print("\n[*] All steps succeeded! No retry needed.")

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

        if retry_result:
            alts = retry_result.get('alternatives', [])
            retry_stats = retry_result.get('retry_stats', {})
            print(f"\n    🔄 Retry:")
            print(f"    Alternative abilities: {len(alts)}")
            if retry_stats:
                r_total = retry_stats.get('total', 0)
                r_success = retry_stats.get('success', 0)
                r_rate = (r_success / r_total * 100) if r_total > 0 else 0
                print(f"    Retry Success:        {r_success}/{r_total} ({r_rate:.1f}%)")

        print(f"\n📁 Generated Files:")
        print(f"    {session_dir}/")
        print(f"    ├── 01_parsed_scenario.json")
        print(f"    ├── 02_validated_scenario.json")
        print(f"    ├── 02_5_svo_extraction.json")
        print(f"    ├── 03_ability_acquisition.json")
        print(f"    ├── 04_attack_chain.json")
        print(f"    ├── 05_created_operation.json")
        print(f"    ├── 06_operation_results.json")
        if react_results:
            print(f"    ├── 07_react_fixes.json")
            if fixed_ability_ids:
                print(f"    ├── 08_react_retry_results.json")
        if retry_result and retry_result.get('retry_operation'):
            print(f"    ├── 09_fallback_analysis.json")
            print(f"    ├── 10_fallback_results.json")
        print(f"    └── session_info.json")

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
                          poll_interval: int = 10, timeout: int = 1800,
                          result_filename: str = "05_operation_results.json") -> Optional[Dict]:
        """
        Operation 완료까지 폴링 후 결과 수집

        Args:
            operation_id: Operation ID
            session_dir: 결과 저장 디렉토리
            poll_interval: 폴링 간격 (초, 기본 10)
            timeout: 최대 대기 시간 (초, 기본 1800 = 30분)
            result_filename: 결과 파일명

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
        self._save_json(session_dir / result_filename, {
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
