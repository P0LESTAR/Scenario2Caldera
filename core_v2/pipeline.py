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

from core_v2.svo_extractor import SVOExtractor, AttackSVO
from core_v2.ability_generator import AbilityGenerator
from core_v2.react_agent import ReactAgent, FixAttempt


class Pipeline:
    """Scenario2Caldera v2 파이프라인 — SVO + ReAct 아키텍처"""

    def __init__(self):
        self.scenario = ScenarioProcessor()
        self.orchestrator = LLMOrchestrator()
        self.caldera = CalderaClient()
        self.svo_extractor = SVOExtractor()
        self.ability_generator = AbilityGenerator()
        self.react_agent = ReactAgent()

        # Cleanup 추적용
        self._created_abilities = []
        self._created_adversaries = []
        self._created_operations = []

    def _optimize_agent_sleep(self, sleep_min: int = 3, sleep_max: int = 5):
        """연결된 모든 에이전트의 sleep interval을 단축하여 실행 속도 향상"""
        print(f"[*] Optimizing agent sleep interval ({sleep_min}~{sleep_max}s)...")
        agents = self.caldera.get_agents()
        if not agents:
            print("  [!] No agents found to optimize")
            return

        for agent in agents:
            paw = agent.get('paw')
            if paw:
                success = self.caldera.update_agent(paw, {
                    "sleep_min": sleep_min,
                    "sleep_max": sleep_max
                })
                if success:
                    print(f"  ✓ Agent {paw}: sleep set to {sleep_min}~{sleep_max}s")
                else:
                    print(f"  ✗ Failed to update agent {paw}")

    def cleanup(self):
        """파이프라인 실행 중 생성된 임시 커스텀 Ability만 삭제
        (Operation과 Adversary는 Caldera UI에서 확인할 수 있도록 남겨둠)
        """
        self._print_header("CLEANUP CALDERA OBJECTS")
        print("[*] Removing generated custom abilities from Caldera...")

        # Abilities만 삭제 (Operation, Adversary는 유지)
        for ab_id in set(self._created_abilities):
            self.caldera.delete_ability(ab_id)

        print(f"  ✓ Cleanup complete. (Operations/Adversaries kept in Caldera)")

    def run(self, scenario_file: str, output_dir: str = None,
             force_generate: bool = False,
             use_svo: bool = True) -> Optional[Tuple[Path, str]]:
        """
        전체 파이프라인 실행

        Args:
            scenario_file: 시나리오 파일 경로
            output_dir: 결과 저장 디렉토리 (기본: results/)
            force_generate: True이면 기존 Caldera ability를 무시하고 SVO로만 생성 (실험용)
            use_svo: False이면 ReAct 프롬프트에서 SVO 제약 제거 (ablation 실험용)

        Returns:
            (session_dir, operation_id) 또는 None
        """
        self.use_svo = use_svo
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

        if force_generate:
            print("  ⚡ force_generate=True — skipping Caldera validation (all abilities will be SVO-generated)")
            validated_data = dict(parsed_data)
            for tech in validated_data.get("techniques", []):
                tech.setdefault("caldera_validation", {})
            _n = len(validated_data.get("techniques", []))
            validated_data["validation"] = {
                "total": _n, "executable": 0, "non_executable": _n,
                "exact_match": 0, "parent_fallback": 0, "coverage_rate": 0.0,
            }
        else:
            validated_data = self.scenario.validate(parsed_data)

        validation = validated_data.get('validation', {})
        print(f"\n  ✓ Total Techniques:     {validation.get('total')}")
        print(f"  ✓ Executable:           {validation.get('executable')} ({validation.get('coverage_rate', 0):.1f}%)")
        print(f"  ✗ Non-Executable:       {validation.get('non_executable')}")

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

        # 에이전트 sleep 단축 (속도 최적화)
        self._optimize_agent_sleep(sleep_min=3, sleep_max=5)

        # 환경 컨텍스트 수집 (LLM이 실제 주소를 커맨드에 넣도록)
        from config import CALDERA_CONFIG
        target_hosts = []
        for a in agents:
            host_ip = a.get('host_ip_addrs', [])
            if isinstance(host_ip, list):
                target_hosts.extend(host_ip)
            elif isinstance(host_ip, str) and host_ip:
                target_hosts.append(host_ip)

        agent_url = CALDERA_CONFIG.get("agent_url", CALDERA_CONFIG["url"])
        agent_info = {
            "c2_server_url": agent_url,
            "host": agent.get('host', '') if agent else '',
            "privilege": agent.get('privilege', 'User') if agent else 'User',
            "target_hosts": list(set(target_hosts)),  # 중복 제거
            "payloads": self.caldera.list_payloads(),  # Caldera에 있는 실제 payload 목록
            "payload_download_url_format": "#{server}/file/download/<filename>",
        }

        # 모든 technique에 대해 ability 확보 (기존 or 생성)
        ability_results = self.ability_generator.generate_abilities_for_plan(
            all_techniques, platform=platform, force_generate=force_generate,
            agent_info=agent_info
        )

        if ability_results:
            for ab in ability_results:
                if ab.get('source') == 'generated' and ab.get('ability_id'):
                    self._created_abilities.append(ab.get('ability_id'))

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

        _svo_suffix = "" if self.use_svo else "_noSVO"
        operation_plan = {
            "name": f"S2C_{validated_data.get('threat_actor', 'Unknown').replace(' ', '_')}{_svo_suffix}",
            "description": f"Automated attack chain for {validated_data.get('scenario_name')}",
            "steps": attack_chain
        }

        # Operation 생성 및 실행
        operation = self.caldera.create_operation_from_plan(
            operation_plan,
            agent_paw=selected_agent,
            auto_start=True
        )

        if operation:
            self._created_operations.append(operation.get('id'))
            if operation.get('s2c_adversary_id'):
                self._created_adversaries.append(operation.get('s2c_adversary_id'))

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
        # PHASE 6: ReAct Operation-Level Loop (최대 3라운드)
        # ==================================================================
        MAX_REACT_ROUNDS = 3
        react_history = []       # 라운드별 기록
        current_results = results
        current_op_id = operation_id

        if current_results and current_results.get('stats', {}).get('failed', 0) > 0:
            self._print_header("PHASE 6: ReAct Operation Loop")

            for round_num in range(1, MAX_REACT_ROUNDS + 1):
                # ── 실패한 link 추출 ────────────────────────────────
                failed_links = [
                    link for link in current_results.get('links', [])
                    if link.get('status', -1) != 0
                ]

                if not failed_links:
                    print(f"\n  ✅ All commands succeeded at round {round_num}!")
                    break

                print(f"\n{'─'*60}")
                print(f"  ROUND {round_num}/{MAX_REACT_ROUNDS}: {len(failed_links)} failed commands")
                print(f"{'─'*60}")

                round_fixes = []

                for i, link in enumerate(failed_links, 1):
                    ability = link.get('ability', {})
                    tech_id = ability.get('technique_id', 'Unknown')
                    ability_id = ability.get('ability_id', '')
                    link_id = link.get('id', '')

                    # ── 실제 에러 메시지 추출 ─────────────────────────
                    raw_output = link.get('output', '')
                    if raw_output in ('True', 'False', 'true', 'false', ''):
                        real_output = self.caldera.get_link_output(current_op_id, link_id)
                        error = real_output if real_output else f"Exit code: {link.get('status', -1)}"
                    else:
                        error = raw_output

                    # ── SVO 찾기 ─────────────────────────────────────
                    svo_data = None
                    for tech in all_techniques:
                        if tech.get('technique_id') == tech_id and tech.get('svo'):
                            svo_data = tech['svo']
                            break

                    if not svo_data:
                        print(f"  [{i}] {tech_id}: No SVO — skip")
                        round_fixes.append({
                            "technique_id": tech_id,
                            "ability_id": ability_id,
                            "status": "skipped",
                            "reason": "no_svo"
                        })
                        continue

                    svo = AttackSVO(**svo_data)

                    # ── 이전 시도 이력 구성 ──────────────────────────
                    # original_command + fixed_command 모두 포함해 역행(oscillation) 방지
                    prev_attempts = []
                    seen_cmds = set()
                    for prev_round in react_history:
                        for prev_fix in prev_round.get('fixes', []):
                            if prev_fix.get('technique_id') != tech_id:
                                continue
                            for cmd_key in ('original_command', 'fixed_command'):
                                cmd = prev_fix.get(cmd_key, '')
                                if cmd and cmd not in seen_cmds:
                                    seen_cmds.add(cmd)
                                    prev_attempts.append(FixAttempt(
                                        attempt=prev_round['round'],
                                        command=cmd,
                                        error=prev_fix.get('error', '')[:300],
                                        failure_type=prev_fix.get('failure_type', 'unknown'),
                                        thought="", action=""
                                    ))

                    # ── 원래 command 추출 ─────────────────────────────
                    executors = ability.get('executors', [])
                    original_cmd = executors[0].get('command', '') if executors else ''

                    print(f"  [{i}] {tech_id} ({svo.verb} → {svo.object})")
                    print(f"      Error: {error[:120]}")

                    # ── ReAct 수정 (1개 커맨드 생성) ──────────────────
                    react_result = self.react_agent.react_fix(
                        svo=svo,
                        failed_command=original_cmd,
                        error_output=error[:500],
                        platform=platform,
                        previous_attempts=prev_attempts,
                        env_context=agent_info,
                        use_svo=self.use_svo
                    )

                    fix_record = {
                        "technique_id": tech_id,
                        "ability_id": ability_id,
                        "svo": svo.to_dict(),
                        "original_command": original_cmd[:200],
                        "error": error[:300],
                        "failure_type": "unknown",
                    }

                    if react_result:
                        fixed_cmd = react_result["command"]
                        self.react_agent.update_ability_command(
                            ability_id, fixed_cmd, svo, platform
                        )
                        fix_record["fixed_command"] = fixed_cmd
                        fix_record["thought"] = react_result["thought"]
                        fix_record["action"] = react_result["action"]
                        fix_record["failure_type"] = react_result["failure_type"]
                        fix_record["svo_focus"] = react_result["svo_focus"]
                        fix_record["status"] = "patched"
                    else:
                        fix_record["status"] = "no_fix"
                        print(f"      [!] ReAct could not fix — skipping")

                    round_fixes.append(fix_record)

                # ── 라운드 커맨드 변경 요약 출력 ─────────────────────
                self._print_round_diff(round_num, round_fixes)

                # ── 라운드 기록 저장 ─────────────────────────────────
                patched_count = sum(1 for f in round_fixes if f.get('status') == 'patched')
                round_record = {
                    "round": round_num,
                    "failed_count": len(failed_links),
                    "patched_count": patched_count,
                    "fixes": round_fixes
                }
                react_history.append(round_record)

                if patched_count == 0:
                    print(f"\n  [!] No fixes produced in round {round_num} — stopping")
                    break

                print(f"\n  ✓ Patched {patched_count}/{len(failed_links)} abilities")

                # ── 전체 Operation 재실행 ────────────────────────────
                print(f"\n  → Re-executing full operation (Round {round_num})...")

                retry_op_plan = {
                    "name": f"{operation_plan.get('name', 'S2C')}_R{round_num}",
                    "description": f"ReAct round {round_num} — {patched_count} commands fixed",
                    "steps": attack_chain
                }

                retry_op = self.caldera.create_operation_from_plan(
                    retry_op_plan,
                    agent_paw=selected_agent,
                    auto_start=True
                )

                if retry_op:
                    self._created_operations.append(retry_op.get('id'))
                    if retry_op.get('s2c_adversary_id'):
                        self._created_adversaries.append(retry_op.get('s2c_adversary_id'))

                if not retry_op:
                    print(f"  [!] Failed to create retry operation")
                    break

                retry_op_id = retry_op.get('id')
                current_op_id = retry_op_id

                round_results = self._wait_and_collect(
                    retry_op_id, session_dir,
                    result_filename=None
                )

                if not round_results:
                    print(f"  [!] Failed to collect retry results")
                    break

                # ── 결과 비교 ────────────────────────────────────────
                prev_success = current_results.get('stats', {}).get('success', 0)
                new_success = round_results.get('stats', {}).get('success', 0)
                new_failed = round_results.get('stats', {}).get('failed', 0)
                print(f"\n  📊 Round {round_num} result: success {prev_success} → {new_success} (failed: {new_failed})")

                round_record['result_stats'] = round_results.get('stats', {})
                round_record['operation_id'] = retry_op_id

                current_results = round_results

                if new_failed == 0:
                    print(f"\n  🎉 All commands succeeded after {round_num} rounds!")
                    break

            # ── 라운드 전체 기록 저장 ────────────────────────────────
            self._save_json(session_dir / "07_react_summary.json", {
                "total_rounds": len(react_history),
                "rounds": react_history
            })

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
        print(f"    Initial Operation:    {operation_id}")
        print(f"    Target Agent:         {selected_agent}")

        if results:
            stats = results.get('stats', {})
            total = stats.get('total', 0)
            success = stats.get('success', 0)
            failed = stats.get('failed', 0)
            rate = (success / total * 100) if total > 0 else 0
            print(f"\n    Initial Execution:")
            print(f"    ✓ Success:            {success}/{total} ({rate:.1f}%)")

        if react_history:
            last_round = react_history[-1]
            last_stats = last_round.get('result_stats', {})
            if last_stats:
                final_success = last_stats.get('success', 0)
                final_total = last_stats.get('total', 0)
                final_rate = (final_success / final_total * 100) if final_total > 0 else 0
                print(f"\n    After ReAct ({len(react_history)} rounds):")
                print(f"    ✓ Success:            {final_success}/{final_total} ({final_rate:.1f}%)")

        print(f"\n📁 Generated Files:")
        print(f"    {session_dir}/")
        print(f"    ├── 01_parsed_scenario.json")
        print(f"    ├── 02_validated_scenario.json")
        print(f"    ├── 02_5_svo_extraction.json")
        print(f"    ├── 03_ability_acquisition.json")
        print(f"    ├── 04_attack_chain.json")
        print(f"    ├── 05_created_operation.json")
        print(f"    ├── 06_operation_results.json")
        if react_history:
            print(f"    ├── 07_react_summary.json")
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

    def run_from_parsed(self, parsed_data: Dict, output_dir: str = None,
                        force_generate: bool = True) -> Optional[Tuple[Path, str]]:
        """
        Phase 1(시나리오 파싱)을 건너뛰고 parsed_data를 직접 주입해 Phase 2부터 실행.
        Thief 같은 기존 adversary의 TTP(technique ID + tactic)만 뼈대로 사용하고
        ability는 SVO 기반으로 새로 생성. (force_generate=True 기본)
        """
        self._print_header("SCENARIO2CALDERA PIPELINE (Phase 2+ — parsed data injected)")

        if output_dir:
            base_dir = Path(output_dir)
        else:
            base_dir = Path(__file__).parent.parent / "results"
        base_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_dir = base_dir / f"session_{timestamp}"
        session_dir.mkdir(exist_ok=True)

        print(f"[*] Output directory: {session_dir}")
        print(f"  ✓ Scenario:    {parsed_data.get('scenario_name')}")
        print(f"  ✓ Threat Actor:{parsed_data.get('threat_actor')}")
        print(f"  ✓ Techniques:  {len(parsed_data.get('techniques', []))}")
        if force_generate:
            print(f"  ⚡ force_generate=True — SVO로 신규 ability 생성 (기존 ability 무시)")

        self._save_json(session_dir / "01_parsed_scenario.json", parsed_data)

        # PHASE 2
        self._print_header("PHASE 2: Caldera Validation")
        if force_generate:
            print("  ⚡ force_generate=True — skipping Caldera validation (all abilities will be SVO-generated)")
            validated_data = dict(parsed_data)
            for tech in validated_data.get("techniques", []):
                tech.setdefault("caldera_validation", {})
            _n = len(validated_data.get("techniques", []))
            validated_data["validation"] = {
                "total": _n, "executable": 0, "non_executable": _n,
                "exact_match": 0, "parent_fallback": 0, "coverage_rate": 0.0,
            }
        else:
            validated_data = self.scenario.validate(parsed_data)
        validation = validated_data.get('validation', {})
        print(f"\n  ✓ Total:      {validation.get('total')}")
        print(f"  ✓ Executable: {validation.get('executable')} ({validation.get('coverage_rate', 0):.1f}%)")
        # PHASE 2.5
        self._print_header("PHASE 2.5: SVO Extraction")
        all_techniques = validated_data.get("techniques", [])
        svos = self.svo_extractor.extract_all_svos(all_techniques)
        self._save_json(session_dir / "02_5_svo_extraction.json", {
            "total_techniques": len(all_techniques),
            "svo_extracted": len(svos),
            "svos": [s.to_dict() for s in svos]
        })

        # PHASE 3
        self._print_header("PHASE 3: Ability Acquisition")
        agents = self.caldera.list_agents()
        if not agents:
            print("\n⚠️  NO AGENTS AVAILABLE")
            return None

        selected_agent = agents[0].get('paw')
        agent = self.caldera.get_agent(selected_agent)
        platform = agent.get('platform', 'windows') if agent else 'windows'
        print(f"\n[*] Agent: {selected_agent} (platform: {platform})")

        # 에이전트 sleep 단축 (속도 최적화)
        self._optimize_agent_sleep(sleep_min=3, sleep_max=5)

        from config import CALDERA_CONFIG
        target_hosts = []
        for a in agents:
            host_ip = a.get('host_ip_addrs', [])
            if isinstance(host_ip, list):
                target_hosts.extend(host_ip)
            elif isinstance(host_ip, str) and host_ip:
                target_hosts.append(host_ip)

        agent_url = CALDERA_CONFIG.get("agent_url", CALDERA_CONFIG["url"])
        agent_info = {
            "c2_server_url": agent_url,
            "host": agent.get('host', '') if agent else '',
            "privilege": agent.get('privilege', 'User') if agent else 'User',
            "target_hosts": list(set(target_hosts)),
            "payloads": self.caldera.list_payloads(),
            "payload_download_url_format": "#{server}/file/download/<filename>",
        }

        ability_results = self.ability_generator.generate_abilities_for_plan(
            all_techniques, platform=platform, force_generate=force_generate,
            agent_info=agent_info
        )

        if ability_results:
            for ab in ability_results:
                if ab.get('source') == 'generated' and ab.get('ability_id'):
                    self._created_abilities.append(ab.get('ability_id'))

        if not ability_results:
            print("\n[!] No abilities available for any technique!")
            return None

        self._save_json(session_dir / "03_ability_acquisition.json", {
            "total_techniques": len(all_techniques),
            "abilities_acquired": len(ability_results),
            "abilities": ability_results
        })

        # PHASE 4
        self._print_header("PHASE 4: Attack Chain Planning & Operation Creation")
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

        self._save_json(session_dir / "04_attack_chain.json", {"attack_chain": attack_chain})

        _svo_suffix = "" if self.use_svo else "_noSVO"
        operation_plan = {
            "name": f"S2C_{validated_data.get('threat_actor', 'Unknown').replace(' ', '_')}{_svo_suffix}",
            "description": f"SVO-generated ability test for {validated_data.get('scenario_name')}",
            "steps": attack_chain
        }

        operation = self.caldera.create_operation_from_plan(
            operation_plan, agent_paw=selected_agent, auto_start=True
        )

        if operation:
            self._created_operations.append(operation.get('id'))
            if operation.get('s2c_adversary_id'):
                self._created_adversaries.append(operation.get('s2c_adversary_id'))

        if not operation:
            print("\n[!] Failed to create operation")
            return None

        self._save_json(session_dir / "05_created_operation.json", {
            "operation": operation,
            "attack_chain": attack_chain,
            "selected_agent": selected_agent,
        })

        operation_id = operation.get('id')

        # PHASE 5
        self._print_header("PHASE 5: Waiting for Operation to Complete")
        results = self._wait_and_collect(operation_id, session_dir,
                                         result_filename="06_operation_results.json")

        # PHASE 6: ReAct Loop
        MAX_REACT_ROUNDS = 3
        react_history = []
        current_results = results
        current_op_id = operation_id

        if current_results and current_results.get('stats', {}).get('failed', 0) > 0:
            self._print_header("PHASE 6: ReAct Operation Loop")

            for round_num in range(1, MAX_REACT_ROUNDS + 1):
                failed_links = [l for l in current_results.get('links', [])
                                if l.get('status', -1) != 0]

                if not failed_links:
                    print(f"\n  ✅ All commands succeeded at round {round_num}!")
                    break

                print(f"\n{'─'*60}")
                print(f"  ROUND {round_num}/{MAX_REACT_ROUNDS}: {len(failed_links)} failed")
                print(f"{'─'*60}")

                round_fixes = []
                for i, link in enumerate(failed_links, 1):
                    ability = link.get('ability', {})
                    tech_id = ability.get('technique_id', 'Unknown')
                    ability_id = ability.get('ability_id', '')
                    link_id = link.get('id', '')

                    raw_output = link.get('output', '')
                    if raw_output in ('True', 'False', 'true', 'false', ''):
                        real_output = self.caldera.get_link_output(current_op_id, link_id)
                        error = real_output if real_output else f"Exit code: {link.get('status', -1)}"
                    else:
                        error = raw_output

                    svo_data = None
                    for tech in all_techniques:
                        if tech.get('technique_id') == tech_id and tech.get('svo'):
                            svo_data = tech['svo']
                            break

                    if not svo_data:
                        print(f"  [{i}] {tech_id}: No SVO — skip")
                        round_fixes.append({"technique_id": tech_id, "ability_id": ability_id,
                                            "status": "skipped", "reason": "no_svo"})
                        continue

                    svo = AttackSVO(**svo_data)
                    prev_attempts = []
                    seen_cmds = set()
                    for prev_round in react_history:
                        for prev_fix in prev_round.get('fixes', []):
                            if prev_fix.get('technique_id') != tech_id:
                                continue
                            for cmd_key in ('original_command', 'fixed_command'):
                                cmd = prev_fix.get(cmd_key, '')
                                if cmd and cmd not in seen_cmds:
                                    seen_cmds.add(cmd)
                                    prev_attempts.append(FixAttempt(
                                        attempt=prev_round['round'],
                                        command=cmd,
                                        error=prev_fix.get('error', '')[:300],
                                        failure_type=prev_fix.get('failure_type', 'unknown'),
                                        thought="", action=""
                                    ))

                    executors = ability.get('executors', [])
                    original_cmd = executors[0].get('command', '') if executors else ''
                    print(f"  [{i}] {tech_id} ({svo.verb} → {svo.object})")
                    print(f"      Error: {error[:120]}")

                    react_result = self.react_agent.react_fix(
                        svo=svo, failed_command=original_cmd,
                        error_output=error[:500], platform=platform,
                        previous_attempts=prev_attempts, env_context=agent_info,
                        use_svo=self.use_svo
                    )

                    fix_record = {
                        "technique_id": tech_id, "ability_id": ability_id,
                        "svo": svo.to_dict(),
                        "original_command": original_cmd[:200], "error": error[:300],
                        "failure_type": "unknown",
                    }

                    if react_result:
                        fixed_cmd = react_result["command"]
                        self.react_agent.update_ability_command(ability_id, fixed_cmd, svo, platform)
                        fix_record["fixed_command"] = fixed_cmd
                        fix_record["thought"] = react_result["thought"]
                        fix_record["action"] = react_result["action"]
                        fix_record["failure_type"] = react_result["failure_type"]
                        fix_record["svo_focus"] = react_result["svo_focus"]
                        fix_record["status"] = "patched"
                    else:
                        fix_record["status"] = "no_fix"
                        print(f"      [!] ReAct could not fix — skipping")

                    round_fixes.append(fix_record)

                self._print_round_diff(round_num, round_fixes)

                patched_count = sum(1 for f in round_fixes if f.get('status') == 'patched')
                round_record = {"round": round_num, "failed_count": len(failed_links),
                                "patched_count": patched_count, "fixes": round_fixes}
                react_history.append(round_record)

                if patched_count == 0:
                    print(f"\n  [!] No fixes in round {round_num} — stopping")
                    break

                print(f"\n  ✓ Patched {patched_count}/{len(failed_links)} — re-executing...")

                retry_op = self.caldera.create_operation_from_plan(
                    {"name": f"{operation_plan['name']}_R{round_num}",
                     "description": f"ReAct R{round_num}", "steps": attack_chain},
                    agent_paw=selected_agent, auto_start=True
                )

                if retry_op:
                    self._created_operations.append(retry_op.get('id'))
                    if retry_op.get('s2c_adversary_id'):
                        self._created_adversaries.append(retry_op.get('s2c_adversary_id'))

                if not retry_op:
                    break

                current_op_id = retry_op.get('id')
                round_results = self._wait_and_collect(
                    current_op_id, session_dir,
                    result_filename=None
                )

                if not round_results:
                    break

                new_failed = round_results.get('stats', {}).get('failed', 0)
                print(f"\n  📊 Round {round_num}: failed {len(failed_links)} → {new_failed}")
                round_record['result_stats'] = round_results.get('stats', {})
                round_record['operation_id'] = current_op_id
                current_results = round_results

                if new_failed == 0:
                    print(f"\n  🎉 All succeeded after {round_num} rounds!")
                    break

            self._save_json(session_dir / "07_react_summary.json", {
                "total_rounds": len(react_history), "rounds": react_history
            })
        else:
            if results:
                print("\n[*] All steps succeeded! No retry needed.")

        # 요약
        self._print_header("PIPELINE COMPLETE")
        if results:
            stats = results.get('stats', {})
            total = stats.get('total', 0)
            success = stats.get('success', 0)
            rate = (success / total * 100) if total > 0 else 0
            print(f"\n  Initial: {success}/{total} ({rate:.1f}%)")

        print(f"\n🔗 Caldera UI: {self.caldera.base_url}/#/operations/{operation_id}")
        print("\n" + "="*80 + "\n✅ DONE\n" + "="*80)

        self._save_json(session_dir / "session_info.json", {
            "session_dir": str(session_dir),
            "operation_id": operation_id,
            "timestamp": datetime.now().isoformat()
        })

        return session_dir, operation_id

    def _wait_and_collect(self, operation_id: str, session_dir: Path,
                          poll_interval: int = 3, timeout: int = 1800,
                          result_filename: Optional[str] = "05_operation_results.json") -> Optional[Dict]:
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
        if result_filename:
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
    def _print_round_diff(round_num: int, fixes: list):
        """라운드별 명령어 변경 내역을 Before/After 형식으로 출력"""
        W = 110  # 줄 너비
        print(f"\n{'─'*W}")
        print(f"  ROUND {round_num} COMMAND DIFF")
        print(f"{'─'*W}")
        patched = [f for f in fixes if f.get('status') == 'patched']
        if not patched:
            print("  (no fixes)")
            return
        for idx, fix in enumerate(patched, 1):
            tech = fix.get('technique_id', '?')
            svo  = fix.get('svo', {})
            verb = svo.get('verb', '')
            obj  = svo.get('object', '')
            before = fix.get('original_command', '').replace('\n', ' ')
            after  = fix.get('fixed_command', '').replace('\n', ' ')
            # error에서 실제 메시지 추출 (JSON 형태면 stdout 우선)
            raw_err = fix.get('error', '')
            try:
                import json as _json
                err_obj = _json.loads(raw_err)
                err_msg = err_obj.get('stdout') or err_obj.get('stderr') or raw_err
            except Exception:
                err_msg = raw_err
            err_msg = err_msg.replace('\r', '').replace('\n', ' ').strip()
            L = 105
            print(f"\n  [{idx}] {tech}  ·  {verb} → {obj}")
            print(f"      BEFORE : {before[:L]}{'…' if len(before)>L else ''}")
            print(f"      ERROR  : {err_msg[:L]}{'…' if len(err_msg)>L else ''}")
            print(f"      AFTER  : {after[:L]}{'…' if len(after)>L else ''}")
        print(f"{'─'*W}")

    @staticmethod
    def _save_json(path: Path, data: Dict):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"\n[*] Saved: {path.name}")
