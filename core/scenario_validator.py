#!/usr/bin/env python3
"""
Scenario Validator
Caldera API를 통해 시나리오 기법들의 실행 가능 여부 검증
"""

import sys
import json
from pathlib import Path
from typing import Dict, List

# 상위 디렉토리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.caldera_client import CalderaClient


class ScenarioValidator:
    """
    파싱된 시나리오의 기법들을 Caldera 환경 검증
    """
    
    def __init__(self):
        self.caldera_client = CalderaClient()
    
    def validate_techniques_with_caldera(self, parsed_data: Dict) -> Dict:
        """
        파싱된 techniques를 Caldera로 검증하고 실행 가능 여부 표시
        
        Args:
            parsed_data: parse_scenario_file()의 결과
        
        Returns:
            검증 정보가 추가된 parsed_data
        """
        print("\n[*] Validating techniques with Caldera...")
        
        techniques = parsed_data.get("techniques", [])
        
        stats = {
            "total": len(techniques),
            "executable": 0,
            "non_executable": 0,
            "exact_match": 0,
            "parent_fallback": 0
        }
        
        for tech in techniques:
            tech_id = tech["technique_id"]
            
            # Caldera에서 ability 조회 (fallback 포함)
            result = self.caldera_client.get_abilities_with_fallback(tech_id)
            
            # 검증 정보 추가
            tech["caldera_validation"] = {
                "executable": result['match_type'] != 'none',
                "match_type": result['match_type'],
                "ability_count": len(result['abilities']),
                "fallback_applied": result['fallback_applied']
            }
            
            # 통계 업데이트
            reason = ""
            status = ""
            
            if result['match_type'] == 'exact':
                stats['executable'] += 1
                stats['exact_match'] += 1
                status = "✓"
                reason = f"{len(result['abilities'])} abilities"
            elif result['match_type'] == 'parent':
                stats['executable'] += 1
                stats['parent_fallback'] += 1
                status = "⚠"
                reason = f"Parent fallback ({result['technique_id']})"
            else:
                stats['non_executable'] += 1
                status = "✗"
                # 실행 불가능 이유 추론
                tactic = tech.get('tactic', '')
                tech_name_lower = tech.get('technique_name', '').lower()
                
                if tactic == 'reconnaissance':
                    reason = "Reconnaissance (Caldera 범위 밖)"
                elif tactic == 'resource-development':
                    reason = "Resource Development (Caldera 범위 밖)"
                elif 'exploit' in tech_name_lower:
                    reason = "CVE 의존적 (환경 특정)"
                elif 'fronting' in tech_name_lower:
                    reason = "고급 인프라 설정 필요"
                else:
                    reason = "Caldera ability 없음"
                
                tech["caldera_validation"]["warning"] = reason
            
            print(f"  {status} {tech_id:12} {tech.get('technique_name', 'N/A'):50} → {reason}")
        
        # 검증 요약 추가
        stats['coverage_rate'] = (stats['executable'] / stats['total'] * 100) if stats['total'] > 0 else 0
        parsed_data["validation"] = stats
        
        # 요약 출력
        print(f"\n[*] Validation Summary:")
        print(f"    Total Techniques:     {stats['total']}")
        print(f"    ✓ Executable:         {stats['executable']} ({stats['coverage_rate']:.1f}%)")
        print(f"      - Exact Match:      {stats['exact_match']}")
        print(f"      - Parent Fallback:  {stats['parent_fallback']}")
        print(f"    ✗ Non-Executable:     {stats['non_executable']}")
        
        return parsed_data
    
    def get_executable_techniques(self, parsed_data: Dict) -> List[Dict]:
        """실행 가능한 techniques만 필터링"""
        techniques = parsed_data.get("techniques", [])
        executable = [
            t for t in techniques
            if t.get("caldera_validation", {}).get("executable", False)
        ]
        
        print(f"\n[*] Filtered executable techniques: {len(executable)}/{len(techniques)}")
        return executable
