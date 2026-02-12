#!/usr/bin/env python3
"""
Enhanced Scenario Parser (테스트 버전)
Caldera 실행 가능 여부 검증 기능 추가
"""

import sys
import json
from pathlib import Path
from typing import Dict, List

# 상위 디렉토리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.scenario_parser import ScenarioParser
from core.caldera_client import EnhancedCalderaClient


class EnhancedScenarioParser(ScenarioParser):
    """
    ScenarioParser를 상속받아 Caldera 검증 기능 추가
    """
    
    def __init__(self):
        super().__init__()
        self.caldera_client = EnhancedCalderaClient()
    
    def validate_techniques_with_caldera(self, parsed_data: Dict) -> Dict:
        """
        파싱된 techniques를 Caldera로 검증하고 실행 가능 여부 표시
        
        Args:
            parsed_data: parse_scenario_file()의 결과
        
        Returns:
            검증 정보가 추가된 parsed_data
            {
                ...원본 데이터,
                "validation": {
                    "total": 13,
                    "executable": 8,
                    "non_executable": 5,
                    "coverage_rate": 61.5
                }
            }
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
                if tactic == 'reconnaissance':
                    reason = "Reconnaissance (Caldera 범위 밖)"
                elif tactic == 'resource-development':
                    reason = "Resource Development (Caldera 범위 밖)"
                elif 'exploit' in tech.get('technique_name', '').lower():
                    reason = "CVE 의존적 (환경 특정)"
                elif 'fronting' in tech.get('technique_name', '').lower():
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
        """
        실행 가능한 techniques만 필터링
        
        Returns:
            실행 가능한 technique 목록
        """
        techniques = parsed_data.get("techniques", [])
        executable = [
            t for t in techniques
            if t.get("caldera_validation", {}).get("executable", False)
        ]
        
        print(f"\n[*] Filtered executable techniques: {len(executable)}/{len(techniques)}")
        return executable
    
    def get_non_executable_techniques(self, parsed_data: Dict) -> List[Dict]:
        """
        실행 불가능한 techniques만 필터링
        
        Returns:
            실행 불가능한 technique 목록
        """
        techniques = parsed_data.get("techniques", [])
        non_executable = [
            t for t in techniques
            if not t.get("caldera_validation", {}).get("executable", False)
        ]
        
        return non_executable


if __name__ == "__main__":
    print("="*80)
    print("Enhanced Scenario Parser Test")
    print("="*80)
    
    parser = EnhancedScenarioParser()
    
    # 기존 로그에서 파싱된 데이터 로드 (LLM 호출 없이 테스트)
    log_path = Path(__file__).parent.parent / "logs" / "carma_session_20260208_181956.json"
    
    with open(log_path, 'r', encoding='utf-8') as f:
        log_data = json.load(f)
    
    parsed_data = log_data.get("scenario_parsed")
    
    print(f"\n[*] Loaded scenario: {parsed_data.get('scenario_name')}")
    print(f"[*] Techniques: {len(parsed_data.get('techniques', []))}")
    
    # Caldera 검증
    validated_data = parser.validate_techniques_with_caldera(parsed_data)
    
    # 실행 가능한 techniques 필터링
    executable = parser.get_executable_techniques(validated_data)
    
    print(f"\n[*] Executable Techniques:")
    for tech in executable:
        validation = tech.get("caldera_validation", {})
        print(f"    - {tech['technique_id']}: {tech['technique_name']}")
        print(f"      Match: {validation['match_type']}, Abilities: {validation['ability_count']}")
    
    # 실행 불가능한 techniques
    non_executable = parser.get_non_executable_techniques(validated_data)
    
    if non_executable:
        print(f"\n[*] Non-Executable Techniques:")
        for tech in non_executable:
            validation = tech.get("caldera_validation", {})
            print(f"    - {tech['technique_id']}: {tech['technique_name']}")
            print(f"      Reason: {validation.get('warning', 'Unknown')}")
    
    # 결과 저장
    output_path = Path(__file__).parent / "validated_scenario.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(validated_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n[*] Validated data saved to: {output_path}")
