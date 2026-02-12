#!/usr/bin/env python3
"""
Enhanced Caldera Client
Parent Technique Fallback 및 Best Ability Selection 기능 추가
"""

import sys
from pathlib import Path
from typing import Dict, List, Optional

# 상위 디렉토리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.caldera_client_base import CalderaClient


class EnhancedCalderaClient(CalderaClient):
    """
    CalderaClient를 상속받아 추가 기능 제공
    - Parent Technique Fallback
    - Best Ability Selection
    """
    
    def get_abilities_with_fallback(self, technique_id: str, enable_fallback: bool = True) -> Dict:
        """
        Technique ID로 Ability 조회 (Parent Technique Fallback 지원)
        
        Args:
            technique_id: MITRE ATT&CK 기법 ID (예: T1547.001)
            enable_fallback: Parent technique fallback 활성화 여부
        
        Returns:
            {
                "technique_id": str,  # 실제 매칭된 technique ID
                "match_type": str,    # "exact", "parent", "none"
                "abilities": List[Dict],
                "fallback_applied": bool
            }
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
        """
        여러 Ability 중 최적의 것을 선택
        
        Args:
            abilities: Ability 목록
            prefer_low_privilege: 낮은 권한 우선 선택 여부
            platform: 플랫폼 필터 (windows, linux, darwin)
        
        Returns:
            선택된 Ability (없으면 None)
        """
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
            # 권한이 없거나 낮은 것 우선
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


if __name__ == "__main__":
    # 테스트
    print("="*80)
    print("Enhanced Caldera Client Test")
    print("="*80)
    
    client = EnhancedCalderaClient()
    
    # 테스트 케이스
    test_cases = [
        "T1547.001",  # Sub-technique with abilities
        "T1589.001",  # Sub-technique without abilities
        "T1047",      # Parent technique with abilities
    ]
    
    for tech_id in test_cases:
        print(f"\n[Test] {tech_id}")
        print("-"*80)
        
        result = client.get_abilities_with_fallback(tech_id)
        
        print(f"  Match Type: {result['match_type']}")
        print(f"  Matched ID: {result['technique_id']}")
        print(f"  Abilities: {len(result['abilities'])}")
        print(f"  Fallback: {result['fallback_applied']}")
        
        if result['abilities']:
            best = client.select_best_ability(
                result['abilities'],
                platform="windows"
            )
            if best:
                print(f"  Best: {best.get('name')}")
