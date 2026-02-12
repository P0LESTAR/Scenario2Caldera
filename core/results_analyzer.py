#!/usr/bin/env python3
"""
Caldera Operation 결과 수집 및 분석
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# 상위 디렉토리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.caldera_client_base import CalderaClient


class OperationAnalyzer:
    """
    Caldera Operation 실행 결과 분석
    """
    
    def __init__(self):
        self.client = CalderaClient()
    
    def get_operation_results(self, operation_id: str) -> Dict:
        """
        Operation 결과 조회
        
        Returns:
            {
                "operation": {...},
                "links": [...],
                "summary": {...}
            }
        """
        print(f"\n[*] Fetching operation results: {operation_id}")
        
        # Operation 정보 조회
        operation = self.client.get_operation(operation_id)
        
        if not operation:
            print(f"  [!] Operation not found: {operation_id}")
            return None
        
        print(f"  OK Operation: {operation.get('name')}")
        print(f"     State: {operation.get('state')}")
        print(f"     Start: {operation.get('start')}")
        
        # Links (실행된 commands) 조회
        links = operation.get('chain', [])
        
        print(f"  OK Links: {len(links)} commands executed")
        
        return {
            "operation": operation,
            "links": links
        }
    
    def analyze_links(self, links: List[Dict]) -> Dict:
        """
        Links 분석
        
        Returns:
            {
                "total": int,
                "success": int,
                "failed": int,
                "by_technique": {...},
                "by_tactic": {...}
            }
        """
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
            # Status 분석
            # 0 = success, -2 = discarded, 1 = running, etc.
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
                    "count": 0,
                    "success": 0,
                    "failed": 0,
                    "name": ability.get('technique_name', 'Unknown')
                }
            
            stats['by_technique'][technique_id]['count'] += 1
            if status == 0:
                stats['by_technique'][technique_id]['success'] += 1
            else:
                stats['by_technique'][technique_id]['failed'] += 1
            
            # Tactic 분석
            if tactic not in stats['by_tactic']:
                stats['by_tactic'][tactic] = {
                    "count": 0,
                    "success": 0,
                    "failed": 0
                }
            
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
        
        # Operation 정보
        print(f"\n📋 Operation Information:")
        print(f"    ID: {operation.get('id')}")
        print(f"    Name: {operation.get('name')}")
        print(f"    State: {operation.get('state')}")
        print(f"    Start: {operation.get('start')}")
        print(f"    Adversary: {operation.get('adversary', {}).get('name')}")
        
        # 전체 통계
        print(f"\n📊 Execution Summary:")
        print(f"    Total Commands: {stats['total']}")
        print(f"    ✓ Success:      {stats['success']} ({stats['success']/stats['total']*100:.1f}%)")
        print(f"    ✗ Failed:       {stats['failed']} ({stats['failed']/stats['total']*100:.1f}%)")
        if stats['running'] > 0:
            print(f"    ⏳ Running:      {stats['running']}")
        
        # Status 상세
        print(f"\n📈 Status Breakdown:")
        for status, count in stats['by_status'].items():
            print(f"    {status:20} {count}")
        
        # Technique별 결과
        print(f"\n🎯 Results by Technique:")
        for tech_id, tech_stats in sorted(stats['by_technique'].items()):
            success_rate = (tech_stats['success'] / tech_stats['count'] * 100) if tech_stats['count'] > 0 else 0
            status_icon = "✓" if tech_stats['failed'] == 0 else "✗"
            print(f"    {status_icon} {tech_id:12} {tech_stats['name']:50} {tech_stats['success']}/{tech_stats['count']} ({success_rate:.0f}%)")
        
        # Tactic별 결과
        print(f"\n🎭 Results by Tactic:")
        for tactic, tactic_stats in sorted(stats['by_tactic'].items()):
            success_rate = (tactic_stats['success'] / tactic_stats['count'] * 100) if tactic_stats['count'] > 0 else 0
            status_icon = "✓" if tactic_stats['failed'] == 0 else "✗"
            print(f"    {status_icon} {tactic:25} {tactic_stats['success']}/{tactic_stats['count']} ({success_rate:.0f}%)")
        
        # 실행된 Commands 상세
        print(f"\n📝 Executed Commands:")
        for i, link in enumerate(links, 1):
            ability = link.get('ability', {})
            status = link.get('status', -999)
            
            if status == 0:
                status_str = "✓"
            elif status == 1:
                status_str = "⏳"
            else:
                status_str = "✗"
            
            print(f"\n    {i}. {status_str} {ability.get('technique_id', 'N/A')}: {ability.get('name', 'Unknown')}")
            print(f"       Tactic: {ability.get('tactic', 'N/A')}")
            print(f"       Status: {status}")
            print(f"       PID: {link.get('pid', 'N/A')}")
            print(f"       Finish: {link.get('finish', 'N/A')}")
            
            # Output 표시 (있으면)
            output = link.get('output', '')
            if output and output != 'False':
                print(f"       Output: {output[:100]}...")
    
    def export_results(self, operation: Dict, links: List[Dict], stats: Dict, 
                      filename: str = "operation_results.json"):
        """결과를 JSON으로 저장"""
        
        output_path = Path(__file__).parent / "execution_ready" / filename
        
        output_data = {
            "operation_id": operation.get('id'),
            "operation_name": operation.get('name'),
            "state": operation.get('state'),
            "start_time": operation.get('start'),
            "adversary": operation.get('adversary', {}).get('name'),
            "summary": stats,
            "links": links,
            "analyzed_at": datetime.now().isoformat()
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n[*] Results exported to: {output_path}")
        
        return output_path


def main():
    print("="*80)
    print("CALDERA OPERATION RESULTS ANALYZER")
    print("="*80)
    
    analyzer = OperationAnalyzer()
    
    # 생성된 operation 정보 로드
    created_op_path = Path(__file__).parent / "execution_ready" / "created_operation.json"
    
    if not created_op_path.exists():
        print(f"\n[!] Created operation file not found: {created_op_path}")
        print("Please provide operation ID manually:")
        operation_id = input("Operation ID: ").strip()
    else:
        with open(created_op_path, 'r', encoding='utf-8') as f:
            created_data = json.load(f)
        
        operation_id = created_data.get('operation', {}).get('id')
        print(f"\n[*] Loaded operation ID: {operation_id}")
    
    if not operation_id:
        print("[!] No operation ID provided")
        return
    
    # 결과 조회
    results = analyzer.get_operation_results(operation_id)
    
    if not results:
        return
    
    operation = results['operation']
    links = results['links']
    
    # 분석
    stats = analyzer.analyze_links(links)
    
    # 출력
    analyzer.print_analysis(operation, links, stats)
    
    # 저장
    analyzer.export_results(operation, links, stats)
    
    print("\n" + "="*80)
    print("✅ ANALYSIS COMPLETE!")
    print("="*80)


if __name__ == "__main__":
    main()
