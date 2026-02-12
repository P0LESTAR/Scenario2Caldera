#!/usr/bin/env python3
"""
APT3 Operation 결과 직접 분석
"""

import sys
import json
from pathlib import Path

# 상위 디렉토리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.caldera_client_base import CalderaClient

# Operation ID
operation_id = "ab036741-33c7-47bf-bc5b-7803d0520b7a"

print("="*80)
print("APT3 OPERATION RESULTS ANALYSIS")
print("="*80)

# Caldera Client 초기화
client = CalderaClient()

# Operation 조회
print(f"\n[*] Fetching operation: {operation_id}")
operation = client.get_operation(operation_id)

if not operation:
    print("[!] Operation not found")
    sys.exit(1)

print(f"  ✓ Operation: {operation.get('name')}")
print(f"    State: {operation.get('state')}")
print(f"    Start: {operation.get('start')}")

# Links (실행된 commands) 분석
links = operation.get('chain', [])
print(f"\n[*] Total commands executed: {len(links)}")

# 통계 수집
stats = {
    "total": len(links),
    "success": 0,
    "failed": 0,
    "running": 0,
    "by_technique": {},
    "by_tactic": {}
}

for link in links:
    status = link.get('status', -999)
    
    if status == 0:
        stats['success'] += 1
    elif status == 1:
        stats['running'] += 1
    else:
        stats['failed'] += 1
    
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

# 결과 출력
print("\n" + "="*80)
print("EXECUTION SUMMARY")
print("="*80)

print(f"\n📊 Overall Statistics:")
print(f"    Total Commands: {stats['total']}")
if stats['total'] > 0:
    print(f"    ✓ Success:      {stats['success']} ({stats['success']/stats['total']*100:.1f}%)")
    print(f"    ✗ Failed:       {stats['failed']} ({stats['failed']/stats['total']*100:.1f}%)")
    if stats['running'] > 0:
        print(f"    ⏳ Running:      {stats['running']}")

# Technique별 결과
print(f"\n🎯 Results by Technique:")
for tech_id, tech_stats in sorted(stats['by_technique'].items()):
    if tech_stats['count'] > 0:
        success_rate = (tech_stats['success'] / tech_stats['count'] * 100)
        status_icon = "✓" if tech_stats['failed'] == 0 else "✗"
        print(f"    {status_icon} {tech_id:12} {tech_stats['name']:50} {tech_stats['success']}/{tech_stats['count']} ({success_rate:.0f}%)")

# Tactic별 결과
print(f"\n🎭 Results by Tactic:")
for tactic, tactic_stats in sorted(stats['by_tactic'].items()):
    if tactic_stats['count'] > 0:
        success_rate = (tactic_stats['success'] / tactic_stats['count'] * 100)
        status_icon = "✓" if tactic_stats['failed'] == 0 else "✗"
        print(f"    {status_icon} {tactic:25} {tactic_stats['success']}/{tactic_stats['count']} ({success_rate:.0f}%)")

# 실행된 Commands 상세
print(f"\n📝 Executed Commands:")
for i, link in enumerate(links, 1):
    ability = link.get('ability', {})
    status = link.get('status', -999)
    
    if status == 0:
        status_str = "✓ SUCCESS"
    elif status == 1:
        status_str = "⏳ RUNNING"
    else:
        status_str = f"✗ FAILED ({status})"
    
    print(f"\n    {i}. {status_str}")
    print(f"       Technique: {ability.get('technique_id', 'N/A')}")
    print(f"       Name: {ability.get('name', 'Unknown')}")
    print(f"       Tactic: {ability.get('tactic', 'N/A')}")
    print(f"       Finish: {link.get('finish', 'N/A')}")
    
    # Output 표시 (있으면)
    output = link.get('output', '')
    if output and output != 'False':
        output_preview = output[:200] if len(output) > 200 else output
        print(f"       Output: {output_preview}...")

# JSON으로 저장
output_file = Path(__file__).parent / "results" / "apt3_analysis.json"
output_data = {
    "operation_id": operation_id,
    "operation_name": operation.get('name'),
    "state": operation.get('state'),
    "start_time": operation.get('start'),
    "statistics": stats,
    "links": links
}

with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(output_data, f, indent=2, ensure_ascii=False)

print(f"\n\n[*] Results saved to: {output_file}")

print("\n" + "="*80)
print("✅ ANALYSIS COMPLETE!")
print("="*80)
