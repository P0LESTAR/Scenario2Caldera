#!/usr/bin/env python3
"""
Scenario2Caldera v2 실행 진입점
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core_v2.pipeline import Pipeline

if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "scenarios/APT3_scenario.md"
    pipeline = Pipeline()
    result = pipeline.run(scenario)
    if result:
        session_dir, op_id = result
        print(f"\n[DONE] session={session_dir}, op_id={op_id}")
    else:
        print("\n[FAILED] Pipeline did not complete")
        sys.exit(1)
