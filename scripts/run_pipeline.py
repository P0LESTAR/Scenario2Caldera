#!/usr/bin/env python3
"""Scenario2Caldera Pipeline CLI"""

import sys
from pathlib import Path

# 상위 디렉토리를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.pipeline import Pipeline


def main():
    if len(sys.argv) > 1:
        scenario_path = sys.argv[1]
    else:
        scenario_path = "scenarios/APT3_scenario.md"

    # 파일 존재 확인
    full_path = Path(scenario_path)
    if not full_path.is_absolute():
        full_path = Path(__file__).parent.parent / scenario_path

    if not full_path.exists():
        print(f"[!] Scenario file not found: {full_path}")
        print(f"Usage: python {Path(__file__).name} <scenario_file>")
        sys.exit(1)

    pipeline = Pipeline()
    result = pipeline.run(str(scenario_path))

    if not result:
        sys.exit(1)


if __name__ == "__main__":
    main()
