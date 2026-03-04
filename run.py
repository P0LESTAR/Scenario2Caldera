#!/usr/bin/env python3
"""
Scenario2Caldera v2 실행 진입점

Usage:
    python run.py scenario.md                    # 기본 실행 (기존 ability 우선)
    python run.py --force-generate   # SVO-only 실험 (기존 ability 무시)
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core_v2.pipeline import Pipeline

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scenario2Caldera v2 Pipeline")
    parser.add_argument("scenario", nargs="?",
                        default="scenarios/APT3_scenario.md",
                        help="시나리오 파일 경로")
    parser.add_argument("--force-generate", action="store_true",
                        help="기존 Caldera ability를 무시하고 SVO로만 커스텀 ability 생성 (실험용)")
    parser.add_argument("--keep-objects", action="store_true",
                        help="실행 중 생성된 Caldera 객체(ability/adversary/operation)를 지우지 않고 남김")
    args = parser.parse_args()

    pipeline = Pipeline()
    result = None
    try:
        result = pipeline.run(args.scenario, force_generate=args.force_generate)
    finally:
        # 정상 종료든 에러 발생(키보드 인터럽트 등)이든 마지막에 삭제
        if not args.keep_objects:
            pipeline.cleanup()

    if result:
        session_dir, op_id = result
        print(f"\n[DONE] session={session_dir}, op_id={op_id}")
    else:
        print("\n[FAILED] Pipeline did not complete")
        sys.exit(1)
