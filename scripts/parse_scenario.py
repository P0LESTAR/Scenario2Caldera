#!/usr/bin/env python3
"""
Scenario Parser Script
Parse a scenario file and extract MITRE ATT&CK techniques
"""

import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.scenario_parser import ScenarioParser


def main():
    if len(sys.argv) < 2:
        print("Usage: python parse_scenario.py <scenario_file>")
        print("Example: python parse_scenario.py scenarios/APT3_scenario.md")
        sys.exit(1)
    
    scenario_file = sys.argv[1]
    
    if not Path(scenario_file).exists():
        print(f"Error: Scenario file not found: {scenario_file}")
        sys.exit(1)
    
    # Parse scenario
    parser = ScenarioParser()
    result = parser.parse_scenario_file(scenario_file)
    
    if not result:
        print("Error: Failed to parse scenario")
        sys.exit(1)
    
    # Save result
    output_dir = Path("results")
    output_dir.mkdir(exist_ok=True)
    
    output_file = output_dir / "parsed_scenario.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    
    print(f"\n✓ Parsed scenario saved to: {output_file}")
    print(f"  Scenario: {result.get('scenario_name')}")
    print(f"  Threat Actor: {result.get('threat_actor')}")
    print(f"  Techniques: {len(result.get('techniques', []))}")


if __name__ == "__main__":
    main()
