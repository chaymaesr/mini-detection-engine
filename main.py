import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rule_loader import RuleLoader, RuleLoaderError
from engine import RuleEngine
from alert_generator import AlertGenerator

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules",   default="rules/rules.json")
    parser.add_argument("--events",  required=True)
    parser.add_argument("--output",  default="alerts")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--no-save", action="store_true")
    return parser.parse_args()

def main():
    print("\n" + "="*60)
    print("   MINI MOTEUR DE DETECTION - OS & Application Security")
    print("="*60 + "\n")
    args = parse_args()

    try:
        loader = RuleLoader(args.rules)
        rules  = loader.load()
    except Exception as e:
        print(f"[ERREUR] {e}"); sys.exit(1)

    with open(args.events, "r", encoding="utf-8") as f:
        events = json.load(f)
    print(f"[main] {len(events)} evenement(s) charge(s)")

    engine    = RuleEngine(rules)
    matches   = engine.run(events)
    generator = AlertGenerator(matches)
    generator.generate()
    generator.print_alerts()

    s = generator.get_summary()
    print(f"  Alertes : {s['total']}  (HIGH:{s['high']} MEDIUM:{s['medium']} LOW:{s['low']})\n")

    if not args.no_save:
        generator.save(output_dir=args.output)

if __name__ == "__main__":
    main()