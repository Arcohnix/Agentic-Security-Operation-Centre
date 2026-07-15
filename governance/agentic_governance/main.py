"""
Entry Point — Agentic AI Adaptive System Governance
Run modes:
  python main.py demo ddos       # DDoS attack simulation
  python main.py demo zeroday    # Zero-day lateral movement simulation
  python main.py demo combined   # Both attack types simultaneously
  python main.py eval            # UNSW-NB15 evaluation metrics
  python main.py full            # Demo + evaluation
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from orchestrator import AdaptiveGovernanceSystem


def run_demo(scenario: str = "ddos"):
    system = AdaptiveGovernanceSystem()
    system.run_demo(scenario=scenario)


def run_evaluation():
    system = AdaptiveGovernanceSystem()
    metrics = system.evaluate_unsw_nb15(n_samples=400)
    print("\nMetrics JSON:")
    print(json.dumps(metrics, indent=2))


def run_full():
    system = AdaptiveGovernanceSystem()
    system.run_demo(scenario="ddos")
    print("\n" + "─" * 65)
    system.run_demo(scenario="zeroday")
    print("\n" + "─" * 65)
    metrics = system.evaluate_unsw_nb15(n_samples=400)


if __name__ == "__main__":
    args = sys.argv[1:]

    if not args or args[0] == "demo":
        scenario = args[1] if len(args) > 1 else "ddos"
        run_demo(scenario)
    elif args[0] == "eval":
        run_evaluation()
    elif args[0] == "full":
        run_full()
    else:
        print("Usage: python main.py [demo ddos|demo zeroday|demo combined|eval|full]")
        run_demo("ddos")
