"""
Main entry point for O-RAN ADG Security Analysis.

Usage:
    python main.py --build       Build the ADG from extracted WG11 data
    python main.py --metrics     Run all quantitative metrics
    python main.py --scenarios   Run evaluation scenarios
    python main.py --visualize   Generate paper figures
    python main.py --all         Run everything
"""

import argparse
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="O-RAN ADG Security Analysis")
    parser.add_argument("--build", action="store_true", help="Build ADG from WG11 data")
    parser.add_argument("--metrics", action="store_true", help="Run quantitative metrics")
    parser.add_argument("--scenarios", action="store_true", help="Run evaluation scenarios")
    parser.add_argument("--visualize", action="store_true", help="Generate paper figures")
    parser.add_argument("--all", action="store_true", help="Run everything")
    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        return

    if args.all:
        args.build = args.metrics = args.scenarios = args.visualize = True

    if args.build:
        from adg_builder import build_adg, print_graph_stats
        print("Building ADG from WG11 data...")
        G = build_adg()
        print_graph_stats(G)

    if args.metrics:
        from adg_builder import build_adg
        from metrics import run_all_metrics
        G = build_adg()
        run_all_metrics(G)

    if args.scenarios:
        from scenarios import run_all_scenarios
        run_all_scenarios()

    if args.visualize:
        from visualize import generate_all_figures
        generate_all_figures()


if __name__ == "__main__":
    main()
