"""
CLI entry point for pqcpayment:
  python -m pqcpayment bench
  python -m pqcpayment serve --port 8020
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import uvicorn

from pqcpayment.bench import run_benchmark


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="pqcpayment",
        description="Card vault reference implementation: FF1 tokens, hybrid lattice + X25519 KEM envelopes",
    )
    sub = parser.add_subparsers(dest="command")

    bench_p = sub.add_parser("bench", help="Run the FF1 + hybrid KEM consistency benchmark")
    bench_p.add_argument("--pans", type=int, default=1000, help="Number of Luhn-valid PANs to test")
    bench_p.add_argument("--kem-trials", type=int, default=50, help="Number of PQC-KEM + CCA2 trials")

    serve_p = sub.add_parser("serve", help="Start FastAPI server and interactive web console")
    serve_p.add_argument("--host", type=str, default="127.0.0.1", help="Bind host")
    serve_p.add_argument("--port", type=int, default=8020, help="Bind port (default: 8020)")

    args = parser.parse_args()
    if args.command == "serve":
        if args.host not in ("127.0.0.1", "localhost", "::1") and not os.environ.get("PQCPAYMENT_API_KEY"):
            print("Refusing to listen on a non-loopback address without PQCPAYMENT_API_KEY set.", file=sys.stderr)
            return 2
        uvicorn.run("pqcpayment.api:app", host=args.host, port=args.port, reload=False)
        return 0

    # Default or "bench": run benchmark suite
    num_pans = getattr(args, "pans", 1000)
    kem_trials = getattr(args, "kem_trials", 50)
    if not (1 <= num_pans <= 100_000 and 1 <= kem_trials <= 1_000):
        parser.error("--pans must be 1..100000 and --kem-trials 1..1000")
    report = run_benchmark(num_pans=num_pans, kem_trials=kem_trials)
    print(json.dumps(report, indent=2))
    return 0 if report.get("all_invariants_passed") else 1


if __name__ == "__main__":
    sys.exit(main())
