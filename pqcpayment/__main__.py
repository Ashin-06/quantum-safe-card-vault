"""
CLI entry point for pqcpayment:
  python -m pqcpayment bench
  python -m pqcpayment serve      (settings: PQCPAYMENT_* environment variables, see ops.py)
  python -m pqcpayment migrate    (apply database migrations to PQCPAYMENT_DATABASE_URL and exit)
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pqcpayment",
        description="Card vault reference implementation: FF1 tokens, ML-KEM-768 + X25519 envelopes",
    )
    sub = parser.add_subparsers(dest="command")

    bench_p = sub.add_parser("bench", help="Run the FF1 + hybrid KEM consistency benchmark")
    bench_p.add_argument("--pans", type=int, default=1000, help="Number of Luhn-valid PANs to test")
    bench_p.add_argument("--kem-trials", type=int, default=50, help="Number of KEM round trips and tamper checks")

    serve_p = sub.add_parser("serve", help="Start FastAPI server and interactive web console")
    serve_p.add_argument("--host", help="default PQCPAYMENT_HOST or 127.0.0.1; any other address needs API keys")
    serve_p.add_argument("--port", type=int, help="default PQCPAYMENT_PORT or 8020")
    sub.add_parser("migrate", help="apply database migrations to PQCPAYMENT_DATABASE_URL")

    args = parser.parse_args(argv)
    if args.command == "migrate":
        from pqcpayment import db, ops

        applied = db.migrate(db.engine(ops.load_settings().database_url))
        print(*(applied or ["up to date"]), sep="\n")
        return 0
    if args.command == "serve":
        import uvicorn

        from pqcpayment import ops

        for name, val in (("HOST", args.host), ("PORT", args.port)):
            if val is not None:
                os.environ[f"PQCPAYMENT_{name}"] = str(val)
        try:
            settings = ops.load_settings()  # fail here, before uvicorn, with a readable message
        except ops.ConfigError as e:
            sys.exit(f"configuration error: {e}")
        ops.setup_logging(settings.log_level)
        uvicorn.run("pqcpayment.api:app", host=settings.host, port=settings.port, log_config=None, access_log=False)
        return 0

    from pqcpayment.bench import run_benchmark

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
