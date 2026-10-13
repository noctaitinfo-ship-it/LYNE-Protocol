#!/usr/bin/env python3
"""Runs LP 0.1's own, locked tests (lp-0.1/tests/run_tests.py — unmodified, byte-identical) inside this package.

The locked file also contains three checks of the repository it was written in: its CI workflow, its secret-scan
script and a gate contract over that repository's files. Those check a development repository, not the protocol, and
cannot apply here. This runner imports the locked module as it is and calls every PROTOCOL check:

  schemas · fixtures (valid, invalid, semantically invalid, tampered) · cryptography and lifecycle · signaling ·
  reproducible examples · protocol text · threat model · changelog

Needs: cryptography, jsonschema (tests/requirements.txt).   Usage: python tests/lp01_protocol_checks.py
"""

import importlib.util
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LP01 = Path(__file__).resolve().parent.parent / "lp-0.1"
PROTOCOL_CHECKS = ["check_fixtures", "check_crypto_and_lifecycle", "check_signaling", "check_reproducible", "check_protocol",
                   "check_threat_model", "check_changelog"]
REPOSITORY_CHECKS = ["check_gate1_contract", "check_secret_scan", "check_ci"]  # not run: they check a development repository


def main():
    sys.path.insert(0, str(LP01 / "tests"))
    spec = importlib.util.spec_from_file_location("lp01_run_tests", LP01 / "tests" / "run_tests.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    missing = [name for name in ["check_schemas", *PROTOCOL_CHECKS, *REPOSITORY_CHECKS] if not hasattr(m, name)]
    if missing:
        print(f"LP 0.1 PROTOCOL CHECKS: FAIL — the locked test file lacks {missing}")
        return 1
    report = m.Report()
    schemas = m.check_schemas(report)
    m.check_fixtures(report, schemas)
    for name in PROTOCOL_CHECKS[1:]:
        getattr(m, name)(report)
    total = report.passed + report.failed
    print(f"\nLP 0.1 PROTOCOL CHECKS: {'PASS' if not report.failed else 'FAIL'} ({report.passed}/{total}; not run here: {', '.join(REPOSITORY_CHECKS)})")
    return 1 if report.failed else 0


if __name__ == "__main__":
    sys.exit(main())
