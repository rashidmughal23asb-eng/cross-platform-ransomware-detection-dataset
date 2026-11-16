#!/usr/bin/env python3
r"""
Prepare the NEXT Ubuntu V10 zero-slot qualification case.

SAFE SCOPE
----------
- Reads the frozen qualification schedule only.
- Selects the lowest-ranked row still marked PENDING.
- Creates a qualification case folder and blank receipt template.
- Does NOT download malware.
- Does NOT read malware binaries.
- Does NOT transfer/stage/execute malware.
- Does NOT start VMware.
- Does NOT consume any official run slot.
"""

from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(
    r"C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs"
)

QUAL_ROOT = (
    ROOT
    / r"01_SHARED\qualification"
    / "UBUNTU_V10_ZERO_SLOT_QUALIFICATION_20261110"
)

SCHEDULE = QUAL_ROOT / "UBUNTU_V10_ZERO_SLOT_QUALIFICATION_SCHEDULE.csv"
RULES = QUAL_ROOT / "QUALIFICATION_RULES.json"
SCHEMA = QUAL_ROOT / "QUALIFICATION_RECEIPT_SCHEMA.json"

CASE_ROOT = QUAL_ROOT / "cases"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_csv(path: Path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def sanitize(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)


def main():
    for path in (SCHEDULE, RULES, SCHEMA):
        if not path.is_file():
            raise RuntimeError(f"Required qualification artifact missing: {path}")

    rows = read_csv(SCHEDULE)

    pending = [
        row for row in rows
        if row.get("qualification_state", "").strip().upper() == "PENDING"
    ]

    if not pending:
        raise RuntimeError("No PENDING qualification rows remain.")

    pending.sort(key=lambda r: int(r["qualification_order"]))
    row = pending[0]

    rank = int(row["qualification_order"])
    family = row["family"].strip()
    sha = row["sha256"].strip().lower()
    role = row["role_at_freeze"].strip()

    case_name = f"Q{rank:02d}_{sanitize(family)}"
    case_dir = CASE_ROOT / case_name

    if case_dir.exists():
        raise RuntimeError(
            f"Case folder already exists; refusing overwrite: {case_dir}"
        )

    case_dir.mkdir(parents=True)
    (case_dir / "evidence").mkdir()
    (case_dir / "notes").mkdir()

    receipt = {
        "schema_version": "1.0",
        "qualification_order": rank,
        "role_at_freeze": role,
        "family": family,
        "sha256": sha,
        "attempt_timestamp_utc": None,
        "official_run_slot_consumed": False,
        "static_platform_identity": "PENDING",
        "telemetry_start": "PENDING",
        "process_launch": "PENDING",
        "meaningful_workload_observed": "PENDING",
        "modified_canary_count": None,
        "total_canary_count": None,
        "actual_execution_seconds": None,
        "termination_mode": None,
        "exit_code": None,
        "exit_code_source": None,
        "telemetry_finalize": "PENDING",
        "evidence_package_sha256": None,
        "snapshot_recovery": "PENDING",
        "workload_verdict": "PENDING",
        "qualification_decision": "PENDING",
        "decision_reason": None,
        "promotion_action": None,
        "notes": (
            "Template only. Populate only from observed zero-slot qualification evidence. "
            "Do not infer missing values."
        ),
    }

    receipt_path = case_dir / "QUALIFICATION_RECEIPT_TEMPLATE.json"
    receipt_path.write_text(
        json.dumps(receipt, indent=2),
        encoding="utf-8",
    )

    checklist = {
        "case_id": case_name,
        "qualification_order": rank,
        "family": family,
        "sha256": sha,
        "role_at_freeze": role,
        "status": "READY_FOR_MANUAL_ZERO_SLOT_QUALIFICATION",
        "must_verify_before_acceptance": [
            "frozen SHA-256 identity matches",
            "Ubuntu/platform compatibility confirmed",
            "telemetry starts successfully",
            "sample process launches under the frozen runner",
            "meaningful intended canary modification/encryption is observed",
            "telemetry finalizes successfully",
            "evidence package is complete and hash-verifiable",
            "snapshot recovery/revert completes successfully",
        ],
        "timing_contract": {
            "maximum_observation_seconds": 60,
            "controller_acceptance_band_if_still_running": "60-65 seconds",
            "watchdog_seconds": 90,
            "post_exit_telemetry_tail_seconds": 10,
            "natural_exit_before_60_allowed": True,
            "natural_exit_acceptance_condition": (
                "Only if genuine intended ransomware workload is observed."
            ),
        },
        "failure_examples": [
            "immediate/error exit without meaningful workload",
            "password/usage/configuration gate prevents intended workload",
            "platform incompatibility",
            "zero intended canary modification",
        ],
        "official_run_slot_consumed": False,
        "malware_downloaded_by_this_step": False,
        "malware_executed_by_this_step": False,
    }

    checklist_path = case_dir / "CASE_READINESS.json"
    checklist_path.write_text(
        json.dumps(checklist, indent=2),
        encoding="utf-8",
    )

    source_hashes = {
        str(SCHEDULE.relative_to(ROOT)): sha256_file(SCHEDULE),
        str(RULES.relative_to(ROOT)): sha256_file(RULES),
        str(SCHEMA.relative_to(ROOT)): sha256_file(SCHEMA),
    }

    receipt2 = {
        "status": "PASS_NEXT_CASE_PREPARED",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "case_id": case_name,
        "qualification_order": rank,
        "family": family,
        "sha256": sha,
        "role_at_freeze": role,
        "source_artifact_sha256": source_hashes,
        "official_run_slot_consumed": False,
        "malware_binaries_read": False,
        "malware_downloaded": False,
        "malware_transferred": False,
        "malware_executed": False,
    }

    prep_receipt = case_dir / "CASE_PREPARATION_RECEIPT.json"
    prep_receipt.write_text(
        json.dumps(receipt2, indent=2),
        encoding="utf-8",
    )

    checksums = []
    for p in sorted(
        x for x in case_dir.rglob("*")
        if x.is_file() and x.name != "SHA256SUMS.txt"
    ):
        checksums.append(f"{sha256_file(p)} *{p.relative_to(case_dir)}")

    (case_dir / "SHA256SUMS.txt").write_text(
        "\n".join(checksums) + "\n",
        encoding="ascii",
    )

    print("NEXT ZERO-SLOT QUALIFICATION CASE: PASS")
    print(f"Order:  {rank}")
    print(f"Role:   {role}")
    print(f"Family: {family}")
    print(f"SHA256: {sha}")
    print("Official run slots consumed: 0")
    print("No malware was downloaded, transferred, staged, or executed.")
    print("Case folder:", case_dir)


if __name__ == "__main__":
    main()
