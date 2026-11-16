#!/usr/bin/env python3
r"""
Freeze the Ubuntu V10 zero-slot qualification schedule and evidence index.

SAFE SCOPE
----------
- Reads only frozen metadata/artifacts.
- Creates scheduling, evidence-index, and reproducibility metadata.
- Does NOT download malware.
- Does NOT read malware binaries.
- Does NOT start VMware.
- Does NOT transfer/stage/execute malware.
- Does NOT consume any official ransomware run slot.

Purpose
-------
Lock the exact qualification sequence:
  ranks 1..10 = PRIMARY qualification order
  ranks 11..19 = RESERVE promotion order

The schedule cannot be re-ranked after outcomes are observed.
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

FREEZE_ROOT = (
    ROOT
    / r"01_SHARED\sample_selection"
    / "UBUNTU_MAXIMAL_POOL_20261110_V10_TRULY_FRESH"
    / "FROZEN_SELECTION_20261110"
)

STATIC_AUDIT_ROOT = (
    ROOT
    / r"01_SHARED\sample_selection"
    / "UBUNTU_ZERO_SLOT_STATIC_READINESS_20261110"
)

OUTPUT_ROOT = (
    ROOT
    / r"01_SHARED\qualification"
    / "UBUNTU_V10_ZERO_SLOT_QUALIFICATION_20261110"
)

MANIFEST = FREEZE_ROOT / "UBUNTU_V10_FROZEN_SELECTION_MANIFEST.csv"
LEDGER = FREEZE_ROOT / "UBUNTU_V10_ZERO_SLOT_PREFLIGHT_LEDGER.csv"
CONTRACT = FREEZE_ROOT / "UBUNTU_V10_PREFLIGHT_CONTRACT.json"
FREEZE_RECEIPT = FREEZE_ROOT / "FREEZE_RECEIPT.json"
STATIC_AUDIT = STATIC_AUDIT_ROOT / "UBUNTU_ZERO_SLOT_STATIC_READINESS.json"

EXPECTED_POOL = 19
EXPECTED_PRIMARY = 10
EXPECTED_RESERVE = 9


def read_csv(path: Path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict]):
    fields = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)

    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require(condition: bool, message: str):
    if not condition:
        raise RuntimeError(message)


def main():
    required = [
        MANIFEST,
        LEDGER,
        CONTRACT,
        FREEZE_RECEIPT,
        STATIC_AUDIT,
    ]
    for path in required:
        require(path.is_file(), f"Required artifact missing: {path}")

    require(not OUTPUT_ROOT.exists(),
            f"Qualification schedule already exists; refusing overwrite: {OUTPUT_ROOT}")

    manifest = read_csv(MANIFEST)
    ledger = read_csv(LEDGER)
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    freeze_receipt = json.loads(FREEZE_RECEIPT.read_text(encoding="utf-8"))
    static_audit = json.loads(STATIC_AUDIT.read_text(encoding="utf-8"))

    require(len(manifest) == EXPECTED_POOL,
            f"Expected {EXPECTED_POOL} frozen rows; found {len(manifest)}")
    require(len(ledger) == EXPECTED_POOL,
            f"Expected {EXPECTED_POOL} ledger rows; found {len(ledger)}")

    require(freeze_receipt.get("status") == "PASS_FROZEN",
            "Frozen selection receipt is not PASS_FROZEN.")
    require(static_audit.get("status") == "PASS_STATIC_READINESS",
            "Static readiness audit is not PASS_STATIC_READINESS.")

    primary = [r for r in manifest if r.get("role") == "PRIMARY"]
    reserve = [r for r in manifest if r.get("role") == "RESERVE"]

    require(len(primary) == EXPECTED_PRIMARY,
            f"Expected {EXPECTED_PRIMARY} PRIMARY rows; found {len(primary)}")
    require(len(reserve) == EXPECTED_RESERVE,
            f"Expected {EXPECTED_RESERVE} RESERVE rows; found {len(reserve)}")

    ranks = [int(r["frozen_rank"]) for r in manifest]
    require(ranks == list(range(1, EXPECTED_POOL + 1)),
            "Frozen ranks are not exactly contiguous 1..19.")

    OUTPUT_ROOT.mkdir(parents=True)
    (OUTPUT_ROOT / "evidence_index").mkdir()
    (OUTPUT_ROOT / "receipts").mkdir()

    schedule = []
    for row in manifest:
        rank = int(row["frozen_rank"])
        schedule.append({
            "qualification_order": rank,
            "role_at_freeze": row["role"],
            "family": row["family"],
            "sha256": row["sha256"],
            "official_run_slot_consumed": "FALSE",
            "qualification_state": "PENDING",
            "static_platform_identity": "PENDING",
            "telemetry_start": "PENDING",
            "process_launch": "PENDING",
            "meaningful_workload_observed": "PENDING",
            "modified_canary_count": "",
            "total_canary_count": "",
            "actual_execution_seconds": "",
            "termination_mode": "",
            "exit_code": "",
            "telemetry_finalize": "PENDING",
            "evidence_package": "PENDING",
            "snapshot_recovery": "PENDING",
            "workload_verdict": "PENDING",
            "qualification_decision": "PENDING",
            "promotion_status": (
                "PRIMARY_TO_QUALIFY"
                if rank <= EXPECTED_PRIMARY
                else "RESERVE_WAITING"
            ),
            "decision_reason": "",
            "evidence_receipt_relpath": (
                f"receipts/Q{rank:02d}_{row['family'].replace('/', '_')}_QUALIFICATION_RECEIPT.json"
            ),
        })

    write_csv(
        OUTPUT_ROOT / "UBUNTU_V10_ZERO_SLOT_QUALIFICATION_SCHEDULE.csv",
        schedule,
    )

    # Freeze a machine-readable rule set.
    qualification_rules = {
        "schema_version": "1.0",
        "status": "FROZEN_QUALIFICATION_SCHEDULE",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "pool_size": EXPECTED_POOL,
        "primary_count": EXPECTED_PRIMARY,
        "reserve_count": EXPECTED_RESERVE,
        "qualification_sequence": "strict frozen_rank ascending",
        "re_rank_after_outcome_allowed": False,
        "official_run_slot_consumed": False,
        "maximum_observation_seconds": 60,
        "controller_acceptance_band_if_still_running": "60-65 seconds",
        "watchdog_seconds": 90,
        "post_exit_telemetry_tail_seconds": 10,
        "natural_exit_before_60_allowed": True,
        "natural_exit_acceptance_condition": (
            "Genuine intended ransomware workload must be observed; "
            "do not restart merely to fill the 60-second window."
        ),
        "workload_pass_requires": [
            "frozen SHA-256 identity matches",
            "Ubuntu/platform compatibility confirmed",
            "telemetry starts",
            "process launches",
            "meaningful intended canary modification/encryption observed",
            "telemetry finalizes",
            "evidence package verifies",
            "snapshot recovery verifies",
        ],
        "workload_fail_examples": [
            "immediate/error exit without meaningful workload",
            "password/usage/configuration gate prevents intended workload",
            "platform incompatibility",
            "zero intended canary modification",
        ],
        "promotion_rule": (
            "If any PRIMARY fails objectively, promote the lowest-ranked "
            "remaining RESERVE. Continue in frozen order until 10 qualified "
            "families are obtained or all 19 are exhausted."
        ),
        "no_post_hoc_hand_picking": True,
        "malware_downloaded_by_this_step": False,
        "malware_executed_by_this_step": False,
    }

    (OUTPUT_ROOT / "QUALIFICATION_RULES.json").write_text(
        json.dumps(qualification_rules, indent=2),
        encoding="utf-8",
    )

    evidence_schema = {
        "schema_version": "1.0",
        "required_per_qualification_receipt": [
            "qualification_order",
            "family",
            "sha256",
            "attempt_timestamp_utc",
            "official_run_slot_consumed",
            "static_platform_identity",
            "telemetry_start",
            "process_launch",
            "meaningful_workload_observed",
            "modified_canary_count",
            "total_canary_count",
            "actual_execution_seconds",
            "termination_mode",
            "exit_code",
            "exit_code_source",
            "telemetry_finalize",
            "evidence_package_sha256",
            "snapshot_recovery",
            "workload_verdict",
            "qualification_decision",
            "decision_reason",
        ],
    }

    (OUTPUT_ROOT / "QUALIFICATION_RECEIPT_SCHEMA.json").write_text(
        json.dumps(evidence_schema, indent=2),
        encoding="utf-8",
    )

    source_hashes = {
        str(path.relative_to(ROOT)): sha256_file(path)
        for path in required
    }

    receipt = {
        "status": "PASS_SCHEDULE_FROZEN",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_artifact_sha256": source_hashes,
        "qualification_rows": len(schedule),
        "primary_rows": len(primary),
        "reserve_rows": len(reserve),
        "static_readiness_status": static_audit.get("status"),
        "freeze_status": freeze_receipt.get("status"),
        "malware_binaries_read": False,
        "malware_downloaded": False,
        "malware_transferred": False,
        "malware_executed": False,
    }

    (OUTPUT_ROOT / "QUALIFICATION_SCHEDULE_FREEZE_RECEIPT.json").write_text(
        json.dumps(receipt, indent=2),
        encoding="utf-8",
    )

    # Hash all output artifacts.
    checksums = []
    for p in sorted(
        x for x in OUTPUT_ROOT.rglob("*")
        if x.is_file() and x.name != "SHA256SUMS.txt"
    ):
        checksums.append(f"{sha256_file(p)} *{p.relative_to(OUTPUT_ROOT)}")

    (OUTPUT_ROOT / "SHA256SUMS.txt").write_text(
        "\n".join(checksums) + "\n",
        encoding="ascii",
    )

    print("UBUNTU V10 ZERO-SLOT QUALIFICATION SCHEDULE: PASS")
    print(f"Frozen qualification rows: {len(schedule)}")
    print(f"PRIMARY first: {len(primary)}")
    print(f"RESERVE in fixed promotion order: {len(reserve)}")
    print("Re-ranking after outcomes: NOT ALLOWED")
    print("Official run slots consumed: 0")
    print("No malware was downloaded, transferred, or executed.")
    print("Qualification root:", OUTPUT_ROOT)


if __name__ == "__main__":
    main()
