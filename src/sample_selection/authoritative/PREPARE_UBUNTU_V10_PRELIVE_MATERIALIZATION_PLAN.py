#!/usr/bin/env python3
r"""
Prepare a SAFE pre-live materialization/storage plan for the frozen Ubuntu V10 pool.

This script:
- Reads the frozen V10 selection manifest only.
- Creates a deterministic materialization plan.
- Computes expected storage from metadata file sizes.
- Defines guest target paths and a fresh post-materialization snapshot name.
- Does NOT download malware.
- Does NOT transfer malware.
- Does NOT execute malware.
- Does NOT modify VMware snapshots.

Outputs:
- UBUNTU_V10_MATERIALIZATION_PLAN.csv
- UBUNTU_V10_STORAGE_AND_SNAPSHOT_PLAN.json
"""

from __future__ import annotations
import csv
import json
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

MANIFEST = FREEZE_ROOT / "UBUNTU_V10_FROZEN_SELECTION_MANIFEST.csv"

OUT_ROOT = (
    ROOT
    / r"01_SHARED\sample_selection"
    / "UBUNTU_V10_PRELIVE_MATERIALIZATION_PLAN_20261110"
)

SNAPSHOT_NAME = "P5G_V10_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261110"
GUEST_BASE = "/opt/RansomLab/MalwareStaging/P5G/V10/Samples"


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


def main():
    if not MANIFEST.is_file():
        raise RuntimeError(f"Frozen manifest missing: {MANIFEST}")

    rows = read_csv(MANIFEST)

    if len(rows) != 19:
        raise RuntimeError(f"Expected 19 frozen rows; found {len(rows)}")

    OUT_ROOT.mkdir(parents=True, exist_ok=True)

    plan = []
    total_bytes = 0

    for row in rows:
        rank = int(row["frozen_rank"])
        family = row["family"].strip()
        sha = row["sha256"].strip().lower()
        role = row["role"].strip()
        size = int(row.get("file_size_bytes") or 0)

        total_bytes += size

        plan.append({
            "frozen_rank": rank,
            "role": role,
            "family": family,
            "sha256": sha,
            "expected_file_size_bytes": size,
            "guest_target_path": f"{GUEST_BASE}/{sha}.sample",
            "archive_status": "NOT_ACQUIRED_BY_THIS_SCRIPT",
            "materialization_status": "PENDING",
            "sha256_verify_after_materialization": "REQUIRED",
            "execution_authorized": "FALSE",
        })

    write_csv(
        OUT_ROOT / "UBUNTU_V10_MATERIALIZATION_PLAN.csv",
        plan,
    )

    plan_json = {
        "schema_version": "1.0",
        "status": "PRELIVE_PLAN_READY",
        "frozen_sample_count": len(plan),
        "primary_count": sum(1 for x in plan if x["role"] == "PRIMARY"),
        "reserve_count": sum(1 for x in plan if x["role"] == "RESERVE"),
        "expected_total_raw_sample_bytes": total_bytes,
        "expected_total_raw_sample_mib": round(total_bytes / (1024 * 1024), 2),
        "guest_materialization_root": GUEST_BASE,
        "recommended_snapshot_name": SNAPSHOT_NAME,
        "storage_minimization_rules": [
            "Store only one copy of each raw sample in the guest.",
            "Do not keep duplicate extracted copies.",
            "Keep acquisition archives outside the VM.",
            "Verify SHA-256 immediately after materialization.",
            "Take one post-materialization/pre-execution snapshot only after all required hashes verify.",
            "Do not execute any sample before the snapshot is successfully created and recorded.",
        ],
        "safety_state": {
            "malware_downloaded_by_this_step": False,
            "malware_transferred_by_this_step": False,
            "malware_executed_by_this_step": False,
            "snapshot_modified_by_this_step": False,
        },
    }

    (OUT_ROOT / "UBUNTU_V10_STORAGE_AND_SNAPSHOT_PLAN.json").write_text(
        json.dumps(plan_json, indent=2),
        encoding="utf-8",
    )

    print("UBUNTU V10 PRE-LIVE MATERIALIZATION PLAN: PASS")
    print(f"Frozen samples: {len(plan)}")
    print(f"Expected raw sample storage: {plan_json['expected_total_raw_sample_mib']} MiB")
    print(f"Guest target root: {GUEST_BASE}")
    print(f"Recommended snapshot: {SNAPSHOT_NAME}")
    print("No malware was downloaded, transferred, or executed.")
    print("Plan root:", OUT_ROOT)


if __name__ == "__main__":
    main()
