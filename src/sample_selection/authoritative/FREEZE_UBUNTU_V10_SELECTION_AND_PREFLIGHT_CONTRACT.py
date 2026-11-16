#!/usr/bin/env python3
r"""
Freeze the exact V10 Ubuntu ransomware metadata selection and zero-slot preflight contract.

NO malware bytes are downloaded, extracted, transferred, staged, or executed.

This script freezes:
- exact 19-family V10 resolved pool
- exact rank order
- exact 10 PROVISIONAL_PRIMARY + 9 RESERVE roles
- exact SHA-256 identities
- Windows-family exclusion set
- zero-fresh-candidate audit
- deterministic reserve-promotion rule
- zero-slot workload acceptance contract

It copies only metadata/evidence files and creates hashes/receipts.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path


CAMPAIGN_ROOT = Path(
    r"C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs"
)

V10_ROOT = CAMPAIGN_ROOT / (
    r"01_SHARED\sample_selection\UBUNTU_MAXIMAL_POOL_20261110_V10_TRULY_FRESH"
)

FREEZE_ROOT = V10_ROOT / "FROZEN_SELECTION_20261110"

POOL_CSV = V10_ROOT / "UBUNTU_MAXIMAL_TRULY_FRESH_RESOLVED_POOL.csv"
PRIMARY_CSV = V10_ROOT / "UBUNTU_PROVISIONAL_PRIMARY10.csv"
RESERVE_CSV = V10_ROOT / "UBUNTU_RESERVE_POOL.csv"
WINDOWS_EXCL_CSV = V10_ROOT / "WINDOWS_FAMILY_EXCLUSION_SET.csv"
ZERO_CSV = V10_ROOT / "UBUNTU_ZERO_FRESH_CANDIDATE_FAMILIES.csv"
RECEIPT_JSON = V10_ROOT / "SELECTION_RECEIPT.json"

EXPECTED_PRIMARY_ORDER = [
    "INC/Lynx",
    "Conti",
    "Babuk",
    "BlackCat/ALPHV",
    "Qilin/Agenda",
    "HelloKitty",
    "AvosLocker",
    "REvil",
    "LockBit",
    "Hive",
]

EXPECTED_RESERVE_ORDER = [
    "BlackMatter",
    "Interlock",
    "BlackBasta",
    "MarioLocker",
    "RansomEXX",
    "Trigona",
    "BrainCipher",
    "IceFire",
    "BlackSuit/Royal",
]

EXPECTED_ZERO_FRESH = {
    "Buhti",
    "Hunters International",
    "Monti",
}

EXPECTED_WINDOWS_FAMILY_COUNT = 10
EXPECTED_RESOLVED_COUNT = 19
EXPECTED_PRIMARY_COUNT = 10
EXPECTED_RESERVE_COUNT = 9


def read_csv(path: Path) -> list[dict]:
    if not path.is_file():
        raise RuntimeError(f"Required file missing: {path}")

    with path.open(
        "r",
        encoding="utf-8-sig",
        errors="strict",
        newline="",
    ) as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict], fields: list[str] | None = None):
    path.parent.mkdir(parents=True, exist_ok=True)

    if fields is None:
        fields = []
        for row in rows:
            for key in row:
                if key not in fields:
                    fields.append(key)

    with path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def norm_family(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


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
        POOL_CSV,
        PRIMARY_CSV,
        RESERVE_CSV,
        WINDOWS_EXCL_CSV,
        ZERO_CSV,
        RECEIPT_JSON,
    ]

    for path in required:
        require(path.is_file(), f"Required V10 artifact missing: {path}")

    pool = read_csv(POOL_CSV)
    primary = read_csv(PRIMARY_CSV)
    reserve = read_csv(RESERVE_CSV)
    windows = read_csv(WINDOWS_EXCL_CSV)
    zero = read_csv(ZERO_CSV)

    receipt = json.loads(RECEIPT_JSON.read_text(encoding="utf-8"))

    # ----- Structural verification -----

    require(
        len(pool) == EXPECTED_RESOLVED_COUNT,
        f"Expected {EXPECTED_RESOLVED_COUNT} V10 resolved rows; found {len(pool)}."
    )

    require(
        len(primary) == EXPECTED_PRIMARY_COUNT,
        f"Expected {EXPECTED_PRIMARY_COUNT} primary rows; found {len(primary)}."
    )

    require(
        len(reserve) == EXPECTED_RESERVE_COUNT,
        f"Expected {EXPECTED_RESERVE_COUNT} reserve rows; found {len(reserve)}."
    )

    require(
        len(windows) == EXPECTED_WINDOWS_FAMILY_COUNT,
        f"Expected {EXPECTED_WINDOWS_FAMILY_COUNT} Windows exclusions; found {len(windows)}."
    )

    pool_families = [row["family"].strip() for row in pool]
    pool_hashes = [row["sha256"].strip().lower() for row in pool]

    require(
        len(set(map(norm_family, pool_families))) == len(pool_families),
        "Duplicate family detected in V10 resolved pool."
    )

    require(
        len(set(pool_hashes)) == len(pool_hashes),
        "Duplicate SHA-256 detected in V10 resolved pool."
    )

    require(
        all(re.fullmatch(r"[a-f0-9]{64}", sha) for sha in pool_hashes),
        "One or more V10 pool SHA-256 values are malformed."
    )

    # Verify frozen rank sequence is complete and contiguous.
    ranks = [int(row["final_pool_rank"]) for row in pool]
    require(
        ranks == list(range(1, EXPECTED_RESOLVED_COUNT + 1)),
        f"V10 final_pool_rank is not exactly 1..{EXPECTED_RESOLVED_COUNT}."
    )

    # Exact primary/reserve order from the completed V10 run.
    actual_primary = [row["family"].strip() for row in primary]
    actual_reserve = [row["family"].strip() for row in reserve]

    require(
        actual_primary == EXPECTED_PRIMARY_ORDER,
        "Primary order differs from the completed V10 result. Refusing to freeze."
    )

    require(
        actual_reserve == EXPECTED_RESERVE_ORDER,
        "Reserve order differs from the completed V10 result. Refusing to freeze."
    )

    zero_families = {row["family"].strip() for row in zero}
    require(
        zero_families == EXPECTED_ZERO_FRESH,
        f"Expected zero-fresh set {sorted(EXPECTED_ZERO_FRESH)}, "
        f"found {sorted(zero_families)}."
    )

    windows_norm = {
        norm_family(row.get("windows_family", ""))
        for row in windows
        if row.get("windows_family")
    }

    overlaps = [
        fam for fam in pool_families
        if norm_family(fam) in windows_norm
    ]

    require(
        not overlaps,
        f"Cross-OS family overlap detected: {overlaps}"
    )

    require(
        receipt.get("malware_bytes_downloaded") is False,
        "V10 receipt does not confirm metadata-only selection."
    )

    require(
        receipt.get("malware_executed") is False,
        "V10 receipt does not confirm no execution."
    )

    # ----- Build frozen contract -----

    if FREEZE_ROOT.exists():
        raise RuntimeError(
            f"Freeze destination already exists; refusing overwrite: {FREEZE_ROOT}"
        )

    FREEZE_ROOT.mkdir(parents=True)

    source_copy_dir = FREEZE_ROOT / "source_v10_artifacts"
    source_copy_dir.mkdir()

    for path in required:
        shutil.copy2(path, source_copy_dir / path.name)

    frozen_manifest = []

    for row in pool:
        rank = int(row["final_pool_rank"])

        frozen_manifest.append({
            "frozen_rank": rank,
            "role": (
                "PRIMARY"
                if rank <= EXPECTED_PRIMARY_COUNT
                else "RESERVE"
            ),
            "family": row["family"],
            "sha256": row["sha256"].lower(),
            "candidate_count_at_freeze": row.get("candidate_count", ""),
            "first_seen_utc": row.get("first_seen_utc", ""),
            "file_name": row.get("file_name", ""),
            "file_size_bytes": row.get("file_size_bytes", ""),
            "mb_signature": row.get("mb_signature", ""),
            "mb_file_arch": row.get("mb_file_arch", ""),
            "vt_type_description": row.get("vt_type_description", ""),
            "vt_malicious_detections": row.get("vt_malicious_detections", ""),
            "cross_os_family_overlap": "FALSE",
            "previous_campaign_hash_reuse": "FALSE",
            "selection_status": "FROZEN_METADATA_ELIGIBLE",
            "workload_status": "NOT_YET_PREFLIGHTED",
        })

    write_csv(
        FREEZE_ROOT / "UBUNTU_V10_FROZEN_SELECTION_MANIFEST.csv",
        frozen_manifest,
    )

    # One row per family for subsequent zero-slot qualification.
    ledger = []

    for row in frozen_manifest:
        ledger.append({
            "frozen_rank": row["frozen_rank"],
            "role_at_freeze": row["role"],
            "family": row["family"],
            "sha256": row["sha256"],
            "preflight_attempted": "FALSE",
            "platform_static_verdict": "PENDING",
            "telemetry_start_verdict": "PENDING",
            "process_launch_verdict": "PENDING",
            "meaningful_canary_modification": "PENDING",
            "modified_canary_count": "",
            "total_canary_count": "",
            "actual_execution_seconds": "",
            "termination_mode": "",
            "exit_code": "",
            "exit_code_source": "",
            "telemetry_finalize_verdict": "PENDING",
            "evidence_package_verdict": "PENDING",
            "snapshot_recovery_verdict": "PENDING",
            "workload_verdict": "PENDING",
            "qualification_decision": "PENDING",
            "decision_reason": "",
            "promotion_action": "",
        })

    write_csv(
        FREEZE_ROOT / "UBUNTU_V10_ZERO_SLOT_PREFLIGHT_LEDGER.csv",
        ledger,
    )

    contract = {
        "schema_version": "1.0",
        "contract_name": "Ubuntu V10 Frozen Selection and Zero-Slot Qualification Contract",
        "freeze_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "selection_source": str(V10_ROOT),
        "resolved_family_count": EXPECTED_RESOLVED_COUNT,
        "primary_count": EXPECTED_PRIMARY_COUNT,
        "reserve_count": EXPECTED_RESERVE_COUNT,
        "zero_fresh_candidate_families": sorted(EXPECTED_ZERO_FRESH),
        "cross_os_family_leakage_rule": (
            "No Ubuntu family may match any frozen Windows ransomware family."
        ),
        "fresh_hash_rule": (
            "No selected Ubuntu SHA-256 may have appeared in the prior frozen "
            "ransomware campaign manifest."
        ),
        "selection_order_rule": (
            "V10 family candidate-count ranking is frozen. No re-ranking after "
            "workload outcomes are observed."
        ),
        "zero_slot_preflight": {
            "official_run_slot_consumed": False,
            "maximum_observation_seconds": 60,
            "normal_controller_acceptance_band_seconds": "60-65 only when process remains running",
            "watchdog_seconds": 90,
            "post_exit_telemetry_tail_seconds": 10,
            "natural_exit_before_60_seconds_allowed": True,
            "natural_exit_condition": (
                "Allowed only when genuine intended ransomware behavior is observed. "
                "Do not restart a successful sample merely to fill the 60-second window."
            ),
            "workload_pass_requires": [
                "sample/platform identity matches frozen SHA-256 and Ubuntu-compatible target",
                "telemetry starts successfully",
                "sample process launches under the frozen runner",
                "meaningful intended canary modification/encryption is observed",
                "telemetry finalizes successfully",
                "evidence package is complete and hash-verifiable",
                "VM recovery/revert completes successfully",
            ],
            "workload_fail_examples": [
                "immediate/error exit with no meaningful canary modification",
                "usage/password/configuration gate prevents intended workload",
                "platform incompatibility",
                "zero intended canary modification despite nominal process success",
            ],
        },
        "promotion_rule": (
            "Evaluate PRIMARY ranks 1-10 under the same frozen zero-slot contract. "
            "If a PRIMARY objectively fails qualification, promote the lowest-ranked "
            "remaining RESERVE in frozen order. Continue until 10 qualified families "
            "are obtained or the frozen pool is exhausted. No post-hoc re-query or hand-picking."
        ),
        "malware_downloaded_by_this_freeze_step": False,
        "malware_executed_by_this_freeze_step": False,
    }

    (FREEZE_ROOT / "UBUNTU_V10_PREFLIGHT_CONTRACT.json").write_text(
        json.dumps(contract, indent=2),
        encoding="utf-8",
    )

    # Freeze receipt with source-file hashes.
    source_hashes = {
        path.name: sha256_file(path)
        for path in required
    }

    freeze_receipt = {
        "status": "PASS_FROZEN",
        "freeze_root": str(FREEZE_ROOT),
        "source_v10_root": str(V10_ROOT),
        "source_artifact_sha256": source_hashes,
        "verified_resolved_count": len(pool),
        "verified_primary_count": len(primary),
        "verified_reserve_count": len(reserve),
        "verified_windows_exclusion_count": len(windows),
        "verified_zero_fresh_families": sorted(zero_families),
        "verified_cross_os_family_overlap_count": len(overlaps),
        "malware_binaries_read": False,
        "malware_downloaded": False,
        "malware_executed": False,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    (FREEZE_ROOT / "FREEZE_RECEIPT.json").write_text(
        json.dumps(freeze_receipt, indent=2),
        encoding="utf-8",
    )

    # Hash every frozen artifact except the checksum file itself.
    checksum_lines = []

    for p in sorted(
        x for x in FREEZE_ROOT.rglob("*")
        if x.is_file() and x.name != "SHA256SUMS.txt"
    ):
        checksum_lines.append(
            f"{sha256_file(p)} *{p.relative_to(FREEZE_ROOT)}"
        )

    (FREEZE_ROOT / "SHA256SUMS.txt").write_text(
        "\n".join(checksum_lines) + "\n",
        encoding="ascii",
    )

    print("UBUNTU V10 SELECTION FREEZE: PASS")
    print(f"Frozen resolved pool: {len(pool)}")
    print(f"Frozen PRIMARY: {len(primary)}")
    print(f"Frozen RESERVE: {len(reserve)}")
    print("Cross-OS family overlap: 0")
    print(
        "Zero-fresh candidates:",
        ", ".join(sorted(zero_families)),
    )
    print("No malware binaries were read, downloaded, or executed.")
    print("Freeze root:", FREEZE_ROOT)


if __name__ == "__main__":
    main()
