#!/usr/bin/env python3
r"""
STATIC Ubuntu zero-slot preflight readiness audit.

SAFE SCOPE
----------
- Reads metadata, manifests, scripts, receipts, and checksums only.
- Does NOT download malware.
- Does NOT read malware binaries.
- Does NOT start VMware.
- Does NOT transfer/stage malware.
- Does NOT execute ransomware.
- Does NOT change snapshots.

Also creates a provisional script-retention ledger so the final Q1/reproducibility
bundle keeps only successful, non-superseded scripts plus any explicitly retained
supporting audit script.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(
    r"C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs"
)

SAMPLE_SELECTION = ROOT / r"01_SHARED\sample_selection"
SCRIPT_DIR = ROOT / r"01_SHARED\scripts\host\sample_selection"

FREEZE_ROOT = (
    SAMPLE_SELECTION
    / "UBUNTU_MAXIMAL_POOL_20261110_V10_TRULY_FRESH"
    / "FROZEN_SELECTION_20261110"
)

AUDIT_ROOT = SAMPLE_SELECTION / "UBUNTU_ZERO_SLOT_STATIC_READINESS_20261110"

FROZEN_MANIFEST = FREEZE_ROOT / "UBUNTU_V10_FROZEN_SELECTION_MANIFEST.csv"
PREFLIGHT_LEDGER = FREEZE_ROOT / "UBUNTU_V10_ZERO_SLOT_PREFLIGHT_LEDGER.csv"
PREFLIGHT_CONTRACT = FREEZE_ROOT / "UBUNTU_V10_PREFLIGHT_CONTRACT.json"
FREEZE_RECEIPT = FREEZE_ROOT / "FREEZE_RECEIPT.json"
FREEZE_SHA = FREEZE_ROOT / "SHA256SUMS.txt"

EXPECTED_SNAPSHOT = "P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013"

TEXT_SUFFIXES = {
    ".ps1", ".py", ".sh", ".json", ".csv", ".md", ".txt",
    ".yaml", ".yml", ".toml", ".bt",
}

MAX_SCAN_BYTES = 5 * 1024 * 1024

# Final-release decision is explicit and conservative.
# PASS does not automatically mean "release": superseded scripts stay out.
SCRIPT_RETENTION_POLICY = [
    {
        "filename": "DIAGNOSE_V7_MALWAREBAZAAR_ELIGIBILITY.py",
        "observed_status": "PASS",
        "release_decision": "RETAIN_SUPPORTING_AUDIT",
        "reason": "Successful diagnostic that established MalwareBazaar architecture-metadata incompleteness.",
    },
    {
        "filename": "SELECT_UBUNTU_FRESH15_METADATA_ONLY_V8_VT_RESOLVED.py",
        "observed_status": "PASS",
        "release_decision": "DO_NOT_RELEASE_SUPERSEDED",
        "reason": "Successful intermediate selector, superseded by V10 freshness and leakage rules.",
    },
    {
        "filename": "VERIFY_WINDOWS_RANSOMWARE_IDENTITIES_READONLY.py",
        "observed_status": "REVIEW_REQUIRED",
        "release_decision": "DO_NOT_RELEASE",
        "reason": "Produced duplicate/incomplete rows and REVIEW_REQUIRED; Windows identities were later verified from authoritative records.",
    },
    {
        "filename": "BUILD_UBUNTU_MAXIMAL_POOL_V9.py",
        "observed_status": "COMPLETE_BUT_METHOD_SUPERSEDED",
        "release_decision": "DO_NOT_RELEASE_SUPERSEDED",
        "reason": "Allowed old Ubuntu hashes back into the pool; replaced by V10.",
    },
    {
        "filename": "BUILD_UBUNTU_MAXIMAL_POOL_V10_TRULY_FRESH.py",
        "observed_status": "PASS",
        "release_decision": "RETAIN_FINAL",
        "reason": "Final truly-fresh, cross-OS leakage-safe metadata selector.",
    },
    {
        "filename": "FREEZE_UBUNTU_V10_SELECTION_AND_PREFLIGHT_CONTRACT.py",
        "observed_status": "PASS",
        "release_decision": "RETAIN_FINAL",
        "reason": "Successfully froze exact V10 ranks, identities, promotion rule, and zero-slot contract.",
    },
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8-sig", errors="strict", newline="") as f:
        return list(csv.DictReader(f))


def add_check(checks, name, passed, detail):
    checks.append({
        "check": name,
        "status": "PASS" if passed else "FAIL",
        "detail": detail,
    })


def verify_freeze_checksums():
    if not FREEZE_SHA.is_file():
        return False, ["SHA256SUMS.txt missing"]

    failures = []
    lines = FREEZE_SHA.read_text(encoding="ascii", errors="strict").splitlines()

    for line in lines:
        if not line.strip():
            continue
        m = re.match(r"^([a-f0-9]{64}) \*(.+)$", line.strip())
        if not m:
            failures.append(f"Malformed checksum line: {line}")
            continue

        expected, rel = m.groups()
        path = FREEZE_ROOT / rel
        if not path.is_file():
            failures.append(f"Missing: {rel}")
            continue

        actual = sha256_file(path)
        if actual != expected:
            failures.append(f"Hash mismatch: {rel}")

    return not failures, failures


def scan_text_references(pattern: str):
    regex = re.compile(pattern, re.I)
    hits = []

    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue

        try:
            if path.stat().st_size > MAX_SCAN_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        if regex.search(text):
            hits.append(str(path))

    return sorted(set(hits))


def write_csv(path: Path, rows: list[dict]):
    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fields = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)

    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def main():
    AUDIT_ROOT.mkdir(parents=True, exist_ok=True)
    checks = []

    required = [
        FROZEN_MANIFEST,
        PREFLIGHT_LEDGER,
        PREFLIGHT_CONTRACT,
        FREEZE_RECEIPT,
        FREEZE_SHA,
    ]

    missing = [str(p) for p in required if not p.is_file()]
    add_check(
        checks,
        "frozen_artifacts_present",
        not missing,
        "All required frozen artifacts present." if not missing else "; ".join(missing),
    )

    manifest_rows = []
    ledger_rows = []
    contract = {}
    receipt = {}

    if FROZEN_MANIFEST.is_file():
        manifest_rows = read_csv(FROZEN_MANIFEST)

        families = [r.get("family", "").strip() for r in manifest_rows]
        shas = [r.get("sha256", "").strip().lower() for r in manifest_rows]
        roles = [r.get("role", "").strip() for r in manifest_rows]

        add_check(
            checks,
            "resolved_family_count_19",
            len(manifest_rows) == 19,
            f"rows={len(manifest_rows)}",
        )
        add_check(
            checks,
            "primary_count_10",
            roles.count("PRIMARY") == 10,
            f"PRIMARY={roles.count('PRIMARY')}",
        )
        add_check(
            checks,
            "reserve_count_9",
            roles.count("RESERVE") == 9,
            f"RESERVE={roles.count('RESERVE')}",
        )
        add_check(
            checks,
            "unique_families_19",
            len(set(families)) == 19,
            f"unique_families={len(set(families))}",
        )
        add_check(
            checks,
            "unique_sha256_19",
            len(set(shas)) == 19 and all(re.fullmatch(r"[a-f0-9]{64}", s) for s in shas),
            f"unique_sha256={len(set(shas))}",
        )

    if PREFLIGHT_LEDGER.is_file():
        ledger_rows = read_csv(PREFLIGHT_LEDGER)
        add_check(
            checks,
            "preflight_ledger_matches_frozen_pool",
            len(ledger_rows) == 19,
            f"ledger_rows={len(ledger_rows)}",
        )

        untouched = all(
            str(r.get("preflight_attempted", "")).upper() == "FALSE"
            and str(r.get("workload_verdict", "")).upper() == "PENDING"
            for r in ledger_rows
        )
        add_check(
            checks,
            "zero_slot_ledger_not_yet_consumed",
            untouched,
            "All rows still unattempted/PENDING." if untouched else "One or more rows already changed.",
        )

    if PREFLIGHT_CONTRACT.is_file():
        contract = json.loads(PREFLIGHT_CONTRACT.read_text(encoding="utf-8"))
        z = contract.get("zero_slot_preflight", {})

        add_check(
            checks,
            "observation_window_60s",
            z.get("maximum_observation_seconds") == 60,
            f"maximum_observation_seconds={z.get('maximum_observation_seconds')}",
        )
        add_check(
            checks,
            "watchdog_90s",
            z.get("watchdog_seconds") == 90,
            f"watchdog_seconds={z.get('watchdog_seconds')}",
        )
        add_check(
            checks,
            "telemetry_tail_10s",
            z.get("post_exit_telemetry_tail_seconds") == 10,
            f"post_exit_telemetry_tail_seconds={z.get('post_exit_telemetry_tail_seconds')}",
        )
        add_check(
            checks,
            "official_slot_zero",
            z.get("official_run_slot_consumed") is False,
            f"official_run_slot_consumed={z.get('official_run_slot_consumed')}",
        )

    if FREEZE_RECEIPT.is_file():
        receipt = json.loads(FREEZE_RECEIPT.read_text(encoding="utf-8"))

        add_check(
            checks,
            "freeze_receipt_pass",
            receipt.get("status") == "PASS_FROZEN",
            f"status={receipt.get('status')}",
        )
        add_check(
            checks,
            "freeze_step_no_malware_activity",
            receipt.get("malware_downloaded") is False
            and receipt.get("malware_executed") is False
            and receipt.get("malware_binaries_read") is False,
            (
                f"read={receipt.get('malware_binaries_read')} "
                f"downloaded={receipt.get('malware_downloaded')} "
                f"executed={receipt.get('malware_executed')}"
            ),
        )

    checksum_ok, checksum_failures = verify_freeze_checksums()
    add_check(
        checks,
        "freeze_sha256s_verify",
        checksum_ok,
        "All frozen artifact hashes match." if checksum_ok else "; ".join(checksum_failures),
    )

    # Static references only. We do not invoke VMware or telemetry.
    snapshot_hits = scan_text_references(re.escape(EXPECTED_SNAPSHOT))
    bpf_hits = scan_text_references(r"\bbpftrace\b")
    auditd_hits = scan_text_references(r"\bauditd\b|\bauditctl\b")
    canary_hits = scan_text_references(r"canary_hashes\.txt")

    add_check(
        checks,
        "ubuntu_snapshot_name_documented",
        bool(snapshot_hits),
        f"references={len(snapshot_hits)}",
    )
    add_check(
        checks,
        "bpftrace_logic_present",
        bool(bpf_hits),
        f"references={len(bpf_hits)}",
    )
    add_check(
        checks,
        "auditd_logic_present",
        bool(auditd_hits),
        f"references={len(auditd_hits)}",
    )
    add_check(
        checks,
        "relocated_canary_hash_manifest_logic_present",
        bool(canary_hits),
        f"references={len(canary_hits)}",
    )

    overall = (
        "PASS_STATIC_READINESS"
        if all(c["status"] == "PASS" for c in checks)
        else "REVIEW_REQUIRED"
    )

    report = {
        "schema_version": "1.0",
        "status": overall,
        "scope": "STATIC_ONLY_NO_MALWARE_NO_VM_EXECUTION",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "freeze_root": str(FREEZE_ROOT),
        "expected_ubuntu_snapshot": EXPECTED_SNAPSHOT,
        "checks": checks,
        "reference_evidence": {
            "snapshot_name_files": snapshot_hits,
            "bpftrace_reference_files": bpf_hits,
            "auditd_reference_files": auditd_hits,
            "canary_hash_manifest_reference_files": canary_hits,
        },
        "next_phase_not_authorized_by_this_audit": [
            "malware acquisition",
            "malware transfer/materialization",
            "ransomware execution",
            "official ransomware run",
        ],
    }

    (AUDIT_ROOT / "UBUNTU_ZERO_SLOT_STATIC_READINESS.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )
    write_csv(
        AUDIT_ROOT / "UBUNTU_ZERO_SLOT_STATIC_READINESS_CHECKS.csv",
        checks,
    )

    # Provisional Q1 script-retention ledger.
    retention_rows = []

    for entry in SCRIPT_RETENTION_POLICY:
        path = SCRIPT_DIR / entry["filename"]
        row = dict(entry)
        row["path"] = str(path)
        row["file_present"] = path.is_file()
        row["sha256"] = sha256_file(path) if path.is_file() else ""
        retention_rows.append(row)

    write_csv(
        AUDIT_ROOT / "Q1_SCRIPT_RETENTION_LEDGER_PROVISIONAL.csv",
        retention_rows,
    )

    # Hash the audit outputs.
    checksum_lines = []
    for p in sorted(
        x for x in AUDIT_ROOT.rglob("*")
        if x.is_file() and x.name != "SHA256SUMS.txt"
    ):
        checksum_lines.append(f"{sha256_file(p)} *{p.relative_to(AUDIT_ROOT)}")

    (AUDIT_ROOT / "SHA256SUMS.txt").write_text(
        "\n".join(checksum_lines) + "\n",
        encoding="ascii",
    )

    print("UBUNTU ZERO-SLOT STATIC READINESS:", overall)
    for c in checks:
        print(f"{c['status']:4} | {c['check']} | {c['detail']}")
    print("")
    print("Q1 script-retention ledger created.")
    print("No malware was downloaded, staged, transferred, or executed.")
    print("Audit root:", AUDIT_ROOT)


if __name__ == "__main__":
    main()
