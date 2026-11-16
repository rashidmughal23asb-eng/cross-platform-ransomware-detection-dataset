#!/usr/bin/env python3
r"""
V10 — Build a truly fresh, cross-OS leakage-safe Ubuntu ransomware candidate pool.

NO malware bytes are downloaded, extracted, transferred, staged, or executed.

Corrections over V9
-------------------
1. Exclude ALL ransomware SHA-256 values previously used anywhere in the frozen
   ransomware campaign (Windows + Ubuntu), not only Windows hashes.
2. Exclude every Windows ransomware family from the Ubuntu family pool.
3. Preserve zero-candidate families in the audit instead of silently dropping them.
4. Reuse cached VirusTotal metadata from V9/V8 where available.

Ranking rule
------------
For remaining Ubuntu families:
  candidate_count DESC
  newest_candidate_first_seen DESC
  family ASC

Final metadata roles
--------------------
- First 10 resolved families: PROVISIONAL_PRIMARY
- Every remaining resolved family: RESERVE

These are metadata-stage roles only. Final acceptance still requires the frozen
zero-slot workload preflight. A sample that exits quickly without meaningful
ransomware workload is rejected and the next ranked reserve is promoted.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

import requests


CAMPAIGN_ROOT = Path(
    r"C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs"
)

VT_KEY_FILE = Path(r"C:\Users\Cyber-01\Desktop\VirusTotal.txt")

V7_ROOT = CAMPAIGN_ROOT / r"01_SHARED\sample_selection\UBUNTU_FRESH15_METADATA_20261110_V7_SIGNATURES"
V7_MB_RAW = V7_ROOT / "raw_api" / "malwarebazaar_signatures"

V9_ROOT = CAMPAIGN_ROOT / r"01_SHARED\sample_selection\UBUNTU_MAXIMAL_POOL_20261110_V9"
V8_ROOT = CAMPAIGN_ROOT / r"01_SHARED\sample_selection\UBUNTU_FRESH15_METADATA_20261110_V8_VT_RESOLVED"

OUTPUT_ROOT = CAMPAIGN_ROOT / r"01_SHARED\sample_selection\UBUNTU_MAXIMAL_POOL_20261110_V10_TRULY_FRESH"
VT_CACHE = OUTPUT_ROOT / "raw_api" / "virustotal"

PRIMARY_TARGET = 10
MAX_VT_CANDIDATES_PER_FAMILY = 10
VT_DELAY_SECONDS = 16
VT_URL = "https://www.virustotal.com/api/v3/files/{sha256}"

FAMILY_BY_INDEX = {
    1: "Akira",
    2: "AvosLocker",
    3: "Babuk",
    4: "BlackBasta",
    5: "BlackCat/ALPHV",
    6: "BlackMatter",
    7: "BlackSuit/Royal",
    8: "BrainCipher",
    9: "Buhti",
    10: "Conti",
    11: "Gunra",
    12: "HelloKitty",
    13: "Hive",
    14: "Hunters International",
    15: "IceFire",
    16: "INC/Lynx",
    17: "Interlock",
    18: "LockBit",
    19: "MarioLocker",
    20: "Monti",
    21: "Qilin/Agenda",
    22: "RansomEXX",
    23: "REvil",
    24: "Trigona",
}

ALIASES = {
    "blackcat": "blackcatalphv",
    "alphv": "blackcatalphv",
    "blackcatalphv": "blackcatalphv",
    "blackmatter": "blackmatter",
    "darkside": "blackmatter",
    "blacksuit": "blacksuitroyal",
    "royal": "blacksuitroyal",
    "blacksuitroyal": "blacksuitroyal",
    "inc": "inclynx",
    "lynx": "inclynx",
    "inclynx": "inclynx",
    "qilin": "qilinagenda",
    "agenda": "qilinagenda",
    "qilinagenda": "qilinagenda",
    "revil": "revil",
    "sodinokibi": "revil",
}

SHA_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "Ransomware-Thesis-Maximal-Pool-Selector/10.0"})


def norm_family(value: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "", (value or "").strip().lower())
    return ALIASES.get(s, s)


def read_secret(path: Path) -> str:
    if not path.is_file():
        raise RuntimeError(f"Secret file not found: {path}")
    raw = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        raise RuntimeError(f"Secret file empty: {path}")

    for line in raw.splitlines():
        s = line.strip()
        m = re.match(
            r"^(?:[A-Za-z0-9_. \-]*?(?:api|auth)[A-Za-z0-9_. \-]*?(?:key)?)?"
            r"\s*[:=]\s*([A-Za-z0-9_\-]{20,})\s*$",
            s,
            re.I,
        )
        if m:
            return m.group(1)

    if re.fullmatch(r"[A-Za-z0-9_\-]{20,}", raw):
        return raw

    raise RuntimeError(f"Could not safely parse API key from: {path}")


def parse_dt(value):
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S UTC",
        "%Y-%m-%dT%H:%M:%S%z",
    ):
        try:
            dt = datetime.strptime(str(value), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass

    return datetime.min.replace(tzinfo=timezone.utc)


def row_blob(row: dict) -> str:
    parts = []

    for key in (
        "signature",
        "file_name",
        "file_type",
        "file_format",
        "file_arch",
        "file_type_mime",
    ):
        value = row.get(key)
        if value is not None:
            parts.append(str(value))

    tags = row.get("tags") or []
    if isinstance(tags, list):
        parts.extend(str(x) for x in tags)
    else:
        parts.append(str(tags))

    return " ".join(parts).lower()


def is_elf(row: dict) -> bool:
    return (
        str(row.get("file_format") or "").lower() == "elf"
        or str(row.get("file_type") or "").lower() == "elf"
    )


def explicit_bad_platform(row: dict) -> bool:
    return bool(re.search(r"(esxi|vmware|vmfs|freebsd)", row_blob(row), re.I))


def load_v7_records():
    grouped = {idx: {} for idx in FAMILY_BY_INDEX}

    if not V7_MB_RAW.is_dir():
        raise RuntimeError(f"V7 raw MalwareBazaar folder not found: {V7_MB_RAW}")

    for p in sorted(V7_MB_RAW.glob("*.json")):
        m = re.match(r"^(\d+)_", p.name)
        if not m:
            continue

        idx = int(m.group(1))
        if idx not in grouped:
            continue

        try:
            obj = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except Exception as e:
            print(f"WARNING: could not parse {p.name}: {e}")
            continue

        for row in (obj.get("data") or []):
            sha = str(row.get("sha256_hash") or "").lower()
            if re.fullmatch(r"[a-f0-9]{64}", sha):
                grouped[idx][sha] = row

    return grouped


def authoritative_manifest_paths():
    paths = sorted(CAMPAIGN_ROOT.rglob("RANSOMWARE_40_RUN_MANIFEST.csv"))
    if not paths:
        raise RuntimeError("No RANSOMWARE_40_RUN_MANIFEST.csv found under campaign root.")
    return paths


def collect_all_previously_used_hashes(manifests):
    """
    Conservative freshness rule:
    every 64-hex SHA-256 appearing in an authoritative ransomware manifest
    is excluded from the new Ubuntu pool.
    """
    hashes = set()
    sources = []

    for p in manifests:
        try:
            text = p.read_text(encoding="utf-8-sig", errors="ignore")
            found = {x.lower() for x in SHA_RE.findall(text)}
            hashes.update(found)
            sources.append({
                "manifest": str(p),
                "sha256_values_found": len(found),
            })
        except Exception as e:
            sources.append({
                "manifest": str(p),
                "sha256_values_found": 0,
                "error": str(e),
            })

    if not hashes:
        raise RuntimeError(
            "Authoritative ransomware manifest(s) were found, but no SHA-256 values "
            "could be recovered. Refusing to weaken freshness rules."
        )

    return hashes, sources


def recover_windows_families(manifests):
    families = {}

    family_keys = {
        "family",
        "family_stratum",
        "familystratum",
        "ransomware_family",
        "provider_family",
        "providerfamily",
        "signature",
    }

    for p in manifests:
        try:
            with p.open(
                "r",
                encoding="utf-8-sig",
                errors="ignore",
                newline="",
            ) as f:
                for row in csv.DictReader(f):
                    normalized = {
                        re.sub(r"[^a-z0-9]+", "_", str(k).lower()).strip("_"):
                        str(v or "").strip()
                        for k, v in row.items()
                    }

                    run_id = normalized.get("run_id") or normalized.get("runid") or ""

                    blob = " ".join(normalized.values()).lower()
                    is_windows = (
                        run_id.lower().startswith("ran_win")
                        or run_id.lower().startswith("w-r-")
                        or ("windows" in blob and "ransomware" in blob)
                    )
                    if not is_windows:
                        continue

                    family = ""
                    for key in family_keys:
                        if normalized.get(key):
                            family = normalized[key]
                            break

                    if family:
                        families[norm_family(family)] = family

        except Exception:
            continue

    if len(families) != 10:
        raise RuntimeError(
            f"Expected exactly 10 Windows ransomware families from frozen manifests; "
            f"found {len(families)}. Refusing to guess."
        )

    return families


def request_vt(url: str, headers: dict, max_attempts=3):
    delays = [30, 60, 90]
    last_error = None

    for attempt in range(1, max_attempts + 1):
        try:
            response = SESSION.get(url, headers=headers, timeout=60)

            if response.status_code in (429, 500, 502, 503, 504):
                raise requests.HTTPError(
                    f"HTTP {response.status_code}: {response.text[:250]}",
                    response=response,
                )

            response.raise_for_status()
            return response

        except Exception as e:
            last_error = e

            if attempt >= max_attempts:
                break

            delay = delays[attempt - 1]
            print(
                f"WARNING: VT attempt {attempt}/{max_attempts} failed: {e}. "
                f"Retrying in {delay}s."
            )
            time.sleep(delay)

    raise RuntimeError(
        f"VT request failed after {max_attempts} attempts: {last_error}"
    )


def find_cached_vt(sha: str):
    candidates = [
        VT_CACHE / f"{sha}.json",
        V9_ROOT / "raw_api" / "virustotal" / f"{sha}.json",
        V8_ROOT / "raw_api" / "virustotal" / f"{sha}.json",
    ]

    for p in candidates:
        if p.is_file():
            return p

    return None


def get_vt_json(sha: str, headers: dict):
    local = VT_CACHE / f"{sha}.json"

    if local.is_file():
        return json.loads(local.read_text(encoding="utf-8")), "V10_CACHE"

    existing = find_cached_vt(sha)
    if existing is not None:
        obj = json.loads(existing.read_text(encoding="utf-8"))
        local.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(existing, local)
        return obj, f"REUSED:{existing.parent.parent.parent.name}"

    response = request_vt(VT_URL.format(sha256=sha), headers)
    obj = response.json()

    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text(
        json.dumps(obj, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    time.sleep(VT_DELAY_SECONDS)

    return obj, "LIVE"


def vt_flatten(attrs: dict) -> str:
    parts = []

    for key in (
        "type_description",
        "type_tag",
        "magic",
        "meaningful_name",
    ):
        value = attrs.get(key)
        if value is not None:
            parts.append(str(value))

    for key in ("type_tags", "tags", "names"):
        value = attrs.get(key) or []
        if isinstance(value, list):
            parts.extend(str(x) for x in value)
        else:
            parts.append(str(value))

    exif = attrs.get("exiftool") or {}
    if isinstance(exif, dict):
        for k, v in exif.items():
            parts.append(str(k))
            parts.append(str(v))

    return " ".join(parts).lower()


def vt_resolve(obj: dict):
    attrs = ((obj.get("data") or {}).get("attributes") or {})
    blob = vt_flatten(attrs)

    malicious = int(
        (attrs.get("last_analysis_stats") or {}).get("malicious") or 0
    )

    if re.search(r"(esxi|vmware|vmfs|freebsd)", blob, re.I):
        return False, "VT_PLATFORM_CONTRADICTION", attrs

    elf_positive = (
        str(attrs.get("type_tag") or "").lower() == "elf"
        or bool(re.search(r"\belf\b", blob, re.I))
    )

    if not elf_positive:
        return False, "VT_NOT_POSITIVELY_ELF", attrs

    x64_positive = bool(
        re.search(
            r"(x86[_\- ]?64|x86-64|amd64|advanced micro devices x86-64)",
            blob,
            re.I,
        )
    )

    if not x64_positive:
        if re.search(
            r"\b(arm|aarch64|mips|ppc|powerpc|sparc)\b",
            blob,
            re.I,
        ):
            return False, "VT_NON_X64_ARCH", attrs

        return False, "VT_ARCH_UNRESOLVED", attrs

    if malicious < 5:
        return False, f"VT_MALICIOUS_COUNT_LT_5({malicious})", attrs

    return True, "VT_ELF_X64_CONFIRMED", attrs


def vt_summary(attrs):
    return {
        "vt_type_description": str(attrs.get("type_description") or ""),
        "vt_type_tag": str(attrs.get("type_tag") or ""),
        "vt_magic": str(attrs.get("magic") or ""),
        "vt_tags": ";".join(str(x) for x in (attrs.get("tags") or [])),
        "vt_malicious_detections": int(
            (attrs.get("last_analysis_stats") or {}).get("malicious") or 0
        ),
    }


def write_csv(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)

    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fields = []

    for row in rows:
        for key in row:
            if not key.startswith("_") and key not in fields:
                fields.append(key)

    with path.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for row in rows:
            writer.writerow({
                k: v
                for k, v in row.items()
                if k in fields
            })


def hash_tree(root: Path):
    lines = []

    for p in sorted(
        x
        for x in root.rglob("*")
        if x.is_file() and x.name != "SHA256SUMS.txt"
    ):
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        lines.append(f"{digest} *{p.relative_to(root)}")

    (root / "SHA256SUMS.txt").write_text(
        "\n".join(lines) + "\n",
        encoding="ascii",
    )


def main():
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    VT_CACHE.mkdir(parents=True, exist_ok=True)

    manifests = authoritative_manifest_paths()

    old_hashes, manifest_sources = collect_all_previously_used_hashes(manifests)
    windows_families = recover_windows_families(manifests)
    grouped = load_v7_records()

    vt_key = read_secret(VT_KEY_FILE)
    vt_headers = {
        "x-apikey": vt_key,
        "Accept": "application/json",
    }

    print("V10 TRULY-FRESH UBUNTU POOL")
    print("No malware bytes will be downloaded, extracted, staged, or executed.")
    print("Previously-used ransomware hashes excluded:", len(old_hashes))
    print(
        "Windows family exclusions:",
        ", ".join(sorted(windows_families.values())),
    )

    write_csv(
        OUTPUT_ROOT / "WINDOWS_FAMILY_EXCLUSION_SET.csv",
        [
            {
                "windows_family": display,
                "normalized_family": nf,
            }
            for nf, display in sorted(
                windows_families.items(),
                key=lambda x: x[1].lower(),
            )
        ],
    )

    write_csv(
        OUTPUT_ROOT / "PREVIOUSLY_USED_RANSOMWARE_HASHES_EXCLUDED.csv",
        [
            {"sha256": sha}
            for sha in sorted(old_hashes)
        ],
    )

    family_rows = []
    zero_rows = []
    all_candidate_rows = []
    ranked_family_objects = []

    for idx in range(1, 25):
        family = FAMILY_BY_INDEX[idx]
        nf = norm_family(family)
        records = list(grouped[idx].values())

        if nf in windows_families:
            family_rows.append({
                "family_index": idx,
                "family": family,
                "status": "EXCLUDED_WINDOWS_FAMILY_OVERLAP",
                "candidate_count": 0,
                "newest_candidate_first_seen": "",
                "newest_candidate_sha256": "",
            })
            continue

        candidates = []

        for row in records:
            sha = str(row.get("sha256_hash") or "").lower()

            if not is_elf(row):
                continue

            if explicit_bad_platform(row):
                continue

            if sha in old_hashes:
                continue

            candidate = {
                "family_index": idx,
                "family": family,
                "sha256": sha,
                "first_seen_utc": str(row.get("first_seen") or ""),
                "_first_seen_sort": parse_dt(row.get("first_seen")),
                "file_name": str(row.get("file_name") or ""),
                "file_size_bytes": int(row.get("file_size") or 0),
                "mb_signature": str(row.get("signature") or ""),
                "mb_file_arch": str(row.get("file_arch") or ""),
                "mb_file_format": str(row.get("file_format") or ""),
                "mb_tags": ";".join(row.get("tags") or []),
            }

            candidates.append(candidate)

        candidates.sort(
            key=lambda x: (
                -x["_first_seen_sort"].timestamp(),
                x["sha256"],
            )
        )

        for order, candidate in enumerate(candidates, 1):
            out = {
                k: v
                for k, v in candidate.items()
                if not k.startswith("_")
            }
            out["within_family_rank"] = order
            all_candidate_rows.append(out)

        if not candidates:
            row = {
                "family_index": idx,
                "family": family,
                "status": "ZERO_FRESH_CANDIDATES",
                "candidate_count": 0,
                "newest_candidate_first_seen": "",
                "newest_candidate_sha256": "",
            }

            family_rows.append(row)
            zero_rows.append(row)
            continue

        family_obj = {
            "family_index": idx,
            "family": family,
            "candidate_count": len(candidates),
            "newest_candidate_first_seen": candidates[0]["first_seen_utc"],
            "newest_candidate_sha256": candidates[0]["sha256"],
            "_newest_sort": candidates[0]["_first_seen_sort"],
            "_candidates": candidates,
        }

        ranked_family_objects.append(family_obj)

    ranked_family_objects.sort(
        key=lambda x: (
            -x["candidate_count"],
            -x["_newest_sort"].timestamp(),
            x["family"].lower(),
        )
    )

    for rank, obj in enumerate(ranked_family_objects, 1):
        family_rows.append({
            "pool_rank": rank,
            "family_index": obj["family_index"],
            "family": obj["family"],
            "status": "ACTIVE_PRE_VT",
            "candidate_count": obj["candidate_count"],
            "newest_candidate_first_seen": obj["newest_candidate_first_seen"],
            "newest_candidate_sha256": obj["newest_candidate_sha256"],
        })

    write_csv(
        OUTPUT_ROOT / "UBUNTU_ALL_TRULY_FRESH_ELF_CANDIDATE_HASHES.csv",
        all_candidate_rows,
    )

    write_csv(
        OUTPUT_ROOT / "UBUNTU_FAMILY_CANDIDATE_COUNTS.csv",
        family_rows,
    )

    write_csv(
        OUTPUT_ROOT / "UBUNTU_ZERO_FRESH_CANDIDATE_FAMILIES.csv",
        zero_rows,
    )

    print(
        "Active family pool before VT:",
        len(ranked_family_objects),
    )

    print(
        "Zero-fresh-candidate families:",
        ", ".join(x["family"] for x in zero_rows) or "NONE",
    )

    print("Starting VT metadata resolution...")

    vt_audit = []
    resolved = []

    for pool_rank, fam in enumerate(ranked_family_objects, 1):
        print(
            f"[{pool_rank}/{len(ranked_family_objects)}] "
            f"{fam['family']}: candidate_count={fam['candidate_count']}"
        )

        chosen = None

        for candidate_order, candidate in enumerate(
            fam["_candidates"][:MAX_VT_CANDIDATES_PER_FAMILY],
            1,
        ):
            sha = candidate["sha256"]

            try:
                obj, source = get_vt_json(sha, vt_headers)
                ok, reason, attrs = vt_resolve(obj)
                summary = vt_summary(attrs)

                vt_audit.append({
                    "family_pool_rank": pool_rank,
                    "family": fam["family"],
                    "family_candidate_count": fam["candidate_count"],
                    "candidate_order": candidate_order,
                    "sha256": sha,
                    "first_seen_utc": candidate["first_seen_utc"],
                    "mb_file_arch": candidate["mb_file_arch"],
                    "mb_tags": candidate["mb_tags"],
                    "vt_source": source,
                    "verdict": "PASS" if ok else "REJECT",
                    "reason": reason,
                    **summary,
                })

                if ok:
                    chosen = {
                        "family": fam["family"],
                        "family_index": fam["family_index"],
                        "candidate_count": fam["candidate_count"],
                        "sha256": sha,
                        "first_seen_utc": candidate["first_seen_utc"],
                        "file_name": candidate["file_name"],
                        "file_size_bytes": candidate["file_size_bytes"],
                        "mb_signature": candidate["mb_signature"],
                        "mb_file_arch": candidate["mb_file_arch"],
                        "mb_tags": candidate["mb_tags"],
                        **summary,
                    }
                    break

            except Exception as e:
                vt_audit.append({
                    "family_pool_rank": pool_rank,
                    "family": fam["family"],
                    "family_candidate_count": fam["candidate_count"],
                    "candidate_order": candidate_order,
                    "sha256": sha,
                    "first_seen_utc": candidate["first_seen_utc"],
                    "mb_file_arch": candidate["mb_file_arch"],
                    "mb_tags": candidate["mb_tags"],
                    "vt_source": "ERROR",
                    "verdict": "ERROR",
                    "reason": str(e),
                    "vt_type_description": "",
                    "vt_type_tag": "",
                    "vt_magic": "",
                    "vt_tags": "",
                    "vt_malicious_detections": "",
                })

        if chosen is not None:
            resolved.append(chosen)

    write_csv(
        OUTPUT_ROOT / "VIRUSTOTAL_RESOLUTION_AUDIT.csv",
        vt_audit,
    )

    resolved.sort(
        key=lambda x: (
            -x["candidate_count"],
            -parse_dt(x["first_seen_utc"]).timestamp(),
            x["family"].lower(),
            x["sha256"],
        )
    )

    pool_rows = []

    for rank, row in enumerate(resolved, 1):
        role = (
            "PROVISIONAL_PRIMARY"
            if rank <= PRIMARY_TARGET
            else "RESERVE"
        )

        pool_rows.append({
            "final_pool_rank": rank,
            "role": role,
            **row,
            "workload_status": "NOT_YET_PREFLIGHTED",
            "promotion_rule": (
                ""
                if role == "PROVISIONAL_PRIMARY"
                else
                "Promote the next ranked reserve only after an earlier primary "
                "objectively fails the frozen zero-slot workload/platform preflight."
            ),
        })

    write_csv(
        OUTPUT_ROOT / "UBUNTU_MAXIMAL_TRULY_FRESH_RESOLVED_POOL.csv",
        pool_rows,
    )

    write_csv(
        OUTPUT_ROOT / "UBUNTU_PROVISIONAL_PRIMARY10.csv",
        [
            x
            for x in pool_rows
            if x["role"] == "PROVISIONAL_PRIMARY"
        ],
    )

    write_csv(
        OUTPUT_ROOT / "UBUNTU_RESERVE_POOL.csv",
        [
            x
            for x in pool_rows
            if x["role"] == "RESERVE"
        ],
    )

    receipt = {
        "schema_version": "10.0",
        "status": (
            "PASS_MAXIMAL_TRULY_FRESH_METADATA_STAGE"
            if len(resolved) >= PRIMARY_TARGET
            else "INSUFFICIENT_RESOLVED_FAMILIES"
        ),
        "malware_bytes_downloaded": False,
        "malware_executed": False,
        "authoritative_manifest_sources": manifest_sources,
        "previously_used_ransomware_hash_count_excluded": len(old_hashes),
        "windows_family_count": len(windows_families),
        "windows_families": sorted(windows_families.values()),
        "active_pre_vt_family_count": len(ranked_family_objects),
        "zero_fresh_candidate_families": [
            {
                "index": x["family_index"],
                "family": x["family"],
            }
            for x in zero_rows
        ],
        "resolved_family_count": len(resolved),
        "provisional_primary_count": min(
            PRIMARY_TARGET,
            len(resolved),
        ),
        "reserve_count": max(
            0,
            len(resolved) - PRIMARY_TARGET,
        ),
        "family_ranking_rule": (
            "candidate_count DESC, newest fresh candidate first_seen DESC, family ASC"
        ),
        "freshness_rule": (
            "Exclude every SHA-256 appearing in any frozen "
            "RANSOMWARE_40_RUN_MANIFEST.csv under the campaign root."
        ),
        "cross_os_leakage_rule": (
            "Exclude every frozen Windows ransomware family from Ubuntu selection."
        ),
        "final_acceptance_rule": (
            "Metadata-stage role is provisional only. Final eligibility requires "
            "zero-slot preflight showing genuine ransomware workload/canary modification, "
            "telemetry success, evidence packaging, and recovery. Immediate/error exit "
            "without meaningful workload is WORKLOAD_FAIL."
        ),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    (OUTPUT_ROOT / "SELECTION_RECEIPT.json").write_text(
        json.dumps(receipt, indent=2),
        encoding="utf-8",
    )

    hash_tree(OUTPUT_ROOT)

    print("")
    print("V10 TRULY-FRESH UBUNTU POOL: COMPLETE")
    print("Resolved families:", len(resolved))
    print(
        "Provisional PRIMARY:",
        ", ".join(
            x["family"]
            for x in pool_rows[:PRIMARY_TARGET]
        )
        or "NONE",
    )
    print(
        "Reserve pool:",
        ", ".join(
            x["family"]
            for x in pool_rows[PRIMARY_TARGET:]
        )
        or "NONE",
    )
    print("No malware bytes were downloaded or executed.")
    print("Evidence root:", OUTPUT_ROOT)


if __name__ == "__main__":
    main()
