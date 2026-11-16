#!/bin/bash
# UBUNTU_V10_POPULATE_GUEST.sh
#
# Guest-side materialization for Ubuntu V10.
# Places the 19 frozen artifacts into /opt/RansomLab/MalwareStaging/P5G/V10/Samples/
# and verifies them, byte-for-byte and size-for-size, against the frozen manifest.
# The old R4 baseline is read-only throughout.
#
# Run as the normal guest user (ubuntu) via the Native-VIX bridge; privileged
# operations go through the transferred sudo credential file.
#
# Hardening (learned from a real failure on 2026-11-10): four of the last-written
# files came back as 0 bytes because the VM was hard-powered-off before ext4 had
# committed its delayed allocations. Therefore:
#   * every staged file is checked for hash AND expected size before it is moved in,
#   * every in-place file is checked for hash AND expected size,
#   * the guest is fsync'd and ALL 19 are re-verified again after the flush,
#   * zero-byte files are counted explicitly and must be 0.
#
# Exit codes:
#   20 credential missing      21 manifest missing       22 stage dir missing
#   31 old R4 root missing     41 old R4 count != 10      42 V10 dir not empty
#   33 manifest not 19 rows    45 verification failed
#   46 count command failed    44 old R4 changed during population
#
# NOTE: This helper does NOT power off the VM and does NOT create a snapshot.

set -euo pipefail

CRED=""
MANIFEST="/tmp/UBUNTU_V10_EXPECTED_SHA256.tsv"
STAGE=""
OUT="/tmp/UBUNTU_V10_POPULATE_RESULT.txt"

V10="/opt/RansomLab/MalwareStaging/P5G/V10/Samples"
R4="/opt/RansomLab/MalwareStaging/P5G/R4/Samples"

for arg in "$@"; do
  case "$arg" in
    --cred=*)     CRED="${arg#--cred=}" ;;
    --manifest=*) MANIFEST="${arg#--manifest=}" ;;
    --stage=*)    STAGE="${arg#--stage=}" ;;
    --out=*)      OUT="${arg#--out=}" ;;
  esac
done

if [ -z "$CRED" ] || [ ! -f "$CRED" ]; then echo "ERROR=CREDENTIAL_FILE_MISSING" >&2; exit 20; fi
if [ ! -f "$MANIFEST" ]; then echo "ERROR=EXPECTED_HASH_MANIFEST_MISSING" >&2; exit 21; fi
if [ -z "$STAGE" ] || [ ! -d "$STAGE" ]; then echo "ERROR=STAGE_DIR_MISSING" >&2; exit 22; fi

sudoq() {
  /usr/bin/sudo -S -p '' "$@" < "$CRED"
}

{
  echo "STATUS=BEGIN"

  # ---- 1. Old R4 baseline preservation (read-only, before any write) ----
  if [ ! -d "$R4" ]; then
    echo "ERROR=OLD_R4_ROOT_MISSING"
    exit 31
  fi
  OLD_COUNT="$(sudoq /usr/bin/find "$R4" -maxdepth 1 -type f -name '*.sample' | /usr/bin/wc -l)"
  echo "OLD_R4_SAMPLE_COUNT=$OLD_COUNT"
  if [ "$OLD_COUNT" -ne 10 ]; then
    echo "ERROR=OLD_R4_SAMPLE_COUNT_NOT_10"
    exit 41
  fi
  echo "OLD_R4_HASHES_BEGIN"
  sudoq /usr/bin/find "$R4" -maxdepth 1 -type f -name '*.sample' -exec /usr/bin/sha256sum {} + | /usr/bin/sort -k 2
  echo "OLD_R4_HASHES_END"

  # ---- 2. V10 target directory must be absent or empty ----
  if [ -d "$V10" ]; then
    PRE_ENTRIES="$(sudoq /usr/bin/find "$V10" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l)"
    echo "V10_PREEXISTING_ENTRIES=$PRE_ENTRIES"
    if [ "$PRE_ENTRIES" -ne 0 ]; then
      echo "ERROR=V10_DIR_NOT_EMPTY"
      exit 42
    fi
  else
    sudoq /usr/bin/mkdir -p "$V10"
    echo "V10_DIR_CREATED=1"
  fi
  sudoq /bin/chown root:root "$V10"
  sudoq /bin/chmod 700 "$V10"
  echo "V10_DIR_MODE=$(sudoq /usr/bin/stat -c '%a' "$V10")"
  echo "V10_DIR_OWNER=$(sudoq /usr/bin/stat -c '%U:%G' "$V10")"

  # ---- 3. Verify each staged file (hash AND size) BEFORE it enters the protected path ----
  EXPECTED_COUNT="$(/usr/bin/wc -l < "$MANIFEST")"
  echo "EXPECTED_COUNT=$EXPECTED_COUNT"
  if [ "$EXPECTED_COUNT" -ne 19 ]; then
    echo "ERROR=EXPECTED_MANIFEST_NOT_19"
    exit 33
  fi

  echo "STAGE_RESULTS_BEGIN"
  S_PASS=0
  S_FAIL=0
  S_MISS=0
  while IFS=$'\t' read -r SHA FAMILY ROLE RANK SIZE; do
    [ -n "$SHA" ] || continue
    SHA="${SHA%$'\r'}"; FAMILY="${FAMILY%$'\r'}"; ROLE="${ROLE%$'\r'}"; RANK="${RANK%$'\r'}"; SIZE="${SIZE%$'\r'}"
    SRC="$STAGE/$SHA.sample"

    if [ ! -f "$SRC" ]; then
      echo "STAGE_MISS|$RANK|$ROLE|$FAMILY|$SHA"
      S_MISS=$((S_MISS+1))
      continue
    fi

    SACT="$(/usr/bin/sha256sum "$SRC" | /usr/bin/awk '{print $1}')"
    SSZ="$(/usr/bin/stat -c '%s' "$SRC")"
    if [ "$SACT" != "$SHA" ] || [ "$SSZ" != "$SIZE" ]; then
      echo "STAGE_FAIL|$RANK|$ROLE|$FAMILY|expected=$SHA|actual=$SACT|size_expected=$SIZE|size_actual=$SSZ"
      S_FAIL=$((S_FAIL+1))
      continue
    fi

    # Atomic placement inside the protected directory.
    TMP="$V10/.incoming_$SHA.tmp"
    sudoq /bin/rm -f "$TMP"
    sudoq /bin/cp -f "$SRC" "$TMP"
    sudoq /bin/chown root:root "$TMP"
    sudoq /bin/chmod 600 "$TMP"
    sudoq /bin/mv -f "$TMP" "$V10/$SHA.sample"

    echo "STAGE_PASS|$RANK|$ROLE|$FAMILY|$SHA|$SSZ"
    S_PASS=$((S_PASS+1))
  done < "$MANIFEST"
  echo "STAGE_RESULTS_END"
  echo "STAGE_PASS_COUNT=$S_PASS"
  echo "STAGE_FAIL_COUNT=$S_FAIL"
  echo "STAGE_MISS_COUNT=$S_MISS"

  # ---- 4. Post-placement verification inside the protected path ----
  echo "HASH_RESULTS_BEGIN"
  PASS=0
  FAIL=0
  while IFS=$'\t' read -r SHA FAMILY ROLE RANK SIZE; do
    [ -n "$SHA" ] || continue
    SHA="${SHA%$'\r'}"; FAMILY="${FAMILY%$'\r'}"; ROLE="${ROLE%$'\r'}"; RANK="${RANK%$'\r'}"; SIZE="${SIZE%$'\r'}"
    FILE="$V10/$SHA.sample"

    if ! sudoq /usr/bin/test -f "$FILE"; then
      echo "MISS|$RANK|$ROLE|$FAMILY|$SHA|$FILE"
      FAIL=$((FAIL+1))
      continue
    fi

    ACTUAL="$(sudoq /usr/bin/sha256sum "$FILE" | /usr/bin/awk '{print $1}')"
    FSIZE="$(sudoq /usr/bin/stat -c '%s' "$FILE")"

    if [ "$ACTUAL" = "$SHA" ] && [ "$FSIZE" = "$SIZE" ]; then
      echo "PASS|$RANK|$ROLE|$FAMILY|$SHA|$FSIZE|$FILE"
      PASS=$((PASS+1))
    else
      echo "FAIL|$RANK|$ROLE|$FAMILY|expected=$SHA|actual=$ACTUAL|size_expected=$SIZE|size_actual=$FSIZE|$FILE"
      FAIL=$((FAIL+1))
    fi
  done < "$MANIFEST"
  echo "HASH_RESULTS_END"
  echo "HASH_PASS=$PASS"
  echo "HASH_FAIL=$FAIL"

  # ---- 5. Cardinality: 19 files, 0 duplicates, 0 unexpected, 0 zero-byte ----
  # NOTE: the V10 directory is root:root 700, so the unprivileged shell cannot
  # glob into it. All counting goes through sudo; globs are avoided entirely.
  echo "COUNT_RESULTS_BEGIN"
  FILE_COUNT="$(sudoq /usr/bin/find "$V10" -maxdepth 1 -type f -name '*.sample' | /usr/bin/wc -l)" || FILE_COUNT=-1
  ALL_ENTRIES="$(sudoq /usr/bin/find "$V10" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l)" || ALL_ENTRIES=-1
  UNIQUE_HASHES="$(sudoq /usr/bin/find "$V10" -maxdepth 1 -type f -name '*.sample' -exec /usr/bin/sha256sum {} + | /usr/bin/awk '{print $1}' | /usr/bin/sort -u | /usr/bin/wc -l)" || UNIQUE_HASHES=-1
  ZERO_BYTES="$(sudoq /usr/bin/find "$V10" -maxdepth 1 -type f -name '*.sample' -size 0c | /usr/bin/wc -l)" || ZERO_BYTES=-1
  echo "COUNT_RESULTS_END"

  if [ "$FILE_COUNT" -lt 0 ] || [ "$ALL_ENTRIES" -lt 0 ] || [ "$UNIQUE_HASHES" -lt 0 ] || [ "$ZERO_BYTES" -lt 0 ]; then
    echo "ERROR=COUNT_COMMAND_FAILED"
    echo "STATUS=REVIEW_REQUIRED"
    exit 46
  fi

  UNEXPECTED=$((ALL_ENTRIES - FILE_COUNT))
  echo "V10_SAMPLE_COUNT=$FILE_COUNT"
  echo "V10_UNEXPECTED_ENTRIES=$UNEXPECTED"
  echo "V10_UNIQUE_HASHES=$UNIQUE_HASHES"
  echo "V10_ZERO_BYTE_SAMPLES=$ZERO_BYTES"

  # ---- 6. Old R4 baseline still intact after placement ----
  OLD_AFTER="$(sudoq /usr/bin/find "$R4" -maxdepth 1 -type f -name '*.sample' | /usr/bin/wc -l)"
  echo "OLD_R4_SAMPLE_COUNT_AFTER=$OLD_AFTER"
  if [ "$OLD_AFTER" -ne 10 ]; then
    echo "ERROR=OLD_R4_CHANGED_DURING_POPULATION"
    echo "STATUS=REVIEW_REQUIRED"
    exit 44
  fi

  # ---- 7. Flush to disk, then re-verify what actually landed on disk ----
  # The power-off that follows is a hard VIX power-off; without this flush ext4
  # delayed allocation can leave the most recent files at 0 bytes.
  sudoq /bin/sync
  /bin/sleep 1
  sudoq /bin/sync
  echo "GUEST_SYNC=DONE"

  echo "POST_SYNC_RESULTS_BEGIN"
  PS_PASS=0
  PS_FAIL=0
  while IFS=$'\t' read -r SHA FAMILY ROLE RANK SIZE; do
    [ -n "$SHA" ] || continue
    SHA="${SHA%$'\r'}"; SIZE="${SIZE%$'\r'}"
    FILE="$V10/$SHA.sample"
    if ! sudoq /usr/bin/test -f "$FILE"; then
      echo "POST_SYNC_MISS|$SHA"
      PS_FAIL=$((PS_FAIL+1))
      continue
    fi
    PA="$(sudoq /usr/bin/sha256sum "$FILE" | /usr/bin/awk '{print $1}')"
    PZ="$(sudoq /usr/bin/stat -c '%s' "$FILE")"
    if [ "$PA" = "$SHA" ] && [ "$PZ" = "$SIZE" ]; then
      PS_PASS=$((PS_PASS+1))
    else
      echo "POST_SYNC_FAIL|$SHA|size_expected=$SIZE|size_actual=$PZ|sha=$PA"
      PS_FAIL=$((PS_FAIL+1))
    fi
  done < "$MANIFEST"
  echo "POST_SYNC_RESULTS_END"
  echo "POST_SYNC_HASH_PASS=$PS_PASS"
  echo "POST_SYNC_HASH_FAIL=$PS_FAIL"

  # ---- 8. Verdict ----
  if [ "$PASS" -ne 19 ] || [ "$FAIL" -ne 0 ] \
     || [ "$FILE_COUNT" -ne 19 ] || [ "$UNEXPECTED" -ne 0 ] \
     || [ "$UNIQUE_HASHES" -ne 19 ] || [ "$ZERO_BYTES" -ne 0 ] \
     || [ "$PS_PASS" -ne 19 ] || [ "$PS_FAIL" -ne 0 ]; then
    echo "STATUS=REVIEW_REQUIRED"
    exit 45
  fi

  echo "V10_SAMPLE_PERMISSIONS_TEMPORARY=600"
  echo "PERMISSION_FREEZE_DEFERRED_TO=UBUNTU_V10_FINALIZE_GUEST.sh"
  echo "STATUS=PASS_19_POPULATED_GUEST_HASH_VERIFIED"
} > "$OUT" 2>&1

/bin/rm -f "$CRED"
exit 0
