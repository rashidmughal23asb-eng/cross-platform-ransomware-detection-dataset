#!/bin/bash
set -euo pipefail

CRED=""
MANIFEST="/tmp/UBUNTU_V10_EXPECTED_SHA256.tsv"
OUT="/tmp/UBUNTU_V10_FINALIZE_RESULT.txt"
V10="/opt/RansomLab/MalwareStaging/P5G/V10/Samples"
R4="/opt/RansomLab/MalwareStaging/P5G/R4/Samples"

for arg in "$@"; do
  case "$arg" in
    --cred=*) CRED="${arg#--cred=}" ;;
    --manifest=*) MANIFEST="${arg#--manifest=}" ;;
  esac
done

if [ -z "$CRED" ] || [ ! -f "$CRED" ]; then
  echo "ERROR=CREDENTIAL_FILE_MISSING"
  exit 20
fi
if [ ! -f "$MANIFEST" ]; then
  echo "ERROR=EXPECTED_HASH_MANIFEST_MISSING"
  exit 21
fi

sudoq() {
  /usr/bin/sudo -S -p '' "$@" < "$CRED"
}

{
  echo "STATUS=BEGIN"

  # Preserve old baseline proof.
  if [ ! -d "$R4" ]; then
    echo "ERROR=OLD_R4_ROOT_MISSING"
    exit 31
  fi
  OLD_COUNT="$(sudoq /usr/bin/find "$R4" -maxdepth 1 -type f -name '*.sample' | /usr/bin/wc -l)"
  echo "OLD_R4_SAMPLE_COUNT=$OLD_COUNT"

  # V10 materialization proof.
  if [ ! -d "$V10" ]; then
    echo "ERROR=V10_ROOT_MISSING"
    exit 32
  fi

  V10_COUNT="$(sudoq /usr/bin/find "$V10" -maxdepth 1 -type f -name '*.sample' | /usr/bin/wc -l)"
  echo "V10_SAMPLE_COUNT=$V10_COUNT"

  EXPECTED_COUNT="$(/usr/bin/wc -l < "$MANIFEST")"
  echo "EXPECTED_COUNT=$EXPECTED_COUNT"

  if [ "$EXPECTED_COUNT" -ne 19 ]; then
    echo "ERROR=EXPECTED_MANIFEST_NOT_19"
    exit 33
  fi

  if [ "$V10_COUNT" -ne 19 ]; then
    echo "ERROR=V10_SAMPLE_COUNT_NOT_19"
    exit 34
  fi

  echo "HASH_RESULTS_BEGIN"
  PASS=0
  FAIL=0

  while IFS=$'\t' read -r SHA FAMILY ROLE RANK; do
    [ -n "$SHA" ] || continue
    FILE="$V10/$SHA.sample"

    if ! sudoq /usr/bin/test -f "$FILE"; then
      echo "MISS|$RANK|$ROLE|$FAMILY|$SHA|$FILE"
      FAIL=$((FAIL+1))
      continue
    fi

    ACTUAL="$(sudoq /usr/bin/sha256sum "$FILE" | /usr/bin/awk '{print $1}')"
    SIZE="$(sudoq /usr/bin/stat -c '%s' "$FILE")"

    if [ "$ACTUAL" = "$SHA" ]; then
      echo "PASS|$RANK|$ROLE|$FAMILY|$SHA|$SIZE|$FILE"
      PASS=$((PASS+1))
    else
      echo "FAIL|$RANK|$ROLE|$FAMILY|expected=$SHA|actual=$ACTUAL|$FILE"
      FAIL=$((FAIL+1))
    fi
  done < "$MANIFEST"

  echo "HASH_RESULTS_END"
  echo "HASH_PASS=$PASS"
  echo "HASH_FAIL=$FAIL"

  if [ "$PASS" -ne 19 ] || [ "$FAIL" -ne 0 ]; then
    echo "STATUS=REVIEW_REQUIRED"
    exit 35
  fi

  # Harden only the V10 sample files after all hashes pass.
  sudoq /bin/chown root:root "$V10"
  sudoq /bin/chmod 700 "$V10"
  sudoq /usr/bin/find "$V10" -maxdepth 1 -type f -name '*.sample' -exec /bin/chown root:root {} \;
  sudoq /usr/bin/find "$V10" -maxdepth 1 -type f -name '*.sample' -exec /bin/chmod 000 {} \;

  echo "V10_DIR_MODE=$(sudoq /usr/bin/stat -c '%a' "$V10")"
  echo "V10_DIR_OWNER=$(sudoq /usr/bin/stat -c '%U:%G' "$V10")"

  ZERO_MODE_COUNT="$(sudoq /usr/bin/find "$V10" -maxdepth 1 -type f -name '*.sample' -perm 000 | /usr/bin/wc -l)"
  echo "V10_ZERO_MODE_SAMPLE_COUNT=$ZERO_MODE_COUNT"

  if [ "$ZERO_MODE_COUNT" -ne 19 ]; then
    echo "ERROR=V10_PERMISSION_FREEZE_FAILED"
    exit 36
  fi

  echo "STATUS=PASS_ALL_19_HASH_VERIFIED_AND_PERMISSION_FROZEN"
} > "$OUT" 2>&1

/bin/rm -f "$CRED"
exit 0
