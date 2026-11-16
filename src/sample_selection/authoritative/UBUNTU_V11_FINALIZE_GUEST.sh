#!/bin/bash
# UBUNTU V11 FINALIZE GUEST (D-109) - runs INSIDE the guest, as root.
#
# Verifies the FROZEN FAMILY SET of ten qualified distinct Ubuntu families in
# the guest: for every row of the expected-hash manifest it checks that the
# sample exists at its canonical staging path, that its SHA-256 and byte count
# match the frozen identity, and that it is root-owned with mode 000. It also
# proves that the campaign's original R4 staging root is preserved, exactly as
# the V10 finalisation did.
#
# It MODIFIES NOTHING: it only reads. (The installation of the three new V11
# samples is a separate step that runs before this one.)
#
# Arguments: --cred=<cred file> --manifest=<expected tsv>
set -euo pipefail

CRED=""
MANIFEST=""
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
if [ -z "$MANIFEST" ] || [ ! -f "$MANIFEST" ]; then
  echo "ERROR=EXPECTED_HASH_MANIFEST_MISSING"
  exit 21
fi

sudoq() {
  /usr/bin/sudo -S -p '' "$@" < "$CRED"
}

V10="/opt/RansomLab/MalwareStaging/P5G/V10/Samples"
V11="/opt/RansomLab/MalwareStaging/P5G/V11/Samples"
R4="/opt/RansomLab/MalwareStaging/P5G/R4/Samples"

{
  echo "STATUS=BEGIN"

  # ---- the campaign's original staging root must be preserved ----
  if [ ! -d "$R4" ]; then
    echo "ERROR=OLD_R4_ROOT_MISSING"
    exit 31
  fi
  OLD_COUNT="$(sudoq /usr/bin/find "$R4" -maxdepth 1 -type f -name '*.sample' | /usr/bin/wc -l)"
  echo "OLD_R4_SAMPLE_COUNT=$OLD_COUNT"

  # ---- the frozen family set ----
  echo "FAMILY_SET_BEGIN"
  PASS=0
  FAIL=0
  COUNT=0
  V10_ZERO=0
  V11_ZERO=0

  while IFS=$'\t' read -r SHA FAMILY ROOT BYTES; do
    [ -n "$SHA" ] || continue
    # D-112: the expected-hash TSV may arrive with CRLF line endings (the host writes it
    # on Windows), which leaves a trailing CR on the LAST field. Strip it, or every row
    # would fail the byte-count comparison.
    BYTES="${BYTES%$'\r'}"
    ROOT="${ROOT%$'\r'}"
    FAMILY="${FAMILY%$'\r'}"
    SHA="${SHA%$'\r'}"

    COUNT=$((COUNT+1))
    FILE="$ROOT/$SHA.sample"

    if ! sudoq /usr/bin/test -f "$FILE"; then
      echo "MISS|$FAMILY|$SHA|$FILE"
      FAIL=$((FAIL+1))
      continue
    fi

    ACTUAL="$(sudoq /usr/bin/sha256sum "$FILE" | /usr/bin/awk '{print $1}')"
    SIZE="$(sudoq /usr/bin/stat -c '%s' "$FILE")"
    MODE="$(sudoq /usr/bin/stat -c '%a' "$FILE")"
    OWNER="$(sudoq /usr/bin/stat -c '%U:%G' "$FILE")"

    if [ "$ACTUAL" != "$SHA" ]; then
      echo "HASHFAIL|$FAMILY|expected=$SHA|actual=$ACTUAL"
      FAIL=$((FAIL+1))
      continue
    fi
    if [ "$SIZE" != "$BYTES" ]; then
      echo "BYTESFAIL|$FAMILY|expected=$BYTES|actual=$SIZE"
      FAIL=$((FAIL+1))
      continue
    fi
    if [ "$MODE" != "0" ]; then
      echo "MODEFAIL|$FAMILY|actual=$MODE|expected=0"
      FAIL=$((FAIL+1))
      continue
    fi
    if [ "$OWNER" != "root:root" ]; then
      echo "OWNERFAIL|$FAMILY|actual=$OWNER|expected=root:root"
      FAIL=$((FAIL+1))
      continue
    fi

    echo "PASS|$FAMILY|$SHA|$BYTES|$MODE|$OWNER|$FILE"
    PASS=$((PASS+1))
  done < "$MANIFEST"

  echo "FAMILY_SET_END"
  echo "FAMILY_COUNT=$COUNT"
  echo "FAMILY_PASS=$PASS"
  echo "FAMILY_FAIL=$FAIL"

  if [ "$COUNT" -ne 10 ] || [ "$PASS" -ne 10 ] || [ "$FAIL" -ne 0 ]; then
    echo "STATUS=REVIEW_REQUIRED"
    exit 35
  fi

  # ---- permission state of both staging roots ----
  for pair in "V10:$V10" "V11:$V11"; do
    NAME="${pair%%:*}"; DIR="${pair#*:}"
    if sudoq /usr/bin/test -d "$DIR"; then
      C="$(sudoq /usr/bin/find "$DIR" -maxdepth 1 -type f -name '*.sample' -perm 000 | /usr/bin/wc -l)"
      T="$(sudoq /usr/bin/find "$DIR" -maxdepth 1 -type f -name '*.sample' | /usr/bin/wc -l)"
      echo "${NAME}_SAMPLE_COUNT=$T"
      echo "${NAME}_ZERO_MODE_SAMPLE_COUNT=$C"
      echo "${NAME}_DIR_MODE=$(sudoq /usr/bin/stat -c '%a' "$DIR")"
      echo "${NAME}_DIR_OWNER=$(sudoq /usr/bin/stat -c '%U:%G' "$DIR")"
    else
      echo "${NAME}_ROOT_MISSING"
    fi
  done

  echo "STATUS=PASS_ALL_10_QUALIFIED_FAMILIES_VERIFIED_AND_PERMISSION_FROZEN"
} > /tmp/UBUNTU_V11_FINALIZE_RESULT.txt 2>&1

/bin/rm -f "$CRED"
exit 0
