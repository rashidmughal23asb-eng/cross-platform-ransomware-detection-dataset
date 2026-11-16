#!/bin/bash
set -euo pipefail

CRED=""
for arg in "$@"; do
  case "$arg" in
    --cred=*) CRED="${arg#--cred=}" ;;
  esac
done

if [ -z "$CRED" ] || [ ! -f "$CRED" ]; then
  echo "ERROR=CREDENTIAL_FILE_MISSING"
  exit 20
fi

TARGET="/opt/RansomLab/MalwareStaging/P5G/V10/Samples"
OLD="/opt/RansomLab/MalwareStaging/P5G/R4/Samples"
OUT="/tmp/UBUNTU_V10_Q1_PREP_RESULT.txt"

sudoq() {
  /usr/bin/sudo -S -p '' "$@" < "$CRED"
}

{
  echo "STATUS=PASS_GUEST_PREPARATION"
  echo "TARGET_ROOT=$TARGET"
  echo "OLD_ROOT=$OLD"

  sudoq /bin/mkdir -p "$TARGET"
  sudoq /bin/chown root:root "$TARGET"
  sudoq /bin/chmod 700 "$TARGET"

  TARGET_MODE="$(sudoq /usr/bin/stat -c '%a' "$TARGET")"
  TARGET_OWNER="$(sudoq /usr/bin/stat -c '%U:%G' "$TARGET")"
  echo "TARGET_MODE=$TARGET_MODE"
  echo "TARGET_OWNER=$TARGET_OWNER"

  if [ -d "$OLD" ]; then
    echo "OLD_ROOT_EXISTS=YES"
    OLD_COUNT="$(sudoq /usr/bin/find "$OLD" -maxdepth 1 -type f -name '*.sample' | /usr/bin/wc -l)"
    OLD_BYTES="$(sudoq /usr/bin/find "$OLD" -maxdepth 1 -type f -name '*.sample' -printf '%s\n' | /usr/bin/awk '{s+=$1} END{print s+0}')"
  else
    echo "OLD_ROOT_EXISTS=NO"
    OLD_COUNT=0
    OLD_BYTES=0
  fi

  echo "OLD_SAMPLE_COUNT=$OLD_COUNT"
  echo "OLD_SAMPLE_BYTES=$OLD_BYTES"

  NEW_COUNT="$(sudoq /usr/bin/find "$TARGET" -maxdepth 1 -type f -name '*.sample' | /usr/bin/wc -l)"
  echo "V10_SAMPLE_COUNT=$NEW_COUNT"

  echo "DF_OPT_BEGIN"
  /bin/df -Pk /opt
  echo "DF_OPT_END"

  echo "NOTE=OLD_R4_SAMPLES_PRESERVED_UNTIL_V10_19_HASH_VERIFIED"
} > "$OUT" 2>&1

/bin/rm -f "$CRED"
exit 0
