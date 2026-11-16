#!/bin/bash
set -u

OUT="/tmp/UBUNTU_V10_STORAGE_PREFLIGHT_RESULT.txt"
TARGET="/opt/RansomLab/MalwareStaging/P5G/V10/Samples"
OLD="/opt/RansomLab/MalwareStaging/P5G/R4/Samples"

{
  echo "STATUS=PASS_GUEST_STORAGE_QUERY"
  echo "TARGET_ROOT=$TARGET"

  if [ -e "$TARGET" ]; then
    echo "TARGET_EXISTS=YES"
  else
    echo "TARGET_EXISTS=NO"
  fi

  if [ -d "$OLD" ]; then
    echo "OLD_SAMPLE_ROOT_EXISTS=YES"
  else
    echo "OLD_SAMPLE_ROOT_EXISTS=NO"
  fi

  echo "DF_OPT_BEGIN"
  /bin/df -Pk /opt
  echo "DF_OPT_END"

  echo "DF_ROOT_BEGIN"
  /bin/df -Pk /
  echo "DF_ROOT_END"

  echo "P5G_PARENT_BEGIN"
  /bin/ls -ld /opt/RansomLab/MalwareStaging/P5G 2>&1 || true
  echo "P5G_PARENT_END"
} > "$OUT" 2>&1

exit 0
