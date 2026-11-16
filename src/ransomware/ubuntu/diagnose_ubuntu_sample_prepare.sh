#!/usr/bin/env bash
# D-122 guest-side diagnostic for the SAMPLE_PREPARE failure.
#
# READ-ONLY with respect to the campaign: it never executes a ransomware sample, never
# starts telemetry and never writes into the frozen staging area. It only reads the
# staged sample's metadata, checks the guest's network state, verifies the shell syntax
# of the transferred helper and replicates the helper's staging arithmetic in a throwaway
# directory that it deletes again.
#
# It mirrors the FROZEN helper's argument and privilege contract exactly (mode dispatch,
# the root-mode stdout/stderr redirect into $RUNROOT/work, the sudo credential transport),
# so that a failure in those mechanics reproduces here too.
set -u
MODE="${1:-}"; shift || true
if [[ "${1:-}" == "--root" ]]; then shift; ROOT_MODE=1; else ROOT_MODE=0; fi

# Same root-mode redirect as the frozen helper: everything lands in the log file.
# $2 is RUNROOT (the helper's convention: in root mode the second fixed argument is the run root).
if [[ "$ROOT_MODE" -eq 1 && "$#" -ge 2 && -n "${2:-}" ]]; then
  mkdir -p "$2/work"
  exec >> "$2/work/diagnostic.log" 2>&1
fi

run_as_root() {
  local cred="$1"; shift
  exec sudo -S -p '' /bin/bash "$0" "$MODE" --root "$@" < "$cred"
}

if [[ "$ROOT_MODE" -eq 0 ]]; then
  CRED="$1"; RUNROOT="$2"; REPORT="$3"; HELPER_PATH="$4"; SAMPLE_PATH="$5"; SAMPLE_SHA="$6"; SAMPLE_BYTES="$7"; MODE_OCTAL="$8"
  # RUNROOT is passed twice so that, in root mode, $2 is the run root (the helper's convention).
  run_as_root "$CRED" "$RUNROOT" "$RUNROOT" "$REPORT" "$HELPER_PATH" "$SAMPLE_PATH" "$SAMPLE_SHA" "$SAMPLE_BYTES" "$MODE_OCTAL"
fi

RUNROOT="$1"; REPORT="$3"; HELPER_PATH="$4"; SAMPLE_PATH="$5"; SAMPLE_SHA="$6"; SAMPLE_BYTES="$7"; MODE_OCTAL="$8"

{
  echo "== identity =="
  id
  echo "umask=$(umask)"
  echo "== bash syntax of the transferred helper (the check that would have caught D-122) =="
  echo "helper=$HELPER_PATH"
  if bash -n "$HELPER_PATH" 2>&1; then echo "bash_n_helper=PASS"; else echo "bash_n_helper=FAIL"; fi
  if bash -n "$0" 2>&1; then echo "bash_n_self=PASS"; else echo "bash_n_self=FAIL"; fi
  echo "== the sample the runner was pointed at =="
  echo "path=$SAMPLE_PATH"
  echo "expected_sha=$SAMPLE_SHA expected_bytes=$SAMPLE_BYTES expected_mode_arg=$MODE_OCTAL"
  if [[ -f "$SAMPLE_PATH" ]]; then
    echo "EXISTS=yes"
    stat -c 'stat_mode=%a stat_bytes=%s owner=%U:%G' "$SAMPLE_PATH"
    echo "sha256=$(sha256sum "$SAMPLE_PATH" | awk '{print $1}')"
    echo "sha_match=$([ "$(sha256sum "$SAMPLE_PATH" | awk '{print $1}')" = "$SAMPLE_SHA" ] && echo yes || echo no)"
    echo "bytes_match=$([ "$(stat -c %s "$SAMPLE_PATH")" = "$SAMPLE_BYTES" ] && echo yes || echo no)"
  else
    echo "EXISTS=no"
    echo "-- the staging roots --"
    ls -ld /opt/RansomLab/MalwareStaging /opt/RansomLab/MalwareStaging/P5G 2>&1
    ls -ld /opt/RansomLab/MalwareStaging/P5G/R4/Samples /opt/RansomLab/MalwareStaging/P5G/V10/Samples /opt/RansomLab/MalwareStaging/P5G/V11/Samples 2>&1
    for d in /opt/RansomLab/MalwareStaging/P5G/R4/Samples /opt/RansomLab/MalwareStaging/P5G/V10/Samples /opt/RansomLab/MalwareStaging/P5G/V11/Samples; do
      printf '%s : %s files\n' "$d" "$(ls -1 "$d" 2>/dev/null | wc -l)"
    done
  fi
  echo "== the helper's mode arithmetic (norm_mode) =="
  for m in 000 0000 400 0400; do printf 'norm_mode(%s) = %s\n' "$m" "$(printf '%o' $((8#$m)) 2>&1)"; done
  echo "== network state inside the guest =="
  echo "-- ip -4 route show default --"; ip -4 route show default 2>&1
  echo "-- ip -6 route show default --"; ip -6 route show default 2>&1
  echo "-- ip -4 route (all) --"; ip -4 route 2>&1
  echo "-- ip -br link --"; ip -br link 2>&1
  echo "-- external probe 10.255.255.1:53 --"
  if timeout 2 bash -c 'echo > /dev/tcp/10.255.255.1/53' 2>/dev/null; then echo "REACHABLE"; else echo "NOT_REACHABLE"; fi
  echo "== toolchain =="
  for t in bpftrace auditctl ausearch python3 sudo sha256sum stat; do printf '%-12s %s\n' "$t" "$(command -v $t 2>&1)"; done
  bpftrace --version 2>&1 | head -2
  auditctl -v 2>&1 | head -2
  echo "== disk and tmp =="
  df -h /tmp 2>&1 | tail -2
  ls -ld /tmp 2>&1
  echo "== leftover filesystem-root dirs (an empty RUNROOT would create these) =="
  ls -ld /Sample /Canary /evidence /work 2>&1
  echo "== staging rehearsal in a throwaway directory (copy only, never executed) =="
  rm -rf "$RUNROOT/diag"; mkdir -p "$RUNROOT/diag/Sample"
  if cp -p "$SAMPLE_PATH" "$RUNROOT/diag/Sample/x.sample" 2>&1; then
    echo "cp_p=ok"
    chmod 500 "$RUNROOT/diag/Sample/x.sample"
    echo "staged_mode=$(stat -c %a "$RUNROOT/diag/Sample/x.sample")"
    if [[ -x "$RUNROOT/diag/Sample/x.sample" ]]; then echo "EXECUTABLE=yes"; else echo "EXECUTABLE=no"; fi
  else
    echo "cp_p=FAILED"
  fi
  rm -rf "$RUNROOT/diag"
  echo "== canary corpus rehearsal (the helper's own generator, in a throwaway directory) =="
  python3 - "$RUNROOT/diagcanary" <<'PYC'
import hashlib,os,sys
root=sys.argv[1]; n=25
os.makedirs(root,exist_ok=True)
lines=[]
for i in range(1,n+1):
    name='canary_%02d.dat'%i
    seed=hashlib.sha256(('P5G_RANSOMWARE_CANARY_V1_%02d'%i).encode()).digest()
    p=os.path.join(root,name)
    with open(p,'wb') as fh:
        fh.write(seed*512)
    lines.append('%s  %s'%(hashlib.sha256(seed*512).hexdigest(),name))
with open(os.path.join(root,'canary_hashes.txt'),'w') as fh:
    fh.write('\n'.join(lines)+'\n')
PYC
  echo "canary_files=$(ls -1 "$RUNROOT/diagcanary" 2>/dev/null | wc -l)"
  echo "canary_hash_lines=$(wc -l < "$RUNROOT/diagcanary/canary_hashes.txt" 2>/dev/null | tr -d ' ')"
  rm -rf "$RUNROOT/diagcanary"
  echo "== end of diagnostic =="
} > "$REPORT" 2>&1

echo "DIAGNOSTIC_WRITTEN:$REPORT"
