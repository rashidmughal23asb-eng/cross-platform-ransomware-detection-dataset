#!/usr/bin/env bash
# COMPAT_UBUNTU_PILOT.sh
#
# Ubuntu guest helper for the zero-slot compatibility/contract pilot.
# Executes one Ubuntu ransomware sample against a throwaway canary directory
# under bounded observation (60 s max), records a D-041 receipt, and reports
# whether the binary is runnable on Ubuntu.
#
# Pattern: mirrors RANSOMWARE_Guest_Official.sh exactly (set -euo pipefail,
# run_as_root via transferred sudo credential on stdin, json_write helper,
# ATTEMPT first). The password is never in argv.
#
# Mode:
#   compat <attempt> <run_id> <sha> <guest_path> <family> <cred> <work_root> <obs_window> <argv...>
#
# D-038: natural early exit is valid; record actual_execution_seconds, no fill-to-60.
# D-041: every receipt records termination_mode, exit_code, exit_code_source,
#        watchdog_fired, process_tree_killed.
#
# Samples are root-owned 0400; this helper copies each to a temp exec path
# (chmod 700) so the staged sample is never modified. A fresh canary corpus is
# staged per sample and re-checked after execution.

set -euo pipefail
MODE="${1:-}"; shift || true

# Functions are defined BEFORE any dispatch (the non-root path calls run_as_root).
run_as_root(){
  local cred="$1"; shift
  exec sudo -S -p '' /bin/bash "$0" "$MODE" --root "$@" < "$cred"
}

json_write(){ local path="$1"; shift; python3 - "$path" "$@" <<'PYJ'
import json,sys
p=sys.argv[1]; d={}
for item in sys.argv[2:]:
    if '=' in item:
        k,v=item.split('=',1)
        if v=='true': v=True
        elif v=='false': v=False
        elif v=='null': v=None
        else:
            try: v=int(v)
            except ValueError:
                try: v=float(v)
                except ValueError: pass
        d[k]=v
    else:
        d[item]=True
try:
    existing={}
    try: existing=json.load(open(p,encoding='utf-8'))
    except Exception: pass
    existing.update(d)
    with open(p,'w',encoding='utf-8') as f: json.dump(existing,f,indent=2,sort_keys=False); f.write('\n')
except Exception as e:
    sys.stderr.write('JSON_WRITE_FAIL: '+str(e)+'\n'); sys.exit(1)
PYJ
}

sha256_file(){ local f="$1"; python3 -c "import hashlib,sys; h=hashlib.sha256(); f=open('$f','rb'); [h.update(b) for b in iter(lambda:f.read(1<<20),b'')]; f.close(); print(h.hexdigest())"; }

kill_tree(){
  local root="$1"; sig="$2"
  local kids; kids=$(pgrep -P "$root" 2>/dev/null || true)
  for k in $kids; do kill_tree "$k" "$sig" 2>/dev/null || true; done
  kill -$sig "$root" 2>/dev/null || true
}

if [[ "${1:-}" == "--root" ]]; then
  shift
  ROOT_MODE=1
else
  ROOT_MODE=0
fi

ATTEMPT="${1:-pilot}"

# Non-root mode: re-exec under sudo with the sudo credential on stdin.
# args: ATTEMPT RUN_ID SHA PATH FAMILY CRED WORK_ROOT OBS_WINDOW argv...
if [[ $ROOT_MODE -eq 0 ]]; then
  RUN_ID="$2"; SAMPLE_SHA256="$3"; SAMPLE_GUEST_PATH="$4"; FAMILY="$5"; CRED="$6"; WORK_ROOT="$7"; OBS_WINDOW="$8"; shift 8
  SAMPLE_ARGV=("$@")
  run_as_root "$CRED" "$ATTEMPT" "$RUN_ID" "$SAMPLE_SHA256" "$SAMPLE_GUEST_PATH" "$FAMILY" "$CRED" "$WORK_ROOT" "$OBS_WINDOW" "${SAMPLE_ARGV[@]}"
  # run_as_root execs; unreachable.
  exit 0
fi

# ---- root-mode body ----
# args after --root: ATTEMPT RUN_ID SHA PATH FAMILY CRED WORK_ROOT OBS_WINDOW argv...
ATTEMPT="$1"; RUN_ID="$2"; SAMPLE_SHA256="$3"; SAMPLE_GUEST_PATH="$4"; FAMILY="$5"; CRED="$6"; WORK_ROOT="$7"; OBS_WINDOW="$8"; shift 8
SAMPLE_ARGV=("$@")

RUNROOT="$WORK_ROOT"
CANARY_ROOT="$RUNROOT/canary"
EXEC_DIR="$RUNROOT/exec"
mkdir -p "$RUNROOT/work" "$RUNROOT/evidence" "$EXEC_DIR" "$CANARY_ROOT"
exec >> "$RUNROOT/work/guest_helper_${MODE}.log" 2>&1
echo "COMPAT_GUEST_START ATTEMPT=$ATTEMPT RUN_ID=$RUN_ID SHA=$SAMPLE_SHA256 FAMILY=$FAMILY OBS_WINDOW=$OBS_WINDOW"
echo "SAMPLE_ARGV: ${SAMPLE_ARGV[*]}"

# Verify the staged sample (root-owned 0400) before copying.
[[ -f "$SAMPLE_GUEST_PATH" ]] || { echo "SAMPLE_SOURCE_MISSING: $SAMPLE_GUEST_PATH" >&2; exit 10; }
ACTUAL_SHA=$(sha256_file "$SAMPLE_GUEST_PATH")
[[ "$ACTUAL_SHA" == "$SAMPLE_SHA256" ]] || { echo "SAMPLE_SHA256_DRIFT: $ACTUAL_SHA" >&2; exit 11; }
ACTUAL_BYTES=$(stat -c %s "$SAMPLE_GUEST_PATH")
[[ "$ACTUAL_BYTES" -gt 0 ]] || { echo "SAMPLE_BYTES_ZERO" >&2; exit 12; }

# Copy to a temp exec path (chmod 700); never modify the 0400 staged sample.
STAGED_EXEC="$EXEC_DIR/${SAMPLE_SHA256}.sample"
cp -p "$SAMPLE_GUEST_PATH" "$STAGED_EXEC"
chmod 700 "$STAGED_EXEC"
[[ -x "$STAGED_EXEC" ]] || { echo "SAMPLE_EXEC_NOT_EXECUTABLE" >&2; exit 13; }

# Stage a fresh canary corpus (5 decoy files, pre-hashed).
python3 - "$CANARY_ROOT" 5 <<'PYC'
import hashlib,os,sys
root=sys.argv[1]; n=int(sys.argv[2]); os.makedirs(root,exist_ok=True)
lines=[]
for i in range(n):
    name='canary_%02d.dat'%i
    data=('P5G_COMPAT_CANARY_V1_%02d'%i).encode()* (i+1)
    p=os.path.join(root,name)
    with open(p,'wb') as f: f.write(data)
    lines.append(hashlib.sha256(data).hexdigest()+'  '+name)
with open(os.path.join(root,'canary_hashes.txt'),'w') as f: f.write('\n'.join(lines)+'\n')
print(root)
PYC
CANARY_COUNT=$(wc -l < "$CANARY_ROOT/canary_hashes.txt" | tr -d ' ')
[[ "$CANARY_COUNT" -eq 5 ]] || { echo "CANARY_CORPUS_SIZE_MISMATCH: $CANARY_COUNT" >&2; exit 15; }

# ---- bounded execution with watchdog (mirrors official sample_execute, no bpftrace) ----
rm -f "$RUNROOT/work/watchdog_fired.txt" "$RUNROOT/work/start_ns.txt" "$RUNROOT/work/sample_pid.txt" "$RUNROOT/work/launch.fifo"
mkfifo "$RUNROOT/work/launch.fifo"
chmod 600 "$RUNROOT/work/launch.fifo"

export RUNROOT STAGED_EXEC
LAUNCHER="$RUNROOT/work/launch_sample.sh"
# Build the argv string up-front; host already substituted <CANARY>; args contain no spaces.
SAMPLE_ARGV_STRING=$(printf ' %q' "${SAMPLE_ARGV[@]}"); SAMPLE_ARGV_STRING="${SAMPLE_ARGV_STRING# }"
cat > "$LAUNCHER" <<LAUNCH
#!/bin/bash
set -u
printf '%s\n' "\$\$" > "$RUNROOT/work/sample_pid.txt"
read -r _ < "$RUNROOT/work/launch.fifo"
exec "$STAGED_EXEC" $SAMPLE_ARGV_STRING
LAUNCH
chmod 700 "$LAUNCHER"

nohup /bin/bash "$LAUNCHER" > "$RUNROOT/evidence/sample.stdout.txt" 2> "$RUNROOT/evidence/sample.stderr.txt" &
LAUNCHER_PID=$!
for _ in $(seq 1 100); do if [[ -s "$RUNROOT/work/sample_pid.txt" ]]; then break; fi; sleep 0.05; done
[[ -s "$RUNROOT/work/sample_pid.txt" ]] || { echo "SAMPLE_LAUNCH_PID_TIMEOUT" >&2; exit 34; }
SAMPLE_PID=$(cat "$RUNROOT/work/sample_pid.txt")
# The launcher is blocked on the FIFO before exec, so it is always alive here.
kill -0 "$SAMPLE_PID" 2>/dev/null || { echo "SAMPLE_NOT_ALIVE_BEFORE_START" >&2; exit 34; }

# Watchdog subshell: kills the process tree at the observation-window deadline.
(
  START_WD=$(date +%s%N)
  while kill -0 "$SAMPLE_PID" 2>/dev/null; do
    NOW=$(date +%s%N)
    if (( (NOW - START_WD) / 1000000 >= OBS_WINDOW * 1000 )); then
      printf 'fired\n' > "$RUNROOT/work/watchdog_fired.txt"
      kill_tree "$SAMPLE_PID" TERM
      sleep 2
      kill_tree "$SAMPLE_PID" KILL
      break
    fi
    sleep 0.2
  done
) & WATCHDOG_PID=$!

START_NS=$(date +%s%N); printf '%s\n' "$START_NS" > "$RUNROOT/work/start_ns.txt"
# Release the sample only after start_ns is recorded and the watchdog is armed.
printf 'GO\n' > "$RUNROOT/work/launch.fifo"

EXIT_CODE=0
wait "$SAMPLE_PID" || EXIT_CODE=$?
STOP_NS=$(date +%s%N)
ACTUAL_SECONDS=$(python3 -c "print(round(($STOP_NS - $START_NS) / 1e9, 3))")

WATCHDOG_FIRED=false
[[ -f "$RUNROOT/work/watchdog_fired.txt" ]] && WATCHDOG_FIRED=true
PROCESS_TREE_KILLED=$WATCHDOG_FIRED
kill "$WATCHDOG_PID" 2>/dev/null || true
wait "$WATCHDOG_PID" 2>/dev/null || true

python3 -c "assert $ACTUAL_SECONDS <= $OBS_WINDOW + 5, 'SAMPLE_EXCEEDED_OBSERVATION_WINDOW'" 2>/dev/null || { echo "SAMPLE_EXCEEDED_OBSERVATION_WINDOW: $ACTUAL_SECONDS" >&2; exit 32; }
if [[ "$PROCESS_TREE_KILLED" == true ]]; then
  kill -0 "$SAMPLE_PID" 2>/dev/null && { echo "PROCESS_TREE_NOT_KILLED" >&2; exit 33; }
fi

EXIT_SOURCE=$(if [[ "$PROCESS_TREE_KILLED" == true ]]; then echo WATCHDOG_KILL; else echo PROCESS_EXITCODE; fi)
TERMINATION_MODE=$(if [[ "$PROCESS_TREE_KILLED" == true ]]; then echo OBSERVATION_WINDOW_KILL; else echo NATURAL_EXIT; fi)

# Canary integrity check after execution.
CANARY_ALL_INTACT=true; CANARY_MISMATCHES=0
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  h="${line%% *}"; name="${line##* }"
  p="$CANARY_ROOT/$name"
  if [[ ! -f "$p" ]]; then CANARY_ALL_INTACT=false; CANARY_MISMATCHES=$((CANARY_MISMATCHES+1)); continue; fi
  ah=$(sha256_file "$p")
  if [[ "$ah" != "$h" ]]; then CANARY_ALL_INTACT=false; CANARY_MISMATCHES=$((CANARY_MISMATCHES+1)); fi
done < "$CANARY_ROOT/canary_hashes.txt"

json_write "$RUNROOT/evidence/compat_receipt.json" status=PASS attempt_id="$ATTEMPT" run_id="$RUN_ID" sample_run_id="$RUN_ID" sample_sha256="$SAMPLE_SHA256" sample_guest_path="$SAMPLE_GUEST_PATH" family_stratum="$FAMILY" ground_truth=RANSOMWARE_COMPAT process_density_role=MALICIOUS_PRIMARY_SUBJECT telemetry_adapter=bpftrace+auditd evidence_archive_format=tar.gz watchdog_armed=true watchdog_fired="$WATCHDOG_FIRED" termination_mode="$TERMINATION_MODE" root_pid="$SAMPLE_PID" sample_exit_code="$EXIT_CODE" exit_code="$EXIT_CODE" exit_code_source="$EXIT_SOURCE" actual_execution_seconds="$ACTUAL_SECONDS" observation_window_seconds="$OBS_WINDOW" watchdog_seconds="$OBS_WINDOW" process_tree_killed="$PROCESS_TREE_KILLED" process_exit_code="$EXIT_CODE" start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)" stop_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)" ransomware_executed=false telemetry_started=false network_used=false sample_root_written=false canary_total="$CANARY_COUNT" canary_checked="$CANARY_COUNT" canary_mismatches="$CANARY_MISMATCHES" canary_all_intact="$CANARY_ALL_INTACT" sample_argv="$SAMPLE_ARGV_STRING"

echo "COMPAT_GUEST_RUN=PASS SAMPLE=$RUN_ID ROOT_PID=$SAMPLE_PID EXIT_CODE=$EXIT_CODE ACTUAL_DURATION=${ACTUAL_SECONDS}s WINDOW=${OBS_WINDOW}s TREE_KILLED=$PROCESS_TREE_KILLED TERMINATION=$TERMINATION_MODE CANARY_INTACT=$CANARY_ALL_INTACT"
