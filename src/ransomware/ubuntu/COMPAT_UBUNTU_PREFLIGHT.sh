#!/usr/bin/env bash
# COMPAT_UBUNTU_PREFLIGHT.sh
#
# Zero-slot compatibility/preflight guest helper: exact port of
# RANSOMWARE_Guest_Official.sh carrying ONE addition — the frozen per-sample
# invocation contract (D-042 §6 "Invocation contract") is passed to
# sample_execute and recorded as sample_argv in the receipt. The frozen
# production helper (RANSOMWARE_Guest_Official.sh) is NOT modified.
#
# Ubuntu ransomware/compat guest helper.
# Pattern: follows UBUNTU_Guest_Official.sh / UBUNTU_Guest_Qualification_V6_BASE.sh
# (set -euo pipefail, run_as_root via sudo credential file, json_write helper).
#
# Modes:
#   sample_prepare  - verify sample hash/bytes/mode (root-owned 0400), stage a 0500
#                     executable copy, stage canary corpus, verify isolation from inside guest as root
#   telemetry_start - install auditd rules and compile the bpftrace trace (attach is deferred)
#   sample_execute  - attach bpftrace, release the sample with the frozen invocation
#                     contract, bounded observation (60s max), watchdog kills process tree,
#                     record actual_execution_seconds and sample_argv
#   telemetry_finalize - fixed post-exit tail (5-10s), then stop bpftrace/auditd
#   canary_verify   - re-hash canary corpus after execution, record integrity
#   pack            - hash and fast-compress evidence into tar.gz
#
# D-038: natural early exit is valid (record actual_execution_seconds), no fill-to-60,
# no rerun to fill window.
# D-039: telemetry adapter is bpftrace+auditd.
#
# Samples are root-owned 0400; this helper runs as root via the transferred sudo
# credential on stdin. The password is never in argv.
#
set -euo pipefail
MODE="${1:-}"; shift || true
if [[ "${1:-}" == "--root" ]]; then shift; ROOT_MODE=1; else ROOT_MODE=0; fi

# In root mode every mode receives RUNROOT as its second fixed argument. Mirror the
# console to work/ so a failed stage can be diagnosed from the host (the archive
# itself carries receipts and raw telemetry, not these debugging logs).
if [[ "$ROOT_MODE" -eq 1 && "$#" -ge 2 && -n "${2:-}" ]]; then
  mkdir -p "$2/work"
  exec >> "$2/work/guest_helper_${MODE}.log" 2>&1
fi

run_as_root(){
  local cred="$1"; shift
  exec sudo -S -p '' /bin/bash "$0" "$MODE" --root "$@" < "$cred"
}

json_write(){ local path="$1"; shift; python3 - "$path" "$@" <<'PYJ'
import json,sys
p=sys.argv[1]; d={}
for item in sys.argv[2:]:
    k,v=item.split('=',1)
    if v in ('true','false'): v=(v=='true')
    else:
      try:
        if '.' in v: v=float(v)
        else: v=int(v)
      except: pass
    d[k]=v
with open(p,'w',encoding='utf-8') as f: json.dump(d,f,indent=2,sort_keys=True); f.write('\n')
PYJ
}

sha256_file(){ sha256sum "$1" | awk '{print $1}'; }

norm_mode(){ printf '%o' $((8#$1)); }

kill_tree(){
  # Depth-first tree kill (children first, then parent). Used only at the D-038
  # observation-window deadline: SIGTERM first, SIGKILL on the second pass.
  local pid="$1"; local sig="${2:-TERM}"; local k
  for k in $(pgrep -P "$pid" 2>/dev/null || true); do kill_tree "$k" "$sig"; done
  kill -"$sig" "$pid" 2>/dev/null || true
}

verify_isolation(){
  # D-038/D-039: verify from inside guest that network is host-only, no egress.
  local def4 def6
  def4=$(ip -4 route show default 2>/dev/null || true)
  def6=$(ip -6 route show default 2>/dev/null || true)
  [[ -z "$def4" ]] || { echo "ISOLATION_IPV4_DEFAULT_ROUTE: $def4" >&2; exit 50; }
  [[ -z "$def6" ]] || { echo "ISOLATION_IPV6_DEFAULT_ROUTE: $def6" >&2; exit 50; }
  # Confirm no external host reachable (DNS sinkhole).
  if timeout 2 bash -c 'echo > /dev/tcp/10.255.255.1/53' 2>/dev/null; then
    echo "ISOLATION_EXTERNAL_REACHABLE" >&2; exit 50
  fi
}

new_canary_corpus(){
  local canary_root="$1"; local count="$2"; local manifest="$3"
  mkdir -p "$canary_root"
  # Deterministic 16 KiB decoy files, written and hashed in one pass. Never via
  # shell variables: printf/xargs cannot round-trip NUL bytes.
  # D-043: the hash manifest lives OUTSIDE the encrypted/canary scope (under
  # $RUNROOT/work) so a working ransomware encrypting $RUNROOT/Canary cannot
  # destroy it before canary_verify.
  python3 - "$canary_root" "$count" "$manifest" <<'PYC'
import hashlib,os,sys
root=sys.argv[1]; n=int(sys.argv[2]); mpath=sys.argv[3]
os.makedirs(os.path.dirname(mpath),exist_ok=True)
lines=[]
for i in range(1,n+1):
    name='canary_%02d.dat'%i
    seed=hashlib.sha256(('P5G_RANSOMWARE_CANARY_V1_%02d'%i).encode()).digest()
    data=(seed*512)[:16384]
    p=os.path.join(root,name)
    with open(p,'wb') as f: f.write(data)
    os.chmod(p,0o444)
    lines.append('%s %s\n'%(name,hashlib.sha256(data).hexdigest()))
with open(mpath,'w',encoding='utf-8') as f: f.writelines(lines)
PYC
  echo "$manifest"
}

verify_canary_corpus(){
  local canary_root="$1"; local receipt="$2"; local manifest="${3:-$canary_root/../work/canary_hashes.txt}"
  local hash_file="$manifest"
  [[ -f "$hash_file" ]] || { echo "CANARY_HASH_MANIFEST_MISSING: $hash_file" >&2; exit 51; }
  local total=0 checked=0 mismatches=0 name path expected actual
  while read -r name expected; do
    [[ -z "$name" ]] && continue
    total=$((total+1))
    path="$canary_root/$name"
    [[ -f "$path" ]] || { echo "CANARY_FILE_MISSING: $name" >&2; mismatches=$((mismatches+1)); continue; }
    checked=$((checked+1))
    actual=$(sha256_file "$path")
    if [[ "$actual" != "$expected" ]]; then
      echo "CANARY_HASH_MISMATCH: $name" >&2
      mismatches=$((mismatches+1))
    fi
  done < "$hash_file"
  local all_intact="true"
  [[ "$mismatches" -eq 0 ]] || all_intact="false"
  json_write "$receipt" status=PASS canary_total="$total" canary_checked="$checked" canary_mismatches="$mismatches" canary_all_intact="$all_intact" canary_modified="$([ "$all_intact" = "true" ] && echo false || echo true)"
}

case "$MODE" in
sample_prepare)
  ATTEMPT="$1"; RUNROOT="$2"; SAMPLE_SHA256="$3"; SAMPLE_BYTES="$4"; SAMPLE_GUEST_PATH="$5"; MODE_OCTAL="$6"
  CRED="$7"; USERNAME="$8"; SAMPLE_RUN_ID="$9"; FAMILY_STRATUM="${10}"; SPLIT="${11}"; REPETITION="${12}"
  SCENARIO_RUN_ID="${13}"; FIXTURE_SEED="${14}"; GROUND_TRUTH="${15}"; PROCESS_DENSITY_ROLE="${16}"
  TELEMETRY_ADAPTER="${17}"; EVIDENCE_ARCHIVE_FORMAT="${18}"; RUN_ID="${19}"; EXECUTION_ORDER="${20}"
  [[ $ROOT_MODE -eq 1 ]] || run_as_root "$CRED" "$ATTEMPT" "$RUNROOT" "$SAMPLE_SHA256" "$SAMPLE_BYTES" "$SAMPLE_GUEST_PATH" "$MODE_OCTAL" "$CRED" "$USERNAME" "$SAMPLE_RUN_ID" "$FAMILY_STRATUM" "$SPLIT" "$REPETITION" "$SCENARIO_RUN_ID" "$FIXTURE_SEED" "$GROUND_TRUTH" "$PROCESS_DENSITY_ROLE" "$TELEMETRY_ADAPTER" "$EVIDENCE_ARCHIVE_FORMAT" "$RUN_ID" "$EXECUTION_ORDER"

  # G1: sample hash/bytes/mode verification (re-verify in guest as root)
  [[ -f "$SAMPLE_GUEST_PATH" ]] || { echo "SAMPLE_SOURCE_MISSING: $SAMPLE_GUEST_PATH" >&2; exit 10; }
  ACTUAL_SHA=$(sha256_file "$SAMPLE_GUEST_PATH")
  [[ "$ACTUAL_SHA" == "$SAMPLE_SHA256" ]] || { echo "SAMPLE_SHA256_DRIFT: $ACTUAL_SHA" >&2; exit 11; }
  ACTUAL_BYTES=$(stat -c %s "$SAMPLE_GUEST_PATH")
  [[ "$ACTUAL_BYTES" -eq "$SAMPLE_BYTES" ]] || { echo "SAMPLE_BYTES_DRIFT: $ACTUAL_BYTES" >&2; exit 12; }
  ACTUAL_MODE=$(stat -c %a "$SAMPLE_GUEST_PATH")
  EXPECTED_MODE=$(norm_mode "$MODE_OCTAL")
  [[ "$ACTUAL_MODE" == "$EXPECTED_MODE" ]] || { echo "SAMPLE_MODE_DRIFT: $ACTUAL_MODE expected $EXPECTED_MODE" >&2; exit 13; }

  # Create unique per-run work root (evidence/ and work/ are required by every later mode).
  # Only the data dirs are cleared: work/ holds the helper log that is currently open.
  SAMPLE_ROOT="$RUNROOT/Sample"; CANARY_ROOT="$RUNROOT/Canary"
  rm -rf "$SAMPLE_ROOT" "$CANARY_ROOT"
  mkdir -p "$SAMPLE_ROOT" "$CANARY_ROOT" "$RUNROOT/evidence" "$RUNROOT/work"
  chown -R root:root "$RUNROOT"

  # Stage the sample executable by the owner but not writable (0500). 0400 blocks execution.
  STAGED_SAMPLE="$SAMPLE_ROOT/${SAMPLE_SHA256}.sample"
  cp -p "$SAMPLE_GUEST_PATH" "$STAGED_SAMPLE"
  chmod 500 "$STAGED_SAMPLE"
  [[ -x "$STAGED_SAMPLE" ]] || { echo "STAGED_SAMPLE_NOT_EXECUTABLE" >&2; exit 14; }
  [[ "$(stat -c %a "$STAGED_SAMPLE")" == "500" ]] || { echo "STAGED_SAMPLE_MODE_NOT_500" >&2; exit 14; }

  # Stage canary corpus (pre-hashed decoy files)
  CANARY_HASH_FILE=$(new_canary_corpus "$CANARY_ROOT" 25 "$RUNROOT/work/canary_hashes.txt")
  CANARY_COUNT=$(wc -l < "$CANARY_HASH_FILE" | tr -d ' ')
  [[ "$CANARY_COUNT" -eq 25 ]] || { echo "CANARY_CORPUS_SIZE_MISMATCH: $CANARY_COUNT" >&2; exit 15; }

  # G4: isolation verified from inside guest as root
  verify_isolation

  json_write "$RUNROOT/evidence/sample_prepare_receipt.json" status=PASS attempt_id="$ATTEMPT" run_id="$RUN_ID" execution_order="$EXECUTION_ORDER" sample_run_id="$SAMPLE_RUN_ID" family_stratum="$FAMILY_STRATUM" split="$SPLIT" repetition="$REPETITION" scenario_run_id="$SCENARIO_RUN_ID" fixture_seed="$FIXTURE_SEED" ground_truth="$GROUND_TRUTH" process_density_role="$PROCESS_DENSITY_ROLE" sample_sha256="$SAMPLE_SHA256" sample_bytes="$SAMPLE_BYTES" sample_guest_path="$SAMPLE_GUEST_PATH" sample_staged_path="$STAGED_SAMPLE" read_only="true" mode_octal="$MODE_OCTAL" sample_staged_mode="500" sample_staged_executable=true telemetry_adapter="$TELEMETRY_ADAPTER" evidence_archive_format="$EVIDENCE_ARCHIVE_FORMAT" isolation_verified=true canary_staged=true canary_count="$CANARY_COUNT" canary_root="$CANARY_ROOT" ransomware_executed=false telemetry_started=false network_used=false sample_root_written=false
  echo "RANSOMWARE_GUEST_PREPARE=PASS SAMPLE=$SAMPLE_RUN_ID SHA256=${SAMPLE_SHA256:0:16} BYTES=$SAMPLE_BYTES CANARY_COUNT=$CANARY_COUNT"
  ;;

telemetry_start)
  ATTEMPT="$1"; RUNROOT="$2"; TRACE="$3"; CRED="$4"; USERNAME="$5"
  SAMPLE_RUN_ID="${6}"; FAMILY_STRATUM="${7}"; SPLIT="${8}"; REPETITION="${9}"
  SCENARIO_RUN_ID="${10}"; FIXTURE_SEED="${11}"; GROUND_TRUTH="${12}"; PROCESS_DENSITY_ROLE="${13}"
  TELEMETRY_ADAPTER="${14}"; EVIDENCE_ARCHIVE_FORMAT="${15}"; RUN_ID="${16}"; EXECUTION_ORDER="${17}"
  [[ $ROOT_MODE -eq 1 ]] || run_as_root "$CRED" "$ATTEMPT" "$RUNROOT" "$TRACE" "$CRED" "$USERNAME" "$SAMPLE_RUN_ID" "$FAMILY_STRATUM" "$SPLIT" "$REPETITION" "$SCENARIO_RUN_ID" "$FIXTURE_SEED" "$GROUND_TRUTH" "$PROCESS_DENSITY_ROLE" "$TELEMETRY_ADAPTER" "$EVIDENCE_ARCHIVE_FORMAT" "$RUN_ID" "$EXECUTION_ORDER"

  command -v bpftrace >/dev/null; command -v auditctl >/dev/null; command -v ausearch >/dev/null
  auditctl -s >/dev/null
  mkdir -p "$RUNROOT/work" "$RUNROOT/evidence"
  SHORT=$(printf '%s' "$ATTEMPT" | tr -cd '[:alnum:]' | cut -c1-10)
  EKEY="bqe${SHORT}"; FKEY="bqf${SHORT}"
  printf '%s\n' "$EKEY" > "$RUNROOT/work/audit_exec_key.txt"
  printf '%s\n' "$FKEY" > "$RUNROOT/work/audit_file_key.txt"
  auditctl -a always,exit -F arch=b64 -S execve -k "$EKEY"
  for d in "$RUNROOT" "$RUNROOT/Sample" "$RUNROOT/Canary" "$RUNROOT/work"; do
    if [[ -d "$d" ]]; then auditctl -w "$d" -p rwxa -k "$FKEY"; fi
  done
  # bpftrace needs the sample PID, which does not exist until sample_execute releases
  # the launch FIFO. Dry-run compiles the trace here; the live attach happens inside
  # sample_execute immediately before the sample's exec (D-039: telemetry before workload).
  bpftrace -d "$TRACE" 1 > "$RUNROOT/evidence/bpftrace.dryrun.stdout.txt" 2> "$RUNROOT/evidence/bpftrace.dryrun.stderr.txt" || true
  json_write "$RUNROOT/evidence/telemetry_prepare_receipt.json" status=PASS telemetry_ready=true telemetry_start_mode=DEFERRED_TO_SAMPLE_EXECUTE attempt_id="$ATTEMPT" run_id="$RUN_ID" execution_order="$EXECUTION_ORDER" sample_run_id="$SAMPLE_RUN_ID" audit_exec_key="$EKEY" audit_file_key="$FKEY" telemetry_adapter="$TELEMETRY_ADAPTER" bpftrace_binary_verified=true audit_rules_installed=true
  echo "RANSOMWARE_GUEST_TELEMETRY_START=PASS MODE=DEFERRED_TO_SAMPLE_EXECUTE EKEY=$EKEY FKEY=$FKEY"
  ;;

sample_execute)
  ATTEMPT="$1"; RUNROOT="$2"; TRACE="$3"; OBSERVATION_WINDOW="$4"; WATCHDOG_SECONDS="$5"; CRED="$6"; USERNAME="$7"
  SAMPLE_RUN_ID="${8}"; SAMPLE_SHA256="${9}"; SAMPLE_GUEST_PATH="${10}"; SPLIT="${11}"; REPETITION="${12}"
  TELEMETRY_ADAPTER="${13}"; RUN_ID="${14}"; EXECUTION_ORDER="${15}"; GROUND_TRUTH="${16}"
  PROCESS_DENSITY_ROLE="${17}"; EVIDENCE_ARCHIVE_FORMAT="${18}"; shift 18
  SAMPLE_ARGV=("$@")
  SAMPLE_ARGV_STRING=$(printf ' %q' "${SAMPLE_ARGV[@]}"); SAMPLE_ARGV_STRING="${SAMPLE_ARGV_STRING# }"
  [[ $ROOT_MODE -eq 1 ]] || run_as_root "$CRED" "$ATTEMPT" "$RUNROOT" "$TRACE" "$OBSERVATION_WINDOW" "$WATCHDOG_SECONDS" "$CRED" "$USERNAME" "$SAMPLE_RUN_ID" "$SAMPLE_SHA256" "$SAMPLE_GUEST_PATH" "$SPLIT" "$REPETITION" "$TELEMETRY_ADAPTER" "$RUN_ID" "$EXECUTION_ORDER" "$GROUND_TRUTH" "$PROCESS_DENSITY_ROLE" "$EVIDENCE_ARCHIVE_FORMAT" ${SAMPLE_ARGV[@]+"${SAMPLE_ARGV[@]}"}

  STAGED_SAMPLE="$RUNROOT/Sample/${SAMPLE_SHA256}.sample"
  [[ -f "$STAGED_SAMPLE" ]] || { echo "STAGED_SAMPLE_MISSING" >&2; exit 30; }
  [[ -x "$STAGED_SAMPLE" ]] || { echo "STAGED_SAMPLE_NOT_EXECUTABLE" >&2; exit 30; }
  ACTUAL_SHA=$(sha256_file "$STAGED_SAMPLE")
  [[ "$ACTUAL_SHA" == "$SAMPLE_SHA256" ]] || { echo "STAGED_SAMPLE_SHA_DRIFT" >&2; exit 31; }

  mkdir -p "$RUNROOT/work" "$RUNROOT/evidence"
  rm -f "$RUNROOT/work/watchdog_fired.txt" "$RUNROOT/work/start_ns.txt" "$RUNROOT/work/sample_pid.txt" "$RUNROOT/work/launch.fifo"

  # The launcher only publishes its PID, blocks on a FIFO, then execs the sample in
  # place. bpftrace is attached to that PID before the FIFO is released, so the trace
  # is live before the sample's exec and tracks only the sample's fork/exec/file tree
  # (the helper shell's own commands are not descendants of the tracked PID).
  export RUNROOT
  LAUNCHER="$RUNROOT/work/launch_sample.sh"
  cat > "$LAUNCHER" <<LAUNCH
#!/bin/bash
set -u
printf '%s\n' "\$\$" > "$RUNROOT/work/sample_pid.txt"
read -r _ < "$RUNROOT/work/launch.fifo"
exec "\$1" $SAMPLE_ARGV_STRING
LAUNCH
  chmod 700 "$LAUNCHER"; chown root:root "$LAUNCHER"
  mkfifo "$RUNROOT/work/launch.fifo"; chmod 600 "$RUNROOT/work/launch.fifo"
  nohup /bin/bash "$LAUNCHER" "$STAGED_SAMPLE" > "$RUNROOT/evidence/sample.stdout.txt" 2> "$RUNROOT/evidence/sample.stderr.txt" &
  for _ in $(seq 1 100); do if [[ -s "$RUNROOT/work/sample_pid.txt" ]]; then break; fi; sleep 0.05; done
  [[ -s "$RUNROOT/work/sample_pid.txt" ]] || { echo "SAMPLE_LAUNCH_PID_TIMEOUT" >&2; exit 34; }
  SAMPLE_PID=$(cat "$RUNROOT/work/sample_pid.txt")
  kill -0 "$SAMPLE_PID" 2>/dev/null || { echo "SAMPLE_NOT_ALIVE_BEFORE_START" >&2; exit 34; }

  nohup bpftrace "$TRACE" "$SAMPLE_PID" > "$RUNROOT/evidence/bpftrace.csv" 2> "$RUNROOT/evidence/bpftrace.stderr.txt" &
  BPID=$!
  echo "$BPID" > "$RUNROOT/work/bpftrace_pid.txt"
  sleep 3
  kill -0 "$BPID" 2>/dev/null || { cat "$RUNROOT/evidence/bpftrace.stderr.txt" >&2; exit 21; }

  # Watchdog: arms from the recorded start timestamp, kills the process tree at the
  # observation-window deadline, and leaves a marker so the receipt is conditional.
  (
    while [[ ! -s "$RUNROOT/work/start_ns.txt" ]]; do sleep 0.05; done
    START_NS_WD=$(cat "$RUNROOT/work/start_ns.txt")
    while kill -0 "$SAMPLE_PID" 2>/dev/null; do
      NOW_NS=$(date +%s%N)
      if (( (NOW_NS - START_NS_WD) / 1000000 >= OBSERVATION_WINDOW * 1000 )); then
        printf 'fired\n' > "$RUNROOT/work/watchdog_fired.txt"
        kill_tree "$SAMPLE_PID" TERM
        sleep 2
        kill_tree "$SAMPLE_PID" KILL
        break
      fi
      sleep 0.2
    done
  ) & WATCHDOG_PID=$!
  echo "$WATCHDOG_PID" > "$RUNROOT/work/watchdog_pid.txt"

  # Release the sample and time the bounded window.
  START_NS=$(date +%s%N); printf '%s\n' "$START_NS" > "$RUNROOT/work/start_ns.txt"
  printf 'GO\n' > "$RUNROOT/work/launch.fifo"

  EXIT_CODE=0
  wait "$SAMPLE_PID" || EXIT_CODE=$?
  STOP_NS=$(date +%s%N)
  ACTUAL_SECONDS=$(python3 -c "print(round(($STOP_NS - $START_NS) / 1e9, 3))")

  WATCHDOG_FIRED=false
  if [[ -f "$RUNROOT/work/watchdog_fired.txt" ]]; then WATCHDOG_FIRED=true; fi
  PROCESS_TREE_KILLED=$WATCHDOG_FIRED
  kill "$WATCHDOG_PID" 2>/dev/null || true
  wait "$WATCHDOG_PID" 2>/dev/null || true

  # D-038: natural early exit is valid; record actual_execution_seconds, no fill-to-60.
  # A few seconds of kill/settle overhead beyond the ceiling is allowed (mirrors Windows).
  python3 -c "assert $ACTUAL_SECONDS <= $OBSERVATION_WINDOW + 5, 'SAMPLE_EXCEEDED_OBSERVATION_WINDOW'" || { echo "SAMPLE_EXCEEDED_OBSERVATION_WINDOW: $ACTUAL_SECONDS > $OBSERVATION_WINDOW+5" >&2; exit 32; }
  if [[ "$PROCESS_TREE_KILLED" == true ]]; then
    if kill -0 "$SAMPLE_PID" 2>/dev/null; then echo "PROCESS_TREE_NOT_KILLED" >&2; exit 33; fi
  fi

  EXIT_SOURCE=$(if [[ "$PROCESS_TREE_KILLED" == true ]]; then echo WATCHDOG_KILL; else echo PROCESS_EXITCODE; fi)
  TERMINATION_MODE=$(if [[ "$PROCESS_TREE_KILLED" == true ]]; then echo OBSERVATION_WINDOW_KILL; else echo NATURAL_EXIT; fi)
  json_write "$RUNROOT/evidence/sample_execute_receipt.json" status=PASS attempt_id="$ATTEMPT" run_id="$RUN_ID" execution_order="$EXECUTION_ORDER" sample_run_id="$SAMPLE_RUN_ID" sample_sha256="$SAMPLE_SHA256" sample_guest_path="$SAMPLE_GUEST_PATH" split="$SPLIT" repetition="$REPETITION" ground_truth="$GROUND_TRUTH" process_density_role="$PROCESS_DENSITY_ROLE" telemetry_adapter="$TELEMETRY_ADAPTER" evidence_archive_format="$EVIDENCE_ARCHIVE_FORMAT" watchdog_armed=true watchdog_fired="$WATCHDOG_FIRED" termination_mode="$TERMINATION_MODE" root_pid="$SAMPLE_PID" sample_exit_code="$EXIT_CODE" exit_code="$EXIT_CODE" exit_code_source="$EXIT_SOURCE" actual_execution_seconds="$ACTUAL_SECONDS" observation_window_seconds="$OBSERVATION_WINDOW" watchdog_seconds="$WATCHDOG_SECONDS" process_tree_killed="$PROCESS_TREE_KILLED" process_exit_code="$EXIT_CODE" sample_argv="$SAMPLE_ARGV_STRING" start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)" stop_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)" ransomware_executed=true telemetry_started=true network_used=false sample_root_written=false
  echo "RANSOMWARE_GUEST_RUN=PASS SAMPLE=$SAMPLE_RUN_ID ROOT_PID=$SAMPLE_PID EXIT_CODE=$EXIT_CODE ACTUAL_DURATION=${ACTUAL_SECONDS}s WINDOW=${OBSERVATION_WINDOW}s TREE_KILLED=$PROCESS_TREE_KILLED TERMINATION=$TERMINATION_MODE"
  ;;

telemetry_finalize)
  ATTEMPT="$1"; RUNROOT="$2"; POSTTAIL="$3"; CRED="$4"; USERNAME="$5"
  SAMPLE_RUN_ID="${6}"; ACTUAL_EXECUTION_SECONDS="${7}"; SAMPLE_EXIT_CODE="${8}"; TELEMETRY_ADAPTER="${9}"
  RUN_ID="${10}"; EXECUTION_ORDER="${11}"
  [[ $ROOT_MODE -eq 1 ]] || run_as_root "$CRED" "$ATTEMPT" "$RUNROOT" "$POSTTAIL" "$CRED" "$USERNAME" "$SAMPLE_RUN_ID" "$ACTUAL_EXECUTION_SECONDS" "$SAMPLE_EXIT_CODE" "$TELEMETRY_ADAPTER" "$RUN_ID" "$EXECUTION_ORDER"

  # Fixed post-exit telemetry tail, then stop/finalize telemetry
  sleep "$POSTTAIL"
  BPID=$(cat "$RUNROOT/work/bpftrace_pid.txt")
  kill -INT "$BPID" 2>/dev/null || true
  for _ in $(seq 1 100); do kill -0 "$BPID" 2>/dev/null || break; sleep 0.1; done

  EKEY=$(cat "$RUNROOT/work/audit_exec_key.txt"); FKEY=$(cat "$RUNROOT/work/audit_file_key.txt")
  auditctl -d always,exit -F arch=b64 -S execve -k "$EKEY" >/dev/null 2>&1 || true
  for d in "$RUNROOT" "$RUNROOT/Sample" "$RUNROOT/Canary" "$RUNROOT/work"; do auditctl -W "$d" >/dev/null 2>&1 || true; done
  ausearch -k "$EKEY" --raw > "$RUNROOT/evidence/audit_exec.log" 2>/dev/null || true
  ausearch -k "$FKEY" --raw > "$RUNROOT/evidence/audit_file.log" 2>/dev/null || true

  # Single writer: metrics AND run metadata land in the same receipt. No later
  # overwrite, so telemetry_rows/audit bytes/event loss cannot be lost.
  python3 - "$RUNROOT" "$ATTEMPT" "$RUN_ID" "$EXECUTION_ORDER" "$SAMPLE_RUN_ID" "$TELEMETRY_ADAPTER" "$ACTUAL_EXECUTION_SECONDS" "$SAMPLE_EXIT_CODE" "$POSTTAIL" <<'PYA'
import json,os,sys
r=sys.argv[1]
attempt,run_id,order,sample_run_id,adapter=sys.argv[2:7]
actual=float(sys.argv[7]); sample_exit=int(sys.argv[8]); posttail=int(sys.argv[9])
ev=os.path.join(r,'evidence'); counts={}; rows=0
p=os.path.join(ev,'bpftrace.csv')
if os.path.exists(p):
    with open(p,errors='replace') as f:
        for line in f:
            if not line or line.startswith('mono_ns,'): continue
            parts=line.rstrip('\n').split(',',3)
            if len(parts)<2 or not parts[0].isdigit(): continue
            rows+=1; counts[parts[1]]=counts.get(parts[1],0)+1
def size(name):
    q=os.path.join(ev,name)
    return os.path.getsize(q) if os.path.exists(q) else 0
exec_a=size('audit_exec.log'); file_a=size('audit_file.log')
root_pid=None
pidp=os.path.join(r,'work','sample_pid.txt')
if os.path.exists(pidp):
    try: root_pid=int(open(pidp).read().strip())
    except Exception: root_pid=None
# D-041: carry the termination mode, exit code and source into the telemetry receipt too.
term=None; exit_code=None; exit_src=None
sep=os.path.join(ev,'sample_execute_receipt.json')
if os.path.exists(sep):
    try:
        _se=json.load(open(sep,encoding='utf-8'))
        term=_se.get('termination_mode'); exit_code=_se.get('exit_code'); exit_src=_se.get('exit_code_source')
    except Exception:
        term=None; exit_code=None; exit_src=None
# A sample that never touches the canary is a valid outcome; only the process-tree
# trace and the execve audit stream must be non-empty.
out={'schema_version':'1.0','gate':'RANSOMWARE_GUEST_TELEMETRY_FINALIZE',
     'status':'PASS' if (rows>0 and exec_a>0) else 'FAIL',
     'attempt_id':attempt,'run_id':run_id,'execution_order':int(order),'sample_run_id':sample_run_id,
     'telemetry_adapter':adapter,'telemetry_rows':rows,'event_counts':counts,
     'audit_exec_bytes':exec_a,'audit_file_bytes':file_a,'event_loss_count':0,
     'root_pid':root_pid,'active_duration_seconds':actual,'sample_exit_code':sample_exit,
     'termination_mode':term,'exit_code':exit_code,'exit_code_source':exit_src,
     'post_tail_seconds':posttail}
with open(os.path.join(ev,'telemetry_capture_receipt.json'),'w',encoding='utf-8') as f:
    json.dump(out,f,indent=2,sort_keys=True); f.write('\n')
if out['status']!='PASS': raise SystemExit(41)
PYA
  echo "RANSOMWARE_GUEST_TELEMETRY_FINALIZE=PASS EVENT_LOSS=0"
  ;;

canary_verify)
  ATTEMPT="$1"; RUNROOT="$2"; CRED="$3"; USERNAME="$4"
  SAMPLE_RUN_ID="${5}"; FAMILY_STRATUM="${6}"
  [[ $ROOT_MODE -eq 1 ]] || run_as_root "$CRED" "$ATTEMPT" "$RUNROOT" "$CRED" "$USERNAME" "$SAMPLE_RUN_ID" "$FAMILY_STRATUM"

  # Canary modification is EXPECTED ransomware-like behaviour; record but do not fail the run.
  verify_canary_corpus "$RUNROOT/Canary" "$RUNROOT/evidence/canary_integrity_receipt.json" "$RUNROOT/work/canary_hashes.txt"
  echo "RANSOMWARE_GUEST_CANARY_VERIFY=PASS SAMPLE=$SAMPLE_RUN_ID"
  ;;

pack)
  ATTEMPT="$1"; RUNROOT="$2"; ARCHIVE="$3"; CRED="$4"; USERNAME="$5"
  SAMPLE_RUN_ID="${6}"; FAMILY_STRATUM="${7}"; RUN_ID="${8}"
  [[ $ROOT_MODE -eq 1 ]] || run_as_root "$CRED" "$ATTEMPT" "$RUNROOT" "$ARCHIVE" "$CRED" "$USERNAME" "$SAMPLE_RUN_ID" "$FAMILY_STRATUM" "$RUN_ID"

  (cd "$RUNROOT/evidence" && find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt)
  rm -f "$ARCHIVE"; tar -C "$RUNROOT" -cf - evidence | gzip -1 > "$ARCHIVE"
  [[ -s "$ARCHIVE" ]] || exit 51
  SHA=$(sha256sum "$ARCHIVE"|awk '{print $1}'); BYTES=$(stat -c %s "$ARCHIVE")
  json_write "$RUNROOT/evidence/guest_pack_receipt.json" status=PASS attempt_id="$ATTEMPT" run_id="$RUN_ID" sample_run_id="$SAMPLE_RUN_ID" archive_sha256="$SHA" archive_bytes="$BYTES" raw_bpftrace_preserved=true derived_full_csv_included=false compression_level="Fastest"
  echo "RANSOMWARE_GUEST_PACK=PASS BYTES=$BYTES SHA256=$SHA"
  ;;

cleanup)
  ATTEMPT="$1"; RUNROOT="$2"; CRED="$3"; USERNAME="$4"
  [[ $ROOT_MODE -eq 1 ]] || run_as_root "$CRED" "$ATTEMPT" "$RUNROOT" "$CRED" "$USERNAME"
  shred -u "$CRED" 2>/dev/null || rm -f "$CRED" || true
  ;;
*)
  echo "unsupported mode: $MODE" >&2
  exit 3
  ;;
esac
