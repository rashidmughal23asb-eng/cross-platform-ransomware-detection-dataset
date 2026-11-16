#!/usr/bin/env bash
set -euo pipefail
MODE="${1:-}"; shift || true
if [[ "${1:-}" == "--root" ]]; then shift; ROOT_MODE=1; else ROOT_MODE=0; fi
BASE="${0}.v6base"
DISP="${0}.scenario"

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

case "$MODE" in
prepare)
  ATTEMPT="$1"; RUNROOT="$2"; DURATION="$3"; CRED="$4"; USERNAME="$5"; SCENARIO="$6"; REPETITION="$7"; SCENARIO_RUN_ID="$8"; FIXTURE_SEED="$9"; SPLIT="${10}"; SCENARIO_NAME="${11}"; LEAD_APP="${12}"; RUN_ID="${13}"; GLOBAL_ORDER="${14}"
  [[ $ROOT_MODE -eq 1 ]] || run_as_root "$CRED" "$ATTEMPT" "$RUNROOT" "$DURATION" "$CRED" "$USERNAME" "$SCENARIO" "$REPETITION" "$SCENARIO_RUN_ID" "$FIXTURE_SEED" "$SPLIT" "$SCENARIO_NAME" "$LEAD_APP" "$RUN_ID" "$GLOBAL_ORDER"
  [[ -f "$DISP" ]] || { echo scenario dispatcher missing >&2; exit 10; }
  rm -rf "$RUNROOT"
  TMPPREP="/tmp/${SCENARIO}_prep_${ATTEMPT}.json"; rm -f "$TMPPREP"
  /bin/bash "$DISP" prepare "$SCENARIO" "$ATTEMPT" "$RUNROOT" "$DURATION" "$TMPPREP" "$REPETITION" "$USERNAME" "$FIXTURE_SEED"
  mkdir -p "$RUNROOT/evidence/toolcheck" "$RUNROOT/work"
  cp "$TMPPREP" "$RUNROOT/evidence/scenario_prepare_inner.json"; rm -f "$TMPPREP"

  FAIL=0
  for n in $(seq -w 1 15); do
    s="S$n"; r="$RUNROOT/evidence/toolcheck/$s.json"
    if /bin/bash "$DISP" toolcheck "$s" "$ATTEMPT" "$RUNROOT" "$DURATION" "$r" A "$USERNAME" "$s-UBU-A"; then :; else FAIL=1; fi
  done
  [[ "$FAIL" -eq 0 ]] || { json_write "$RUNROOT/evidence/workload_prepare_receipt.json" status=FAIL run_id="$RUN_ID" global_order="$GLOBAL_ORDER" scenario_id="$SCENARIO" repetition="$REPETITION" scenario_run_id="$SCENARIO_RUN_ID" fixture_seed="$FIXTURE_SEED" all15_toolcheck_status=FAIL; exit 13; }

  cat > "$RUNROOT/work/compound_root.sh" <<'ROOT'
#!/usr/bin/env bash
set -u
R="$1"; D="$2"; DISP="$3"; ATTEMPT="$4"; USERNAME="$5"; SCENARIO="$6"; REPETITION="$7"; SCENARIO_RUN_ID="$8"; FIXTURE_SEED="$9"; SPLIT="${10}"; SCENARIO_NAME="${11}"; LEAD_APP="${12}"; RUN_ID="${13}"; GLOBAL_ORDER="${14}"
STARTFLAG="$R/work/START"; STOPFLAG="$R/work/STOP"
echo $$ > "$R/work/root_pid.txt"
while [[ ! -f "$STARTFLAG" ]]; do sleep 0.05; done
rm -f "$STOPFLAG"
START_NS=$(date +%s%N)
( sleep "$D"; date +%s%N > "$R/work/active_end_ns.txt"; touch "$STOPFLAG" ) & TIMER=$!

branch_scenario(){ /bin/bash "$DISP" run "$SCENARIO" "$ATTEMPT" "$R" "$D" "$R/evidence/scenario_run_inner.json" "$REPETITION" "$USERNAME" "$FIXTURE_SEED"; }
branch_mutation(){ i=0; L="$R/fixture/support_mut"; mkdir -p "$L"; cp -a "$R/fixture/source/set_00/." "$L/" 2>/dev/null || cp -a "$R/fixture/source/." "$L/"; while [[ ! -f "$STOPFLAG" ]]; do for f in "$L"/*; do [[ -f "$f" ]] || continue; t="$f.tmp"; mv "$f" "$t"; printf 'm=%s\n' "$i" >> "$t"; mv "$t" "$f"; i=$((i+1)); [[ -f "$STOPFLAG" ]] && break; done; done; }
branch_archive(){ i=0; while [[ ! -f "$STOPFLAG" ]]; do a="$R/fixture/support_archive.tar.gz"; d="$R/fixture/support_extract"; rm -rf "$d"; tar -czf "$a" -C "$R/fixture/source" .; mkdir -p "$d"; tar -xzf "$a" -C "$d"; i=$((i+1)); done; }
branch_temp(){ i=0; T="$R/fixture/support_temp"; mkdir -p "$T"; while [[ ! -f "$STOPFLAG" ]]; do f="$T/t_$i.tmp"; printf '%08d-%s\n' "$i" "$(date +%s%N)" > "$f"; rm -f "$f"; i=$((i+1)); done; }
branch_copy(){ i=0; while [[ ! -f "$STOPFLAG" ]]; do d="$R/fixture/support_copy/r$((i%3))"; rm -rf "$d"; mkdir -p "$d"; cp -a "$R/fixture/source/." "$d/"; i=$((i+1)); done; }

branch_scenario & P1=$!
branch_mutation & P2=$!
branch_archive & P3=$!
branch_copy & P4=$!
branch_temp & P5=$!
printf '%s\n' "$P1" "$P2" "$P3" "$P4" "$P5" > "$R/work/branch_pids.txt"

FAIL=0
wait "$P1" || FAIL=1
wait "$P2" || FAIL=1
wait "$P3" || FAIL=1
wait "$P4" || FAIL=1
wait "$P5" || FAIL=1
wait "$TIMER" 2>/dev/null || true
END_NS=$(date +%s%N); ACTIVE_END_NS=$(cat "$R/work/active_end_ns.txt")
ABSENT=true
for p in "$P1" "$P2" "$P3" "$P4" "$P5"; do kill -0 "$p" 2>/dev/null && ABSENT=false || true; done
python3 - "$R/evidence/workload_run_receipt.json" "$START_NS" "$ACTIVE_END_NS" "$END_NS" "$$" "$P1" "$P2" "$P3" "$P4" "$P5" "$FAIL" "$ABSENT" "$SCENARIO" "$REPETITION" "$SCENARIO_RUN_ID" "$FIXTURE_SEED" "$SPLIT" "$SCENARIO_NAME" "$LEAD_APP" "$RUN_ID" "$GLOBAL_ORDER" <<'PYR'
import json,sys
p=sys.argv[1]; s,a,e=map(int,sys.argv[2:5]); root=int(sys.argv[5]); kids=list(map(int,sys.argv[6:11])); fail=int(sys.argv[11]); absent=sys.argv[12].lower()=="true"; scenario,rep,scenario_run_id,fixture_seed,split,scenario_name,lead_app,run_id=sys.argv[13:21]; global_order=int(sys.argv[21])
d={
"schema_version":"3.0","gate":"OFFICIAL_BENIGN_SCENARIO_RUN","status":"PASS" if fail==0 else "FAIL","run_id":run_id,"global_order":global_order,"scenario_id":scenario,"scenario_name":scenario_name,
"scenario_type":"application_led_compound_benign","lead_application":lead_app,"split":split,"repetition":rep,"scenario_run_id":scenario_run_id,"fixture_seed":fixture_seed,
"root_pid":root,"root_process_name":"bash","active_duration_seconds":round((a-s)/1e9,3),"root_lifecycle_seconds":round((e-s)/1e9,3),
"compound_task_count":5,"branch_pids":kids,"process_tree_edges":[{"parent":root,"child":k} for k in kids],
"operation_families":["bulk_copy","rename","modify","compress","decompress","temporary_create","delete","archive_rotation"],
"process_exit_code":0 if fail==0 else 1,"child_pid_absence_verified":absent,"execution_complete":fail==0,"observation_status":"COMPLETE" if fail==0 else "FAILED","network_used":False}
with open(p,"w",encoding="utf-8") as f: json.dump(d,f,indent=2,sort_keys=True); f.write("\n")
PYR
exit "$FAIL"
ROOT
  chmod 755 "$RUNROOT/work/compound_root.sh"; chown -R "$USERNAME":"$USERNAME" "$RUNROOT"
  nohup runuser -u "$USERNAME" -- /bin/bash "$RUNROOT/work/compound_root.sh" "$RUNROOT" "$DURATION" "$DISP" "$ATTEMPT" "$USERNAME" "$SCENARIO" "$REPETITION" "$SCENARIO_RUN_ID" "$FIXTURE_SEED" "$SPLIT" "$SCENARIO_NAME" "$LEAD_APP" "$RUN_ID" "$GLOBAL_ORDER" > "$RUNROOT/evidence/workload.stdout.txt" 2> "$RUNROOT/evidence/workload.stderr.txt" &
  for _ in $(seq 1 100); do [[ -s "$RUNROOT/work/root_pid.txt" ]] && break; sleep 0.1; done
  [[ -s "$RUNROOT/work/root_pid.txt" ]] || { echo root pid missing >&2; exit 11; }
  ROOTPID=$(cat "$RUNROOT/work/root_pid.txt"); kill -0 "$ROOTPID" 2>/dev/null || { echo root process not alive >&2; exit 12; }
  json_write "$RUNROOT/evidence/workload_prepare_receipt.json" status=PASS run_id="$RUN_ID" global_order="$GLOBAL_ORDER" scenario_id="$SCENARIO" scenario_name="$SCENARIO_NAME" split="$SPLIT" repetition="$REPETITION" scenario_run_id="$SCENARIO_RUN_ID" fixture_seed="$FIXTURE_SEED" lead_application="$LEAD_APP" duration_seconds="$DURATION" root_pid="$ROOTPID" all15_toolcheck_status=PASS toolcheck_count=15 executed_workload=false
  ;;
workload_run)
  ATTEMPT="$1"; RUNROOT="$2"; DURATION="$3"; CRED="$4"; USERNAME="$5"; SCENARIO="$6"; REPETITION="$7"; SCENARIO_RUN_ID="$8"; FIXTURE_SEED="$9"; SPLIT="${10}"; SCENARIO_NAME="${11}"; LEAD_APP="${12}"; RUN_ID="${13}"; GLOBAL_ORDER="${14}"
  [[ $ROOT_MODE -eq 1 ]] || run_as_root "$CRED" "$ATTEMPT" "$RUNROOT" "$DURATION" "$CRED" "$USERNAME" "$SCENARIO" "$REPETITION" "$SCENARIO_RUN_ID" "$FIXTURE_SEED" "$SPLIT" "$SCENARIO_NAME" "$LEAD_APP" "$RUN_ID" "$GLOBAL_ORDER"
  touch "$RUNROOT/work/START"; chown "$USERNAME":"$USERNAME" "$RUNROOT/work/START"
  deadline=$((SECONDS + DURATION + 20))
  while [[ ! -s "$RUNROOT/evidence/workload_run_receipt.json" && $SECONDS -lt $deadline ]]; do sleep 0.2; done
  [[ -s "$RUNROOT/evidence/workload_run_receipt.json" ]] || { echo workload receipt timeout >&2; exit 31; }
  python3 - "$RUNROOT/evidence/workload_run_receipt.json" "$SCENARIO" <<'PYC'
import json,sys
d=json.load(open(sys.argv[1],encoding="utf-8"))
assert d["status"]=="PASS"
assert d["scenario_id"]==sys.argv[2]
assert int(d["compound_task_count"])>=5
assert 60.0 <= float(d["active_duration_seconds"]) <= 65.0
assert float(d["root_lifecycle_seconds"]) <= 70.0
assert d.get("child_pid_absence_verified") is True
PYC
  ;;
# V25_UBUNTU_PACK_ROUTE: pack is implemented and validated by the frozen V6 base
# helper. Route it through the same root-aware entry point as telemetry modes.
telemetry_start|telemetry_finalize|pack)
  [[ -f "$BASE" ]] || { echo base helper missing >&2; exit 40; }
  exec /bin/bash "$BASE" "$MODE" "$@"
  ;;
*)
  echo "unsupported mode: $MODE" >&2
  exit 2
  ;;
esac
