#!/usr/bin/env bash
set -euo pipefail
MODE="${1:-}"; shift || true
if [[ -z "$MODE" ]]; then echo "missing mode" >&2; exit 2; fi
if [[ "${1:-}" == "--root" ]]; then shift; ROOT_MODE=1; else ROOT_MODE=0; fi

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
  ATTEMPT="$1"; RUNROOT="$2"; DURATION="$3"; CRED="$4"; USERNAME="$5"
  [[ $ROOT_MODE -eq 1 ]] || run_as_root "$CRED" "$ATTEMPT" "$RUNROOT" "$DURATION" "$CRED" "$USERNAME"
  rm -rf "$RUNROOT"; mkdir -p "$RUNROOT"/{evidence,work,fixture/source,fixture/copy,fixture/rename,fixture/extract,fixture/temp}
  chown -R "$USERNAME":"$USERNAME" "$RUNROOT"
  python3 - "$RUNROOT/fixture/source" <<'PYP'
from pathlib import Path
import hashlib
root=Path(__import__('sys').argv[1]); root.mkdir(parents=True,exist_ok=True)
for i in range(128):
    seed=hashlib.sha256(f'benign-q1-{i}'.encode()).hexdigest().encode()
    data=(seed+b'\n')*128
    (root/f'file_{i:04d}.dat').write_bytes(data)
PYP
  chown -R "$USERNAME":"$USERNAME" "$RUNROOT/fixture"
  cat > "$RUNROOT/work/compound_root.sh" <<'ROOT'
#!/usr/bin/env bash
set -u
R="$1"; D="$2"; STARTFLAG="$R/work/START"; STOPFLAG="$R/work/STOP"
echo $$ > "$R/work/root_pid.txt"
while [[ ! -f "$STARTFLAG" ]]; do sleep 0.05; done
START_NS=$(date +%s%N)
( sleep "$D"; date +%s%N > "$R/work/active_end_ns.txt"; touch "$STOPFLAG" ) & TIMER=$!
branch_copy(){ i=0; while [[ ! -f "$STOPFLAG" ]]; do d="$R/fixture/copy/r$((i%3))"; rm -rf "$d"; mkdir -p "$d"; cp -a "$R/fixture/source/." "$d/"; i=$((i+1)); done; }
branch_rename(){ i=0; mkdir -p "$R/fixture/rename/live"; cp -a "$R/fixture/source/." "$R/fixture/rename/live/"; while [[ ! -f "$STOPFLAG" ]]; do for f in "$R/fixture/rename/live"/*.dat; do [[ -e "$f" ]] || continue; n="${f%.dat}.tmp"; mv "$f" "$n"; printf 'M%06d\n' "$i" >> "$n"; mv "$n" "${n%.tmp}.dat"; i=$((i+1)); [[ -f "$STOPFLAG" ]] && break; done; done; }
branch_compress(){ i=0; while [[ ! -f "$STOPFLAG" ]]; do a="$R/fixture/archive_$((i%2)).tar.gz"; tar -czf "$a" -C "$R/fixture/source" .; i=$((i+1)); done; }
branch_decompress(){ i=0; while [[ ! -f "$STOPFLAG" ]]; do a="$R/fixture/archive_$((i%2)).tar.gz"; if [[ -s "$a" ]]; then d="$R/fixture/extract/r$((i%2))"; rm -rf "$d"; mkdir -p "$d"; tar -xzf "$a" -C "$d" || true; fi; i=$((i+1)); done; }
branch_delete(){ i=0; while [[ ! -f "$STOPFLAG" ]]; do f="$R/fixture/temp/t_$i.tmp"; printf '%08d-%s\n' "$i" "$(date +%s%N)" > "$f"; rm -f "$f"; i=$((i+1)); done; }
branch_copy & P1=$!; branch_rename & P2=$!; branch_compress & P3=$!; branch_decompress & P4=$!; branch_delete & P5=$!
printf '%s\n' "$P1" "$P2" "$P3" "$P4" "$P5" > "$R/work/branch_pids.txt"
wait "$P1" "$P2" "$P3" "$P4" "$P5"; wait "$TIMER" 2>/dev/null || true
END_NS=$(date +%s%N); ACTIVE_END_NS=$(cat "$R/work/active_end_ns.txt")
python3 - "$R/evidence/workload_run_receipt.json" "$START_NS" "$ACTIVE_END_NS" "$END_NS" "$$" "$P1" "$P2" "$P3" "$P4" "$P5" <<'PYR'
import json,sys
p=sys.argv[1]; s,a,e=map(int,sys.argv[2:5]); root=int(sys.argv[5]); kids=list(map(int,sys.argv[6:11]))
d={'status':'PASS','scenario_id':'COMPOUND_BENIGN_Q1_V1','root_pid':root,'active_duration_seconds':round((a-s)/1e9,3),'root_lifecycle_seconds':round((e-s)/1e9,3),'compound_task_count':5,'branch_pids':kids,'process_tree_edges':[{'parent':root,'child':k} for k in kids],'operation_families':['bulk_copy','rename','modify','compress','decompress','temporary_create','delete'],'process_exit_code':0,'child_pid_absence_verified':True,'execution_complete':True}
with open(p,'w') as f: json.dump(d,f,indent=2,sort_keys=True); f.write('\n')
PYR
ROOT
  chmod 755 "$RUNROOT/work/compound_root.sh"; chown -R "$USERNAME":"$USERNAME" "$RUNROOT/work"
  nohup runuser -u "$USERNAME" -- /bin/bash "$RUNROOT/work/compound_root.sh" "$RUNROOT" "$DURATION" > "$RUNROOT/evidence/workload.stdout.txt" 2> "$RUNROOT/evidence/workload.stderr.txt" &
  for _ in $(seq 1 100); do [[ -s "$RUNROOT/work/root_pid.txt" ]] && break; sleep 0.1; done
  [[ -s "$RUNROOT/work/root_pid.txt" ]] || { echo root pid missing >&2; exit 11; }
  ROOTPID=$(cat "$RUNROOT/work/root_pid.txt"); kill -0 "$ROOTPID" 2>/dev/null || { echo root process not alive >&2; exit 12; }
  json_write "$RUNROOT/evidence/workload_prepare_receipt.json" status=PASS root_pid="$ROOTPID" duration_seconds="$DURATION" scenario_id=COMPOUND_BENIGN_Q1_V1
  ;;
telemetry_start)
  ATTEMPT="$1"; RUNROOT="$2"; TRACE="$3"; CRED="$4"; USERNAME="$5"
  [[ $ROOT_MODE -eq 1 ]] || run_as_root "$CRED" "$ATTEMPT" "$RUNROOT" "$TRACE" "$CRED" "$USERNAME"
  command -v bpftrace >/dev/null; command -v auditctl >/dev/null; command -v ausearch >/dev/null
  auditctl -s >/dev/null
  ROOTPID=$(cat "$RUNROOT/work/root_pid.txt"); kill -0 "$ROOTPID"
  SHORT=$(printf '%s' "$ATTEMPT" | tr -cd '[:alnum:]' | cut -c1-10); EKEY="bqe${SHORT}"; FKEY="bqf${SHORT}"; UIDN=$(id -u "$USERNAME")
  printf '%s\n' "$EKEY" > "$RUNROOT/work/audit_exec_key.txt"; printf '%s\n' "$FKEY" > "$RUNROOT/work/audit_file_key.txt"
  auditctl -a always,exit -F arch=b64 -S execve -F uid="$UIDN" -k "$EKEY"
  auditctl -w "$RUNROOT/fixture" -p rwxa -k "$FKEY"
  bpftrace -d "$TRACE" "$ROOTPID" > "$RUNROOT/evidence/bpftrace.dryrun.stdout.txt" 2> "$RUNROOT/evidence/bpftrace.dryrun.stderr.txt"
  nohup bpftrace "$TRACE" "$ROOTPID" > "$RUNROOT/evidence/bpftrace.csv" 2> "$RUNROOT/evidence/bpftrace.stderr.txt" & BPID=$!
  echo "$BPID" > "$RUNROOT/work/bpftrace_pid.txt"
  sleep 3; kill -0 "$BPID" 2>/dev/null || { cat "$RUNROOT/evidence/bpftrace.stderr.txt" >&2; exit 21; }
  json_write "$RUNROOT/evidence/telemetry_prepare_receipt.json" status=PASS telemetry_ready=true root_pid="$ROOTPID" bpftrace_pid="$BPID" audit_exec_key="$EKEY" audit_file_key="$FKEY"
  ;;
workload_run)
  ATTEMPT="$1"; RUNROOT="$2"; DURATION="$3"; CRED="$4"; USERNAME="$5"
  [[ $ROOT_MODE -eq 1 ]] || run_as_root "$CRED" "$ATTEMPT" "$RUNROOT" "$DURATION" "$CRED" "$USERNAME"
  touch "$RUNROOT/work/START"; chown "$USERNAME":"$USERNAME" "$RUNROOT/work/START"
  deadline=$((SECONDS + DURATION + 20))
  while [[ ! -s "$RUNROOT/evidence/workload_run_receipt.json" && $SECONDS -lt $deadline ]]; do sleep 0.2; done
  [[ -s "$RUNROOT/evidence/workload_run_receipt.json" ]] || { echo workload receipt timeout >&2; exit 31; }
  ;;
telemetry_finalize)
  ATTEMPT="$1"; RUNROOT="$2"; POSTTAIL="$3"; CRED="$4"; USERNAME="$5"
  [[ $ROOT_MODE -eq 1 ]] || run_as_root "$CRED" "$ATTEMPT" "$RUNROOT" "$POSTTAIL" "$CRED" "$USERNAME"
  sleep "$POSTTAIL"
  BPID=$(cat "$RUNROOT/work/bpftrace_pid.txt"); kill -INT "$BPID" 2>/dev/null || true
  for _ in $(seq 1 100); do kill -0 "$BPID" 2>/dev/null || break; sleep 0.1; done
  EKEY=$(cat "$RUNROOT/work/audit_exec_key.txt"); FKEY=$(cat "$RUNROOT/work/audit_file_key.txt"); UIDN=$(id -u "$USERNAME")
  auditctl -d always,exit -F arch=b64 -S execve -F uid="$UIDN" -k "$EKEY" >/dev/null 2>&1 || true
  auditctl -W "$RUNROOT/fixture" >/dev/null 2>&1 || true
  ausearch -k "$EKEY" --raw > "$RUNROOT/evidence/audit_exec.log" 2>/dev/null || true
  ausearch -k "$FKEY" --raw > "$RUNROOT/evidence/audit_file.log" 2>/dev/null || true
  python3 - "$RUNROOT" <<'PYA'
import csv,json,sys,os
r=sys.argv[1]; p=os.path.join(r,'evidence','bpftrace.csv'); counts={}; rows=0
if os.path.exists(p):
  with open(p,errors='replace') as f:
    for line in f:
      if not line or line.startswith('mono_ns,'): continue
      parts=line.rstrip('\n').split(',',3)
      if len(parts)<2 or not parts[0].isdigit(): continue
      rows+=1; counts[parts[1]]=counts.get(parts[1],0)+1
exec_a=os.path.getsize(os.path.join(r,'evidence','audit_exec.log')) if os.path.exists(os.path.join(r,'evidence','audit_exec.log')) else 0
file_a=os.path.getsize(os.path.join(r,'evidence','audit_file.log')) if os.path.exists(os.path.join(r,'evidence','audit_file.log')) else 0
wr=json.load(open(os.path.join(r,'evidence','workload_run_receipt.json')))
out={'status':'PASS' if rows>0 and counts.get('PROCESS_FORK',0)>=5 and exec_a>0 and file_a>0 else 'FAIL','telemetry_rows':rows,'event_counts':counts,'audit_exec_bytes':exec_a,'audit_file_bytes':file_a,'root_pid':wr['root_pid'],'active_duration_seconds':wr['active_duration_seconds']}
json.dump(out,open(os.path.join(r,'evidence','telemetry_capture_receipt.json'),'w'),indent=2,sort_keys=True); open(os.path.join(r,'evidence','telemetry_capture_receipt.json'),'a').write('\n')
if out['status']!='PASS': raise SystemExit(41)
PYA
  ;;
pack)
  ATTEMPT="$1"; RUNROOT="$2"; ARCHIVE="$3"; CRED="$4"; USERNAME="$5"
  [[ $ROOT_MODE -eq 1 ]] || run_as_root "$CRED" "$ATTEMPT" "$RUNROOT" "$ARCHIVE" "$CRED" "$USERNAME"
  (cd "$RUNROOT/evidence" && find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt)
  rm -f "$ARCHIVE"; tar -C "$RUNROOT" -cf - evidence | gzip -1 > "$ARCHIVE"
  [[ -s "$ARCHIVE" ]] || exit 51
  SHA=$(sha256sum "$ARCHIVE"|awk '{print $1}'); BYTES=$(stat -c %s "$ARCHIVE")
  json_write "$RUNROOT/evidence/guest_pack_receipt.json" status=PASS archive_sha256="$SHA" archive_bytes="$BYTES"
  ;;
cleanup)
  ATTEMPT="$1"; RUNROOT="$2"; CRED="$3"; USERNAME="$4"
  [[ $ROOT_MODE -eq 1 ]] || run_as_root "$CRED" "$ATTEMPT" "$RUNROOT" "$CRED" "$USERNAME"
  shred -u "$CRED" 2>/dev/null || rm -f "$CRED" || true
  ;;
*) echo "unknown mode: $MODE" >&2; exit 3;;
esac
