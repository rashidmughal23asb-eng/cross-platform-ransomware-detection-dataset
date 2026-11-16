#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"; SCENARIO="${2:-}"; ATTEMPT="${3:-0000000000000000}"; RUNROOT="${4:-}"; DURATION="${5:-60}"; RECEIPT="${6:-}"; REP="${7:-A}"; USERNAME="${8:-${SUDO_USER:-$(id -un)}}"; SEED="${9:-}"
[[ "$MODE" =~ ^(toolcheck|prepare|run)$ ]] || { echo "BAD_MODE" >&2; exit 2; }
[[ "$SCENARIO" =~ ^S(0[1-9]|1[0-5])$ ]] || { echo "BAD_SCENARIO" >&2; exit 2; }
[[ "$REP" =~ ^(A|B)$ ]] || { echo "BAD_REPETITION" >&2; exit 2; }
[[ -n "$RECEIPT" ]] || { echo "RECEIPT_REQUIRED" >&2; exit 2; }
[[ -n "$RUNROOT" ]] || RUNROOT="/tmp/benign_scenario/${ATTEMPT}/${SCENARIO}_${REP}"
[[ -n "$SEED" ]] || SEED="${SCENARIO}-UBU-${REP}"

json_write(){
  local path="$1"; shift
  python3 - "$path" "$@" <<'PY'
import json,sys
p=sys.argv[1]; d={}
for item in sys.argv[2:]:
    k,v=item.split("=",1)
    if v in ("true","false"): v=(v=="true")
    else:
        try: v=int(v)
        except:
            try: v=float(v)
            except: pass
    d[k]=v
with open(p,"w",encoding="utf-8") as f: json.dump(d,f,indent=2,sort_keys=True); f.write("\n")
PY
}
scenario_name(){ case "$1" in
S01) echo BULK_MIGRATION;; S02) echo RESILIENT_SYNC;; S03) echo ARCHIVE_ROTATION;; S04) echo HIGH_DENSITY_ARCHIVE;;
S05) echo REPOSITORY_CHURN;; S06) echo SCRIPTED_ETL;; S07) echo MEDIA_PIPELINE;; S08) echo DATABASE_MAINTENANCE;;
S09) echo OFFICE_AUTOSAVE_EXPORT;; S10) echo BUILD_CONFIGURE;; S11) echo PARALLEL_BUILD;; S12) echo PACKAGE_STAGING;;
S13) echo TEXT_REWRITE;; S14) echo INSTALLER_PACKAGE_MAINTENANCE;; S15) echo SEQUENTIAL_IO_ROTATION;; esac; }
lead_name(){ case "$1" in
S01) echo cp;; S02) echo rsync;; S03) echo tar;; S04) echo 7-Zip;; S05) echo git;; S06) echo Python;;
S07) echo FFmpeg;; S08) echo SQLite;; S09) echo LibreOffice;; S10) echo CMake;; S11) echo Ninja;; S12) echo gzip;;
S13) echo sed;; S14) echo dpkg;; S15) echo dd;; esac; }
resolve_tool(){ case "$1" in
S01) command -v cp;; S02) command -v rsync;; S03) command -v tar;; S04) command -v 7z || command -v 7zz;;
S05) command -v git;; S06) command -v python3;; S07) command -v ffmpeg;; S08) command -v sqlite3;;
S09) command -v libreoffice || command -v soffice;; S10) command -v cmake;; S11) command -v ninja;;
S12) command -v gzip;; S13) command -v sed;; S14) command -v dpkg;; S15) command -v dd;; esac; }

NAME="$(scenario_name "$SCENARIO")"; LEAD="$(lead_name "$SCENARIO")"
mkdir -p "$(dirname "$RECEIPT")"

if [[ "$MODE" == "toolcheck" ]]; then
  TOOL="$(resolve_tool "$SCENARIO" 2>/dev/null || true)"
  EXTRA_PASS=true
  if [[ "$SCENARIO" == "S14" ]]; then command -v dpkg-deb >/dev/null 2>&1 || EXTRA_PASS=false; fi
  STATUS=PASS; [[ -n "$TOOL" && "$EXTRA_PASS" == true ]] || STATUS=FAIL
  json_write "$RECEIPT" "schema_version=1.0" "gate=SCENARIO_TOOLCHECK" "status=$STATUS" "os=Ubuntu" "scenario_id=$SCENARIO" "scenario_name=$NAME" "lead_application=$LEAD" "tool_path=${TOOL:-}" "executed_workload=false"
  [[ "$STATUS" == PASS ]] || exit 2
  exit 0
fi

SRC="$RUNROOT/fixture/source"; ASSETS="$RUNROOT/assets"; LEADROOT="$RUNROOT/lead"; MUT="$RUNROOT/mutation"; ROT="$RUNROOT/rotation"; WORK="$RUNROOT/work"
if [[ "$MODE" == "prepare" ]]; then
  [[ ! -e "$RUNROOT" ]] || { echo "SCENARIO_WORK_ROOT_ALREADY_EXISTS" >&2; exit 3; }
  mkdir -p "$SRC" "$ASSETS" "$LEADROOT" "$MUT" "$ROT" "$WORK"
  python3 - "$SRC" "$SEED" <<'PY'
from pathlib import Path
import hashlib,sys
root=Path(sys.argv[1]); seed=sys.argv[2]
for d in range(8):
    sub=root/f"set_{d:02d}"; sub.mkdir(parents=True,exist_ok=True)
    for i in range(32):
        h=hashlib.sha256(f"{seed}:{d}:{i}".encode()).digest()
        data=(h*256)[:8192]
        (sub/f"file_{i:03d}.bin").write_bytes(data)
PY
  for n in 1 2 3; do printf '<html><body><h1>Benign Scenario %s</h1><p>Deterministic office export.</p></body></html>\n' "$n" > "$ASSETS/document_0${n}.html"; done
  python3 - "$ASSETS/rewrite.txt" <<'PY'
import sys
with open(sys.argv[1],"w",encoding="utf-8") as f:
    for i in range(256): f.write(f"benign source line {i}\n")
PY
  cat > "$ASSETS/etl.py" <<'PY'
import pathlib,sys,hashlib
src=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2]); out.mkdir(parents=True,exist_ok=True)
for p in sorted(src.rglob("*.bin"))[:128]:
    (out/(p.stem+".txt")).write_text(hashlib.sha256(p.read_bytes()).hexdigest()+"\n",encoding="utf-8")
PY
  mkdir -p "$ASSETS/cmake_project" "$ASSETS/ninja_project"
  cat > "$ASSETS/cmake_project/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.16)
project(Benign NONE)
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/generated.txt" CONTENT "benign-generated\n")
EOF
  cp "$SRC/set_00/file_000.bin" "$ASSETS/ninja_project/input.bin"
  cat > "$ASSETS/ninja_project/build.ninja" <<'EOF'
rule copyfile
  command = cp input.bin output.bin
build output.bin: copyfile input.bin
default output.bin
EOF
  TOOL="$(resolve_tool "$SCENARIO")"
  if [[ "$SCENARIO" == "S05" ]]; then
    cp -a "$SRC/set_00/." "$ASSETS/repo"; git -C "$ASSETS/repo" init -q; git -C "$ASSETS/repo" config user.email benign@example.invalid; git -C "$ASSETS/repo" config user.name "Benign Scenario"; git -C "$ASSETS/repo" add -A; git -C "$ASSETS/repo" commit -qm baseline
  fi
  if [[ "$SCENARIO" == "S08" ]]; then sqlite3 "$ASSETS/scenario.db" "CREATE TABLE IF NOT EXISTS t(id INTEGER PRIMARY KEY,v TEXT); INSERT INTO t(v) VALUES('baseline');"; fi
  if [[ "$SCENARIO" == "S14" ]]; then
    PKGROOT="$ASSETS/debroot"; mkdir -p "$PKGROOT/DEBIAN" "$PKGROOT/opt/benign-s14"
    cat > "$PKGROOT/DEBIAN/control" <<'EOF'
Package: benign-s14
Version: 1.0
Section: misc
Priority: optional
Architecture: all
Maintainer: Benign Scenario <benign@example.invalid>
Description: deterministic benign package-maintenance fixture
EOF
    cp "$SRC/set_00/file_000.bin" "$PKGROOT/opt/benign-s14/payload.bin"
    dpkg-deb --build "$PKGROOT" "$ASSETS/benign-s14.deb" >/dev/null
  fi
  chown -R "$USERNAME":"$USERNAME" "$RUNROOT" 2>/dev/null || true
  BYTES=$(du -sb "$SRC" | awk '{print $1}')
  json_write "$RECEIPT" "schema_version=1.0" "gate=SCENARIO_WORKLOAD_PREPARE" "status=PASS" "os=Ubuntu" "scenario_id=$SCENARIO" "scenario_name=$NAME" "lead_application=$LEAD" "repetition=$REP" "fixture_seed=$SEED" "duration_seconds=$DURATION" "fixture_bytes=$BYTES" "tool_path=$TOOL" "executed=false"
  echo "SCENARIO_PREPARE=PASS OS=Ubuntu SCENARIO=$SCENARIO LEAD=$LEAD"
  exit 0
fi

# RUN mode
[[ -d "$SRC" ]] || { echo "SOURCE_FIXTURE_MISSING" >&2; exit 4; }
STOP="$WORK/STOP"; rm -f "$STOP"; ROOT_PID=$$; START_NS=$(date +%s%N)
( sleep "$DURATION"; date +%s%N > "$WORK/active_end_ns.txt"; touch "$STOP" ) & TIMER=$!

lead_branch(){
  local i=0 TOOL; TOOL="$(resolve_tool "$SCENARIO")"
  while [[ ! -f "$STOP" ]]; do
    i=$((i+1))
    case "$SCENARIO" in
      S01) d="$LEADROOT/copy_$i"; rm -rf "$d"; mkdir -p "$d"; cp -a "$SRC/." "$d/";;
      S02) d="$LEADROOT/mirror"; mkdir -p "$d"; printf 'iteration=%s\n' "$i" > "$SRC/sync_marker.txt"; [[ $i -gt 1 ]] && printf stale > "$d/stale.tmp"; rsync -a --delete "$SRC/" "$d/"; printf 'iteration=%s\n' "$i" >> "$LEADROOT/sync.log"; if [[ $(stat -c %s "$LEADROOT/sync.log") -gt 2048 ]]; then mv "$LEADROOT/sync.log" "$LEADROOT/sync_$i.log"; fi;;
      S03) a="$LEADROOT/a_$i.tar.gz"; d="$LEADROOT/x_$i"; rm -rf "$d"; mkdir -p "$d"; tar -czf "$a" -C "$SRC" .; tar -xzf "$a" -C "$d"; mv "$a" "$LEADROOT/rotated_$i.tar.gz";;
      S04) a="$LEADROOT/a_$i.7z"; d="$LEADROOT/x_$i"; rm -rf "$d"; mkdir -p "$d"; "$TOOL" a -y -mx=1 "$a" "$SRC"/* >/dev/null; "$TOOL" x -y "-o$d" "$a" >/dev/null;;
      S05) printf 'iteration=%s\n' "$i" > "$ASSETS/repo/churn.txt"; git -C "$ASSETS/repo" add -A; git -C "$ASSETS/repo" commit --allow-empty -qm "churn_$i"; git -C "$ASSETS/repo" archive --format=tar.gz -o "$LEADROOT/worktree_$i.tar.gz" HEAD; if (( i % 3 == 0 )); then git -C "$ASSETS/repo" reset --hard HEAD~1 >/dev/null; fi;;
      S06) d="$LEADROOT/etl_$i"; python3 "$ASSETS/etl.py" "$SRC" "$d";;
      S07) o="$LEADROOT/tone_$i.wav"; ffmpeg -hide_banner -loglevel error -f lavfi -i "sine=frequency=$((500+i%500)):duration=1" -y "$o";;
      S08) b="$LEADROOT/backup_$i.db"; rm -f "$b"; sqlite3 "$ASSETS/scenario.db" "INSERT INTO t(v) VALUES('run_$i'); UPDATE t SET v='updated_$i' WHERE id=(SELECT max(id) FROM t); DELETE FROM t WHERE id < (SELECT max(id)-100 FROM t); VACUUM INTO '$b';";;
      S09) d="$LEADROOT/export_$i"; mkdir -p "$d"; for doc in "$ASSETS"/document_*.html; do "$TOOL" --headless --convert-to pdf --outdir "$d" "$doc" >/dev/null 2>&1; done;;
      S10) d="$LEADROOT/build_$i"; cmake -S "$ASSETS/cmake_project" -B "$d" -G Ninja >/dev/null;;
      S11) rm -f "$ASSETS/ninja_project/output.bin"; ninja -C "$ASSETS/ninja_project" -f build.ninja -j 4 >/dev/null; cp "$ASSETS/ninja_project/output.bin" "$LEADROOT/artifact_$i.bin";;
      S12) a="$LEADROOT/pkg_$i.gz"; o="$LEADROOT/unpacked_$i.bin"; gzip -c "$SRC/set_00/file_000.bin" > "$a"; gzip -dc "$a" > "$o";;
      S13) o="$LEADROOT/rewrite_$i.txt"; sed "s/benign/benign_$i/g" "$ASSETS/rewrite.txt" > "$o"; cp "$o" "$LEADROOT/rewrite_copy_$i.txt";;
      S14) dpkg-deb --extract "$ASSETS/benign-s14.deb" "$LEADROOT/stage_$i" >/dev/null;;
      S15) o="$LEADROOT/io_$i.bin"; dd if=/dev/zero of="$o" bs=1M count=4 conv=fsync status=none; cp "$o" "$LEADROOT/io_copy_$i.bin"; mv "$LEADROOT/io_copy_$i.bin" "$LEADROOT/io_rotated_$i.bin"; gzip -f "$LEADROOT/io_rotated_$i.bin";;
    esac
    if (( i > 2 )); then find "$LEADROOT" -maxdepth 1 -mindepth 1 -type d -name "*_$((i-2))" -exec rm -rf {} + 2>/dev/null || true; fi
  done
  printf '%s\n' "$i" > "$WORK/lead_iterations.txt"
}
mutation_branch(){
  local i=0 LIVE="$MUT/live"; mkdir -p "$LIVE"; cp -a "$SRC/set_00/." "$LIVE/"
  while [[ ! -f "$STOP" ]]; do
    i=$((i+1))
    for f in "$LIVE"/*.bin; do [[ -e "$f" ]] || continue; mv "$f" "$f.wrk"; printf 'patch-%s\n' "$i" >> "$f.wrk"; mv "$f.wrk" "$f"; [[ -f "$STOP" ]] && break; done
  done
  printf '%s\n' "$i" > "$WORK/mutation_iterations.txt"
}
rotation_branch(){
  local i=0
  while [[ ! -f "$STOP" ]]; do
    i=$((i+1)); a="$ROT/r_$i.tar.gz"; d="$ROT/x_$i"; rm -rf "$d"; mkdir -p "$d"; tar -czf "$a" -C "$SRC/set_01" .; tar -xzf "$a" -C "$d"
    if (( i > 1 )); then rm -rf "$ROT/x_$((i-1))" "$ROT/r_$((i-1)).tar.gz"; fi
  done
  printf '%s\n' "$i" > "$WORK/rotation_iterations.txt"
}

lead_branch & P1=$!; mutation_branch & P2=$!; rotation_branch & P3=$!
FAIL=0
wait "$P1" || FAIL=1
wait "$P2" || FAIL=1
wait "$P3" || FAIL=1
wait "$TIMER" 2>/dev/null || true
[[ $FAIL -eq 0 ]] || { echo "SCENARIO_BRANCH_FAILURE" >&2; exit 5; }
END_NS=$(date +%s%N); ACTIVE_END_NS=$(cat "$WORK/active_end_ns.txt")
python3 - "$RECEIPT" "$SCENARIO" "$NAME" "$LEAD" "$REP" "$SEED" "$START_NS" "$ACTIVE_END_NS" "$END_NS" "$ROOT_PID" "$P1" "$P2" "$P3" <<'PY'
import json,sys
p,scenario,name,lead,rep,seed=sys.argv[1:7]
s,a,e=map(int,sys.argv[7:10]); root=int(sys.argv[10]); kids=list(map(int,sys.argv[11:14]))
ops={
"S01":["bulk_copy","rename","modify","compress","decompress","temporary_create","delete"],
"S02":["sync","mirror","modify","stale_cleanup","archive_rotation","log_rotation"],
"S03":["archive_create","archive_extract","rename_rotation","bulk_copy","cleanup"],
"S04":["parallel_archive","extract","rename","copy","temporary_delete"],
"S05":["checkout","reset","generated_file_churn","archive_worktree","cleanup"],
"S06":["generate","transform","rename","copy","compress","temporary_cleanup"],
"S07":["transcode","rename","copy","archive","temporary_delete"],
"S08":["insert","update","delete","backup","vacuum","archive_rotation"],
"S09":["document_save","export","rename","copy","archive","cleanup"],
"S10":["configure","generate","output_churn","copy","archive","clean"],
"S11":["parallel_build","rebuild","artifact_rename","copy","archive","clean"],
"S12":["package","compress","extract","decompress","rename_rotation","cleanup"],
"S13":["text_rewrite","rename","copy","compress","temporary_delete"],
"S14":["package_extract","staging","rename","copy","temporary_cleanup"],
"S15":["sequential_write","copy","rename","compression","delete","rotation"]}[scenario]
d={"schema_version":"3.0","gate":"SCENARIO_WORKLOAD_RUN","status":"PASS","os":"Ubuntu","class":"BENIGN","ground_truth":"BENIGN",
"scenario_id":scenario,"scenario_name":name,"scenario_type":"application_led_compound_benign","lead_application":lead,"repetition":rep,"fixture_seed":seed,
"active_duration_target_seconds":round((a-s)/1e9,3),"active_duration_seconds":round((a-s)/1e9,3),"root_lifecycle_seconds":round((e-s)/1e9,3),
"root_pid":root,"root_process_name":"bash","process_exit_code":0,"execution_complete":True,"observation_status":"COMPLETE",
"compound_task_count":3,"branch_pids":kids,"target_pids":[root]+kids,"process_tree_edges":[{"parent":root,"child":k} for k in kids],
"operation_families":ops,"network_used":False}
with open(p,"w",encoding="utf-8") as f: json.dump(d,f,indent=2,sort_keys=True); f.write("\n")
PY
echo "SCENARIO_RUN=PASS OS=Ubuntu SCENARIO=$SCENARIO LEAD=$LEAD ROOT_PID=$ROOT_PID"
exit 0
