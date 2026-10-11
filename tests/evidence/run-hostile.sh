#!/bin/bash
# Hostile evidence runner: runs each probe through the FULL host binary stack
# and appends a commit-bound evidence record to hostile-results.jsonl.
# Usage: run-hostile.sh [probe...]   (default: all)
# Scope for every record here is "full-stack" (complete sandbox binary).
set -u
cd "$(dirname "$0")/../.."
REPO="$(pwd)"
BIN="$REPO/target/debug/litebox-organelle-host"
REV="$(git rev-parse HEAD)"
OUT="$REPO/tests/evidence/hostile-results.jsonl"
mkdir -p "$REPO/tests/evidence"

probe_manifest() {
  local probe="$1" timeout_s="$2"
  cat <<EOF
{
  "organelle_id": "hostile-$probe",
  "authority": "evidence-runner",
  "command": ["$REPO/tests/hostile/$probe"],
  "filesystem_allowlist": [],
  "network": "deny",
  "cpu_limit": 10,
  "memory_limit": 268435456,
  "timeout_secs": $timeout_s
}
EOF
}

run_probe() {
  local probe="$1" timeout_s="$2"
  local mfile; mfile="$(mktemp)"
  probe_manifest "$probe" "$timeout_s" > "$mfile"
  local out err; out="$(mktemp)"; err="$(mktemp)"
  local start end wall_ms exit_code
  start=$(date +%s%3N)
  timeout "$((timeout_s + 30))" "$BIN" run --manifest "$mfile" >"$out" 2>"$err"
  exit_code=$?
  end=$(date +%s%3N); wall_ms=$((end - start))
  # Extract receipt fields (best-effort).
  local exit_status digest timed_out
  exit_status=$(python3 -c "import json,sys; print(json.load(open('$out')).get('exit_status','<no-receipt>'))" 2>/dev/null || echo "<no-receipt>")
  digest=$(grep -o 'receipt digest: [0-9a-f]*' "$err" | awk '{print $3}')
  timed_out=$(python3 -c "import json,sys; print(json.load(open('$out')).get('timed_out','?'))" 2>/dev/null || echo "?")
  local guest_tail
  guest_tail=$(python3 - "$out" <<'PY' 2>/dev/null
import json,sys
r=json.load(open(sys.argv[1]))
print("artifact_hash="+r.get("artifact_hash","?")[:16])
PY
)
  # Guest stdout is not in the receipt; recover from workdir if kept (forensics).
  python3 - "$REV" "$probe" "$exit_code" "$exit_status" "$timed_out" "$wall_ms" "$digest" "$mfile" "$out" "$err" >> "$OUT" <<'PY'
import json,sys,hashlib
rev,probe,exit_code,exit_status,timed_out,wall_ms,digest,mfile,out,err = sys.argv[1:11]
def blob(p):
    try:
        d=open(p,'rb').read()
        return {"sha256":hashlib.sha256(d).hexdigest(),"bytes":len(d),"tail":d[-1500:].decode('utf-8','replace')}
    except Exception as e:
        return {"error":str(e)}
rec={
  "rev":rev,"probe":probe,"scope":"full-stack",
  "exit_code_host":int(exit_code),"receipt_exit_status":exit_status,
  "receipt_timed_out":timed_out,"wall_ms":int(wall_ms),
  "receipt_digest":digest or None,
  "manifest_sha256":blob(mfile)["sha256"],
  "receipt":blob(out),"stderr":blob(err),
}
print(json.dumps(rec))
PY
  rm -f "$mfile" "$out" "$err"
  echo "probe=$probe exit=$exit_code status=$exit_status timed_out=$timed_out wall=${wall_ms}ms"
}

PROBES="${*:-a_proc_mem b_raw_socket c_shim_socket d_write_outside e_mem_exhaust}"
# Rebuild every probe from current source: stale binaries prove nothing.
for p in $PROBES; do
  if [ -f "tests/hostile/$p.c" ]; then
    cc -O2 -o "tests/hostile/$p" "tests/hostile/$p.c" || { echo "BUILD FAILED: $p"; exit 1; }
  fi
done
for p in $PROBES; do
  case "$p" in
    c_shim_socket) T=12;;  # hangs on connect -> watchdog; keep suite fast
    *) T=25;;
  esac
  run_probe "$p" "$T"
done
echo "records appended to $OUT"
