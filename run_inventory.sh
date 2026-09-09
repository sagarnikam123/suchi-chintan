#!/usr/bin/env bash
#
# Run all inventory scanners for one AWS account, N at a time.
# Config comes from .env (see .env.example). Failures are warned but never
# stop the run — a broken scanner won't block the rest.
#
# Usage:
#   cp conf/.env.example conf/.env    # edit AWS_PROFILE, PARALLEL, etc.
#   ./run_inventory.sh
#
# Override .env inline:
#   AWS_PROFILE=myprofile PARALLEL=4 ./run_inventory.sh
#
set -uo pipefail   # NOT -e: one failing scanner must not abort the whole run

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INV_DIR="$HERE/inventory"
# The bash running THIS script (Homebrew 5.x). xargs must reuse it, not bare
# `bash` (= /bin/bash 3.2 on macOS), which fails to re-parse the exported
# run_one function (unicode/`(exit $code)` → "syntax error near `('").
BASH="${BASH:-$(command -v bash)}"

# --- load conf/.env — inline env vars WIN over the file (only set if unset) ---
if [[ -f "$HERE/conf/.env" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"                    # strip comments
    line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"  # trim
    [[ -z "$line" || "$line" != *=* ]] && continue
    key="${line%%=*}"; val="${line#*=}"
    key="${key%"${key##*[![:space:]]}"}"  # trim key
    val="${val#"${val%%[![:space:]]*}"}"  # trim leading space of value
    [[ -z "${!key:-}" ]] && export "$key=$val"   # only if not already set inline
  done < "$HERE/conf/.env"
fi

# --- parse CLI arguments (CLI flags override .env and env vars) ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--profile)
      AWS_PROFILE="$2"; shift 2 ;;
    -a|--account)
      ACCOUNT_ARG="$2"; shift 2 ;;
    -r|--region)
      AWS_REGION="$2"; shift 2 ;;
    -j|--parallel)
      PARALLEL="$2"; shift 2 ;;
    --only)
      ONLY="$2"; shift 2 ;;
    --skip)
      SKIP="$2"; shift 2 ;;
    *)
      shift ;;
  esac
done

# If -a is given without -p, try to resolve profile from accounts.yaml
if [[ -n "${ACCOUNT_ARG:-}" && -z "${AWS_PROFILE:-}" ]]; then
  RESOLVED_PROF=$(python3 -c "
from common import get_accounts
accts = get_accounts('$ACCOUNT_ARG')
if accts:
    print(accts[0].get('profile', ''))
" 2>/dev/null || true)
  [[ -n "$RESOLVED_PROF" ]] && AWS_PROFILE="$RESOLVED_PROF"
fi

# Use the AWS CLI [default] profile when no profile was supplied through
# the shell, conf/.env, -p/--profile, or account lookup.
AWS_PROFILE="${AWS_PROFILE:-default}"
export AWS_PROFILE
PARALLEL="${PARALLEL:-2}"
AWS_REGION="${AWS_REGION:-}"
ONLY="${ONLY:-}"
SKIP="${SKIP:-}"

# --- resolve account ID to store logs per account in output/_run_logs/<account_id>/ ---
ACCOUNT_ID=$(python3 -c "
import boto3
try:
    s = boto3.Session(profile_name='$AWS_PROFILE')
    print(s.client('sts').get_caller_identity()['Account'])
except Exception:
    print('')
" 2>/dev/null || true)

if [[ -n "$ACCOUNT_ID" ]]; then
  LOG_DIR="$HERE/output/_run_logs/$ACCOUNT_ID"
else
  LOG_DIR="$HERE/output/_run_logs/${AWS_PROFILE}"
fi

# --- build the script list ---
if [[ -n "$ONLY" ]]; then
  # explicit list from ONLY (comma-separated)
  IFS=',' read -r -a scripts <<< "$ONLY"
else
  scripts=()
  while IFS= read -r line; do scripts+=("$(basename "$line")"); done \
    < <(find "$INV_DIR" -maxdepth 1 -name 'get_*.py' | sort)
fi

# apply SKIP filter
if [[ -n "$SKIP" ]]; then
  IFS=',' read -r -a skiplist <<< "$SKIP"
  filtered=()
  for s in "${scripts[@]}"; do
    drop=0
    for sk in "${skiplist[@]}"; do [[ "$s" == "$(echo "$sk" | xargs)" ]] && drop=1; done
    [[ $drop -eq 0 ]] && filtered+=("$s")
  done
  scripts=("${filtered[@]}")
fi

mkdir -p "$LOG_DIR"
STATUS_DIR=$(mktemp -d -t aws_inv_status.XXXXXX)
trap 'rm -rf "$STATUS_DIR"' EXIT INT TERM

echo "============================================================"
echo "  suchi-chintan: AWS Inventory Runner"
echo "  Profile:   $AWS_PROFILE"
echo "  Region:    ${AWS_REGION:-<all>}"
echo "  Parallel:  $PARALLEL"
echo "  Scripts:   ${#scripts[@]}"
echo "  Logs:      $LOG_DIR"
echo "============================================================"

TOTAL="${#scripts[@]}"
START_TIME=$(date +%s)

# --- worker: runs one script, logs output, reports pass/fail (never exits nonzero) ---
# The index is assigned up front (dispatch order) and passed in — race-free,
# unlike a shared counter under parallel -P.
run_one() {
  local indexed="$1" profile="$2" region="$3" invdir="$4" logdir="$5" statusdir="$6" total="$7"
  local idx="${indexed%%:*}" script="${indexed#*:}"
  local name="${script%.py}"
  local log="$logdir/${name}.log"
  local status_file="$statusdir/${name}.status"
  local ra=(); [[ -n "$region" ]] && ra=(-r "$region")
  local extra_args=()
  if [[ "$script" == "get_s3_inventory.py" ]]; then
    extra_args=(--metrics)
  fi

  if python3 "$invdir/$script" -p "$profile" "${ra[@]}" "${extra_args[@]}" > "$log" 2>&1; then
    echo "ok" > "$status_file"
    echo "$idx/$total - ✅ $script"
  else
    local code=$?
    echo "fail:$code" > "$status_file"
    echo "$idx/$total - ⚠️  $script FAILED (exit $code) — see $log" >&2
    tail -n 3 "$log" | sed 's/^/       /' >&2
  fi
}
export -f run_one

# --- run PARALLEL at a time via xargs; failures don't stop the batch ---
# Prefix each script with its 1-based index ("3:get_ec2_inventory.py") so the
# worker can print "3/73" without a shared counter.
idx=0
for s in "${scripts[@]}"; do idx=$((idx+1)); printf '%s:%s\n' "$idx" "$s"; done \
  | xargs -P "$PARALLEL" -I {} "$BASH" -c \
      'run_one "$@"' _ {} "$AWS_PROFILE" "$AWS_REGION" "$INV_DIR" "$LOG_DIR" "$STATUS_DIR" "$TOTAL"

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

if [[ $ELAPSED -lt 60 ]]; then
  ELAPSED_STR="${ELAPSED}s"
elif [[ $ELAPSED -lt 3600 ]]; then
  ELAPSED_STR="$((ELAPSED / 60))m $((ELAPSED % 60))s"
else
  ELAPSED_STR="$((ELAPSED / 3600))h $(((ELAPSED % 3600) / 60))m $((ELAPSED % 60))s"
fi

echo "============================================================"
# --- summary from runtime status ---
pass=0; fail=0; failed_names=()
for s in "${scripts[@]}"; do
  status_file="$STATUS_DIR/${s%.py}.status"
  if [[ -f "$status_file" && "$(cat "$status_file")" == "ok" ]]; then
    ((pass++))
  else
    ((fail++)); failed_names+=("$s")
  fi
done
echo "  Done:       $pass ok, $fail with errors"
if [[ $fail -gt 0 ]]; then
  echo "  Failed scripts:"
  printf '    %s\n' "${failed_names[@]}"
fi
echo "  Total Time: $ELAPSED_STR"
echo "============================================================"
