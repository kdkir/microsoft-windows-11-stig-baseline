#!/usr/bin/env bash
# Decide whether the pipeline check passes and print the CINC Auditor results.
#
# The check passes when CINC Auditor ran the profile to completion and
# produced JSON. Failed STIG controls are reported but do not fail the check;
# exit codes 0 (all passed), 100 (some failed) and 101 (some skipped) all mean
# the profile ran. Anything else, or missing JSON, fails the check.
#
# Usage: report-results.sh STATUS_JSON RESULTS_JSON
set -euo pipefail

status_file=$1
results_file=$2
summary=${GITHUB_STEP_SUMMARY:-/dev/stdout}

if [[ ! -s $status_file ]]; then
  echo "::error::The workstation did not report a status."
  exit 1
fi

exit_code=$(jq -r '.exit_code' "$status_file")
error=$(jq -r '.error // empty' "$status_file")

if [[ -n $error ]]; then
  echo "::error::Workstation reported an error: $error"
fi

case $exit_code in
  0 | 100 | 101) ;;
  *)
    echo "::error::CINC Auditor did not complete (exit code $exit_code)."
    exit 1
    ;;
esac

if ! jq -e '.profiles' "$results_file" >/dev/null 2>&1; then
  echo "::error::CINC Auditor finished but produced no readable JSON results."
  exit 1
fi

# Tally control outcomes. Enhanced outcomes adds error, not_applicable
# and not_reviewed on top of passed/failed/skipped.
counts=$(jq -r '
  [ .profiles[].controls[]
    | (.results // []) as $r
    | if   .status != null                             then .status
      elif ($r | length) == 0                          then "not_reviewed"
      elif any($r[]; .status == "failed")              then "failed"
      elif all($r[]; .status == "skipped")             then "skipped"
      else "passed" end ]
  | group_by(.) | map({key: .[0], value: length}) | from_entries' "$results_file")

{
  echo "## Windows 11 STIG scan"
  echo
  echo "CINC Auditor exit code: \`$exit_code\` ($(jq -r '.version' "$results_file"))"
  echo
  echo "| Outcome | Controls |"
  echo "|---|---|"
  jq -r 'to_entries[] | "| \(.key) | \(.value) |"' <<<"$counts"
  echo
  echo "Failed controls are reported only; they do not fail this check."
  echo "Full JSON is in the \`cinc-results\` build artifact."
} >>"$summary"

echo "::group::CINC Auditor JSON output"
jq . "$results_file"
echo "::endgroup::"

failed=$(jq -r '.failed // 0' <<<"$counts")
if [[ $failed -gt 0 ]]; then
  echo "::warning::$failed STIG controls failed on the workstation (reported only)."
fi
echo "Profile ran successfully; check passes."
