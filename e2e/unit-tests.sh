#!/usr/bin/env bash
# Runs go test and says, by name, which tests hand the checks valid records and
# require them to pass, besides how many break or forge a record and require a
# refusal. CI runs it so the job summary shows both kinds.
#
#   e2e/unit-tests.sh TITLE [go test flags and packages]
#
# Prints the verbose test output (as go test -v would) and appends a Markdown
# summary headed TITLE to $GITHUB_STEP_SUMMARY, or prints it when that is unset.
# Exits with go test's status.
#
# The tests make their keys in a temporary directory and delete it when they
# finish; this script keeps nothing either.
set -euo pipefail

title=${1:?usage: e2e/unit-tests.sh TITLE [go test flags and packages]}
shift
log=$(mktemp)
trap 'rm -f "${log:?}"' EXIT

# A failing test must still get its summary, so go test's status is kept, not acted on.
set +e
go test -json "$@" | tee "$log" | jq -rj --unbuffered 'select(.Action == "output" or .Action == "build-output") | .Output'
status=${PIPESTATUS[0]}
set -e

summary=$(jq -rs --arg title "$title" '
  def name: sub("^\\S+ "; "");
  def list: map("- \(name)") | join("\n");
  # One result per test and per case, keyed by package so equal names in two
  # packages stay apart. A test with cases counts by its cases.
  ([ .[] | select(.Test != null and (.Action == "pass" or .Action == "fail" or .Action == "skip")) ]
    | map({key: (.Package + " " + .Test), value: .Action}) | from_entries) as $result
  | ($result | keys) as $all
  | [ $all[] | select(. as $n | $all | any(startswith($n + "/")) | not) ] as $leaves
  | [ $leaves[] | select($result[.] == "pass") ] as $passed
  | [ $leaves[] | select($result[.] == "fail") ] as $failed
  | [ $leaves[] | select($result[.] == "skip") ] as $skipped
  | [ $passed[] | select(test(" [^/]*(Passes|Accepts|Verifies|Reproduces)")) ] as $accepted
  # Why a test skipped: the first line it logged, as "file_test.go:12: message".
  | (reduce (.[] | select(.Action == "output" and .Test != null and (.Output | test("^\\s+\\S+_test\\.go:[0-9]+: "))))
       as $e ({}; ($e.Package + " " + $e.Test) as $k | if has($k) then . else .[$k] = ($e.Output | sub("^\\s+"; "") | rtrimstr("\n")) end)) as $why
  | [ "## \($title)",
    "",
    "**\($passed | length) passed, \($failed | length) failed, \($skipped | length) skipped** (each case of a test counted on its own).",
    "",
    "### Valid records accepted (\($accepted | length))",
    "",
    "Each hands a check the records a correct supply chain signs, with keys made for this run and deleted after it, and requires the check to pass.",
    "",
    (if ($accepted | length) > 0 then ($accepted | list) else "None in this run: the tests that build a chain need the bundles the e2e jobs produce." end),
    "",
    "### Other tests passed (\(($passed | length) - ($accepted | length)))",
    "",
    "Most change one record (a swapped die, an edited payload, a key of the wrong company, a level the evidence does not reach) and require the check to refuse it for that reason; a few test parsers and renderers.",
    "",
    "<details><summary>Names</summary>",
    "",
    ($passed - $accepted | list),
    "",
    "</details>",
    "",
    (if ($failed | length) > 0 then "### Failed\n\n" + ($failed | list) + "\n" else empty end),
    (if ($skipped | length) > 0 then
      "<details><summary>Skipped here (\($skipped | length)): each needs a bundle, tool or board this job does not have</summary>\n\n"
      + ($skipped | map("- \(name)" + (if $why[.] then ": \($why[.])" else "" end)) | join("\n"))
      + "\n\n</details>\n"
    else empty end)
  ] | join("\n")' "$log")

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  printf '%s\n' "$summary" >> "$GITHUB_STEP_SUMMARY"
else
  printf '\n%s\n' "$summary"
fi
exit "$status"
