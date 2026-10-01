#!/usr/bin/env nu

# PMS-1426: print a Forgejo Actions job's log.
#
# This exists because the log looked unreachable for a long time and that
# belief, not the API, is what made CI triage guesswork. Every obvious route
# answers 404: `/actions/runs/<id>/logs` under the web UI,
# `/actions/runs/<id>/jobs/<n>/logs`, `/actions/tasks/<id>/logs`. The working
# one needs a JOB id, and a job id comes from a run, so it is two calls before
# the one that returns anything:
#
#   1. GET /api/v1/repos/<owner>/<repo>/actions/runs            -> run ids
#   2. GET /api/v1/repos/<owner>/<repo>/actions/runs/<id>/jobs  -> job ids
#   3. GET /api/v1/repos/<owner>/<repo>/actions/jobs/<id>/logs  -> the log
#
# Step 2 is the one that was missing. Forgejo here is 16.0.3+gitea-1.22.0.
#
# The token is the one `fj` already stores, so there is nothing to set up:
# ~/.local/share/forgejo-cli/keys.json -> hosts."dev.a8n.run".token.
#
#   nu scripts/ci-job-log.nu                      # the newest failing run
#   nu scripts/ci-job-log.nu --workflow check.yml  # newest failing check run
#   nu scripts/ci-job-log.nu --sha 47802a84        # that commit's failing run
#   nu scripts/ci-job-log.nu --run 47904           # a run id, whatever its status
#   nu scripts/ci-job-log.nu --list                # recent runs, no log
#
# Pipe it: `nu scripts/ci-job-log.nu | rg 'FAIL \['` is how PMS-1426 classified
# ten failures in one pass.

const HOST = "https://dev.a8n.run"
const REPO = "psa-systems/mokosh-server"

def token []: nothing -> string {
	let keys = ($nu.home-dir | path join ".local/share/forgejo-cli/keys.json")
	if not ($keys | path exists) {
		error make { msg: $"no forgejo-cli keys at ($keys); run `fj auth add-key` first" }
	}
	let host = ($HOST | str replace "https://" "")
	let entry = (open $keys | get hosts | get -o $host)
	if ($entry | is-empty) {
		error make { msg: $"forgejo-cli has no key for ($host)" }
	}
	$entry | get token
}

def api [path: string]: nothing -> any {
	http get --headers { Authorization: $"token (token)" } $"($HOST)/api/v1/repos/($REPO)($path)"
}

# Raw text, for the log route, which is not JSON.
def api-text [path: string]: nothing -> string {
	http get --raw --headers { Authorization: $"token (token)" } $"($HOST)/api/v1/repos/($REPO)($path)"
}

def recent-runs [workflow?: string]: nothing -> table {
	let runs = (api "/actions/runs?limit=50" | get workflow_runs)
	let runs = if ($workflow | is-empty) { $runs } else { $runs | where workflow_id == $workflow }
	$runs | select id workflow_id status started commit_sha prettyref
}

def main [
	--run: int			# a run id, used as-is whatever its status
	--sha: string		# a commit sha (any prefix); picks that commit's run
	--workflow: string	# a workflow filename, e.g. integration.yml
	--list				# print recent runs instead of a log
]: nothing -> any {
	if $list {
		return (recent-runs $workflow)
	}

	let run_id = if $run != null {
		$run
	} else {
		let runs = (recent-runs $workflow)
		let runs = if ($sha | is-empty) {
			$runs | where status == "failure"
		} else {
			$runs | where commit_sha =~ $"^($sha)"
		}
		if ($runs | is-empty) {
			error make { msg: "no matching run in the 50 most recent; pass --run <id>, or --list to look" }
		}
		$runs | first | get id
	}

	# A run holds one job per `jobs:` key. Prefer a failing one, because that is
	# what the caller is almost always after; fall back to the first so a green
	# run can still be read.
	let jobs = (api $"/actions/runs/($run_id)/jobs")
	if ($jobs | is-empty) {
		error make { msg: $"run ($run_id) has no jobs" }
	}
	let failing = ($jobs | where status == "failure")
	let job = (if ($failing | is-empty) { $jobs | first } else { $failing | first })
	print --stderr $"run ($run_id), job ($job.id) \"($job.name)\" [($job.status)]"
	api-text $"/actions/jobs/($job.id)/logs"
}
