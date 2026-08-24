#!/usr/bin/env nu

# PMS-906: find CI runs that outlived their own job bound.
#
# PMS-829 gave every job a `timeout-minutes`. That bounds a job against its own
# runaway; it does nothing about the runner not running it. On 2026-08-22, 26
# runs were created across every workflow between 20:26 and 22:49 and all of
# them finished inside a 1.1-minute window 27 hours later, every one reporting
# success. Nothing recorded that CI had been unavailable for a working day,
# because green runs raise no alarm.
#
# The signal this reports needs no new infrastructure and has no false
# positives by construction:
#
#   A run whose wall-clock time exceeds its own job's `timeout-minutes` is a
#   stall the bound did not catch.
#
# A job that legitimately hits its bound is cancelled and reports failure. A run
# that outlives its bound and still reports success was never actually bounded,
# because nothing was executing it.
#
# NOT part of `just check`, deliberately. It needs network access and a
# credential, and it answers a question about history rather than about the
# diff; a pull-request gate that depends on a remote API and a token is a flaky
# gate. `.forgejo/workflows/types-pin-drift.yml` in mokosh-apps is the
# precedent if this ever wants a scheduled, allowed-to-be-red run.
#
# Usage:
#   just ci-stalls                      # the default window
#   nu scripts/check-ci-stalls.nu 7     # a week
#   nu scripts/check-ci-stalls.nu --self-test
#
# Reads FORGEJO_TOKEN from the environment. A missing or unusable token is an
# error, not a pass: "I could not tell" and "nothing stalled" must not produce
# the same green result.

const HOST = 'https://dev.a8n.run'
const REPO = 'psa-systems/mokosh-server'
const WORKFLOW_DIR = '.forgejo/workflows'

# How many runs to read per API page, and how many pages at most. The API pages
# newest-first, so the window is trimmed by date after fetching rather than by
# asking the API for a range it does not offer.
const PAGE_SIZE = 50
const MAX_PAGES = 8

# `timeout-minutes` per job, keyed `<workflow file>::<job>`.
#
# Read from the workflow files rather than listed here, so the thresholds stay
# the ones PMS-829 justified in their own comments. A second copy in this script
# would be one more thing to keep in step, and the drift would be silent.
def job-bounds []: nothing -> record {
    let files = (glob $'($WORKFLOW_DIR)/*.yml')
    if ($files | is-empty) {
        print --stderr $"ERROR: no workflow files under ($WORKFLOW_DIR)."
        exit 1
    }
    $files
    | reduce --fold {} {|path, acc|
        let doc = (open --raw $path | decode utf-8 | from yaml)
        let name = ($path | path basename)
        let jobs = ($doc | get --optional jobs | default {})
        $jobs
        | columns
        | reduce --fold $acc {|job, inner|
            let bound = ($jobs | get $job | get --optional timeout-minutes)
            if $bound == null { $inner } else { $inner | upsert $'($name)::($job)' $bound }
        }
    }
}

# The tightest bound in a workflow file.
#
# The API reports a RUN, not a job, and a run can hold several jobs. Comparing
# against the smallest bound in the file is the conservative reading: it is the
# first moment at which some job in that run should have been cancelled. A file
# whose jobs are bounded 5 and 15 cannot legitimately take 20 minutes without
# one of them having been killed.
def workflow-bound [bounds: record, workflow: string]: nothing -> any {
    let mine = (
        $bounds
        | transpose key minutes
        | where {|row| ($row.key | split row '::' | first) == $workflow }
    )
    if ($mine | is-empty) { null } else { $mine | get minutes | math min }
}

def fetch-runs [token: string]: nothing -> list {
    mut all = []
    for page in 1..$MAX_PAGES {
        let url = $'($HOST)/api/v1/repos/($REPO)/actions/tasks?limit=($PAGE_SIZE)&page=($page)'
        let resp = (
            try {
                http get --headers [Authorization $'token ($token)'] $url
            } catch {|e|
                print --stderr $"ERROR: could not read the actions API: ($e.msg)"
                print --stderr 'A token that cannot answer is a failure, not a pass.'
                exit 1
            }
        )
        let runs = ($resp | get --optional workflow_runs | default [])
        if ($runs | is-empty) { break }
        $all = ($all | append $runs)
        if ($runs | length) < $PAGE_SIZE { break }
    }
    $all
}

# One row per run, with the wall clock the API implies and the bound it should
# have respected.
def classify [runs: list, bounds: record, since: datetime] {
    $runs
    | each {|run|
        let created = ($run.created_at | into datetime)
        if $created < $since { null } else {
            let started = ($run.run_started_at? | default $run.created_at | into datetime)
            # An unfinished run is measured against now, which is what makes a
            # stall visible while it is still happening rather than only after
            # it drains.
            let ended = (if $run.status in ['success' 'failure' 'cancelled' 'skipped'] {
                $run.updated_at | into datetime
            } else {
                date now
            })
            let minutes = (($ended - $started) / 1min)
            let bound = (workflow-bound $bounds $run.workflow_id)
            {
                workflow: $run.workflow_id,
                run: $run.run_number,
                status: $run.status,
                bound: $bound,
                minutes: ($minutes | math round --precision 1),
                created: ($run.created_at | into datetime | format date '%Y-%m-%d %H:%M'),
                finished: $ended,
                over: (if $bound == null { false } else { $minutes > $bound }),
            }
        }
    }
    | compact
}

def report [rows: list, days: int] {
    let unbounded = ($rows | where bound == null | get workflow | uniq)
    let stalled = ($rows | where over | sort-by minutes --reverse)

    if not ($unbounded | is-empty) {
        # Not a failure: a workflow with no bound cannot be judged, and saying
        # so is better than counting it as clean (PMS-829 bounded every job in
        # this repo, so this fires only if one is added without one).
        print --stderr $"NOTE: no `timeout-minutes` for ($unbounded | str join ', '); those runs were not checked."
    }

    if ($stalled | is-empty) {
        print $"ci-stalls OK: ($rows | length) runs in the last ($days) day\(s), none outlived its job bound"
        return
    }

    print --stderr $"ERROR: ($stalled | length) of ($rows | length) run\(s) in the last ($days) day\(s) outlived their job's timeout-minutes \(PMS-906\)."
    print --stderr 'A run that exceeds its bound and still reports success was never bounded:'
    print --stderr 'nothing was executing it. Suspect the runner or the forge, not the job.'
    print --stderr ''

    # Grouped by when they finished, not listed one per line. Runs that drain
    # together drained together: the 2026-08-22 stall was 183 runs finishing
    # inside a minute of each other, and printing that as 183 lines buries the
    # one fact worth having, which is that it was ONE event.
    let events = (
        $stalled
        | insert drained {|row| $row.finished | format date '%Y-%m-%d %H:%M' }
        | group-by drained
        | transpose drained runs
        | sort-by drained --reverse
    )
    for event in $events {
        let runs = $event.runs
        let workflows = ($runs | get workflow | uniq | sort | str join ', ')
        let longest = ($runs | get minutes | math max)
        let first_created = ($runs | get created | math min)
        print --stderr $"  drained ($event.drained): ($runs | length) run\(s), queued from ($first_created), worst ($longest) min"
        print --stderr $"    across ($workflows)"
        if ($runs | length) == 1 {
            let only = ($runs | first)
            print --stderr $"    ($only.workflow) #($only.run), ($only.minutes) min against a ($only.bound) min bound, status ($only.status)"
        }
    }
    print --stderr ''
    print --stderr 'Runs draining together inside a minute are one stall, not many: a job bound'
    print --stderr 'cannot catch that, because nothing was executing the job to be bounded.'
    exit 1
}

def main [
    days: int = 3        # how far back to look
    --self-test          # run against fixtures instead of the live API
] {
    if $self_test {
        self-test
        return
    }

    let token = ($env | get --optional FORGEJO_TOKEN | default '')
    if ($token | str trim | is-empty) {
        print --stderr 'ERROR: FORGEJO_TOKEN is not set, so this check cannot run.'
        print --stderr 'Failing rather than passing: "I could not tell" and "nothing stalled"'
        print --stderr 'must not look the same. Export a Forgejo application token and retry.'
        exit 1
    }

    let bounds = (job-bounds)
    let since = ((date now) - ($days * 1day))
    let rows = (classify (fetch-runs $token) $bounds $since)
    report $rows $days
}

# Fixtures rather than the live API: the behaviour under test is the
# classification, and a check that only works when the network and a credential
# are present cannot be run by whoever is trying to fix it.
def self-test [] {
    mut status = 0
    let bounds = {'check.yml::check': 30, 'e2e.yml::e2e': 20, 'create-release.yml::gate': 5, 'create-release.yml::create-release': 15}
    let since = ('2020-01-01T00:00:00Z' | into datetime)

    # The real 2026-08-22 shape: created in the evening, finished 27 hours
    # later, reporting success.
    let stalled = [{
        workflow_id: 'check.yml', run_number: 4258, status: 'success',
        created_at: '2026-08-22T20:30:00+02:00', run_started_at: '2026-08-22T20:30:00+02:00',
        updated_at: '2026-08-24T00:04:54+02:00',
    }]
    let rows = (classify $stalled $bounds $since)
    if ($rows | first | get over) {
        print 'self-test: a run that outlived its bound is reported'
    } else {
        print --stderr 'self-test: FAIL (the 27-hour stall was not flagged)'
        $status = 1
    }

    # A healthy run of the same workflow must not be flagged, or the check is
    # noise and nobody will run it twice.
    let healthy = [{
        workflow_id: 'check.yml', run_number: 4300, status: 'success',
        created_at: '2026-08-24T02:00:00+02:00', run_started_at: '2026-08-24T02:00:00+02:00',
        updated_at: '2026-08-24T02:05:00+02:00',
    }]
    let rows = (classify $healthy $bounds $since)
    if ($rows | first | get over) {
        print --stderr 'self-test: FAIL (a 5-minute run was flagged against a 30-minute bound)'
        $status = 1
    } else {
        print 'self-test: a healthy run is not flagged'
    }

    # A workflow with no bound cannot be judged. It must be reported as
    # unchecked rather than counted clean.
    let unbounded = [{
        workflow_id: 'unbounded.yml', run_number: 1, status: 'success',
        created_at: '2026-08-24T02:00:00+02:00', run_started_at: '2026-08-24T02:00:00+02:00',
        updated_at: '2026-08-25T02:00:00+02:00',
    }]
    let rows = (classify $unbounded $bounds $since)
    let row = ($rows | first)
    if $row.bound == null and (not $row.over) {
        print 'self-test: a workflow with no bound is left unjudged, not counted clean'
    } else {
        print --stderr 'self-test: FAIL (a workflow with no timeout-minutes was judged anyway)'
        $status = 1
    }

    # A run still going past its bound is the live case, and it is the one worth
    # catching while it can still be acted on.
    let running = [{
        workflow_id: 'e2e.yml', run_number: 4400, status: 'running',
        created_at: ((date now) - 3hr | format date '%+'),
        run_started_at: ((date now) - 3hr | format date '%+'),
        updated_at: ((date now) - 3hr | format date '%+'),
    }]
    let rows = (classify $running $bounds $since)
    if ($rows | first | get over) {
        print 'self-test: a run still going past its bound is reported, not only a finished one'
    } else {
        print --stderr 'self-test: FAIL (an in-flight stall was measured against its last update, not now)'
        $status = 1
    }

    # The bounds must come from the workflow files, not from a list in here.
    let real = (job-bounds)
    if ($real | columns | length) >= 6 {
        print $"self-test: bounds read from ($WORKFLOW_DIR) \(($real | columns | length) jobs)"
    } else {
        print --stderr $"self-test: FAIL \(expected every job in ($WORKFLOW_DIR) to carry a bound, got ($real | columns | length))"
        $status = 1
    }

    if $status == 0 {
        print 'ci-stalls self-test: clean'
    }
    exit $status
}
