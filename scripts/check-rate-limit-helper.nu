#!/usr/bin/env nu

# PMS-773: one function builds every 429 the product emits.
#
# `rate_limited_response` (src/utils/error.rs) writes the `rate_limited` body,
# the `Retry-After` header and the `no-store` directive together. Before this
# gate the same thirteen lines were hand-written in three route files and the
# fourth site agreed with none of them, because there was nothing importable to
# call. This fails a PR that:
#
#   - names TOO_MANY_REQUESTS outside src/utils/error.rs (a fifth hand-rolled
#     copy), or
#   - discards a computed wait with `let _ = retry_after`.

const HELPER_FILE = 'src/utils/error.rs'

def main [] {
    let violations = (
        glob src/**/*.rs
        | each {|f|
            let is_helper = ($f | str contains $HELPER_FILE)
            let lines = (open --raw $f | decode utf-8 | lines)
            $lines
            | enumerate
            | each {|row|
                let trimmed = ($row.item | str trim)
                let inline_429 = (
                    ($row.item | str contains 'TOO_MANY_REQUESTS')
                    and (not $is_helper)
                    and (not ($trimmed | str starts-with '//'))
                )
                let dropped_wait = ($row.item | str contains 'let _ = retry_after')
                let reason = if $inline_429 {
                    'builds a 429 outside the shared helper'
                } else if $dropped_wait {
                    'computes a retry delay and discards it'
                } else {
                    null
                }
                if ($reason == null) {
                    null
                } else {
                    {file: $f, line: ($row.index + 1), reason: $reason, code: $trimmed}
                }
            }
            | compact
        }
        | flatten
    )

    if ($violations | is-empty) {
        print $"rate-limit-helper OK: every 429 comes from rate_limited_response in ($HELPER_FILE)"
    } else {
        print --stderr "ERROR: a 429 is built outside the shared helper, or a computed wait is dropped (PMS-773)."
        print --stderr $"Call `crate::utils::error::rate_limited_response\(retry_after, message\)` instead: it"
        print --stderr "carries the Retry-After header, the retry_after_seconds field and Cache-Control: no-store"
        print --stderr "that every rate-limited surface already promises."
        print --stderr ($violations | table)
        exit 1
    }
}
