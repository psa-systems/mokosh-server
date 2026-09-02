#!/usr/bin/env nu

# Keep transactional email body copy in the templates, not in Rust (PMS-700).
#
# `notification_templates` owns the copy for every dispatcher-delivered mail
# (seeded by migrations 021 / 023 / 028 / 096). Before PMS-700, `Mailer` also
# carried hard-coded `send_password_reset` / `send_welcome` bodies with the same
# wording, so which document a recipient received depended on whether the
# dispatcher was wired. Those helpers are gone; this check fails loud if the
# copy is reintroduced into the source tree.
#
# Exit 0 when no seeded body copy appears under src/, 1 (listing the hits)
# when it does.

# PMS-789 rewrote the product name in both bodies to `{{app_name}}` (migration
# 116), so the current copy is listed alongside the pre-789 wording. Dropping
# the old lines would stop catching a reintroduction of the literal, which is
# now doubly wrong: the name is operator-settable, so hardcoding it in Rust
# contradicts the setting as well as the template.
const PHRASES = [
    "We received a request to reset your {{app_name}} password"
    "An account has been created for you in {{app_name}}"
    "Reset your {{app_name}} password"
    "Welcome to {{app_name}}"
    "We received a request to reset your Mokosh password"
    "An account has been created for you in Mokosh"
    "Reset your Mokosh password"
    "Welcome to Mokosh"
]

def main [] {
    let hits = (
        glob src/**/*.rs
        | each {|f|
            let text = (open --raw $f | decode utf-8)
            $PHRASES | where {|p| $text | str contains $p } | each {|p| {file: $f, phrase: $p} }
        }
        | flatten
    )

    if ($hits | is-empty) {
        print $"mail copy OK: none of the ($PHRASES | length) seeded template phrases appear under src/"
    } else {
        print --stderr "ERROR: seeded notification-template copy duplicated in Rust source."
        print --stderr "The dispatcher renders these bodies from notification_templates; edit the"
        print --stderr "template (in a NEW migration) instead of re-adding a second copy here."
        print --stderr ($hits | table)
        exit 1
    }
}
