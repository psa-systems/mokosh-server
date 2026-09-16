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

# PMS-1198 (CF-9): unlike the auth mails above, the ticket-note body is a
# DELIBERATE second copy. `TicketService`'s no-dispatcher fallback (older test
# fixtures; no `NotificationsService` wired up) has no template to read, so it
# hand-builds the same sentence the seeded `ticket.note_added` template
# (migration 148) prints. The two must therefore keep saying the same thing,
# verbatim, or which document a client receives depends on how the service was
# constructed - exactly the gap that let migrations 104/110/148 rewrite this
# same row three times with nobody noticing the fallback had gone stale.
const TICKET_NOTE_SENTENCE = "has added an update to ticket"
const TICKET_NOTE_SEED_FILE = "migrations/148_restore_ticket_note_org_identity.sql"
const TICKET_NOTE_RUST_FILE = "src/modules/tickets/service.rs"

def check_ticket_note_parity [] {
    let seed_text = (open --raw $TICKET_NOTE_SEED_FILE | decode utf-8)
    let rust_text = (open --raw $TICKET_NOTE_RUST_FILE | decode utf-8)
    let in_seed = ($seed_text | str contains $TICKET_NOTE_SENTENCE)
    let in_rust = ($rust_text | str contains $TICKET_NOTE_SENTENCE)
    if $in_seed and $in_rust {
        null
    } else {
        {seed_file: $TICKET_NOTE_SEED_FILE, seed_has_it: $in_seed, rust_file: $TICKET_NOTE_RUST_FILE, rust_has_it: $in_rust}
    }
}

def main [] {
    let hits = (
        glob src/**/*.rs
        | each {|f|
            let text = (open --raw $f | decode utf-8)
            $PHRASES | where {|p| $text | str contains $p } | each {|p| {file: $f, phrase: $p} }
        }
        | flatten
    )

    let ticket_note_mismatch = (check_ticket_note_parity)

    mut ok = true

    if ($hits | is-empty) {
        print $"mail copy OK: none of the ($PHRASES | length) seeded template phrases appear under src/"
    } else {
        print --stderr "ERROR: seeded notification-template copy duplicated in Rust source."
        print --stderr "The dispatcher renders these bodies from notification_templates; edit the"
        print --stderr "template (in a NEW migration) instead of re-adding a second copy here."
        print --stderr ($hits | table)
        $ok = false
    }

    if ($ticket_note_mismatch == null) {
        print $"ticket-note copy OK: '($TICKET_NOTE_SENTENCE)' appears in both ($TICKET_NOTE_SEED_FILE) and ($TICKET_NOTE_RUST_FILE)"
    } else {
        print --stderr "ERROR: the ticket-note copy has diverged between its two sites."
        print --stderr $"The sentence '($TICKET_NOTE_SENTENCE)' must appear verbatim in both:"
        print --stderr $"  ($TICKET_NOTE_SEED_FILE) \(the seeded ticket.note_added template\)"
        print --stderr $"  ($TICKET_NOTE_RUST_FILE) \(the no-dispatcher fallback body\)"
        print --stderr ($ticket_note_mismatch | table)
        $ok = false
    }

    if not $ok {
        exit 1
    }
}
