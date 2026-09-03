//! PMS-1004: what an invoice line says about the work it bills.
//!
//! `create_invoice_from_time_entries` used to write `Time entry {uuid}` as the
//! description of every line it generated. That string is on the API, on the
//! detail page and on the PDF a customer receives, and a customer cannot read
//! a UUID as an account of what they are paying for. The row the builder locks
//! already carries the date, the work type, the ticket and the notes; this
//! module turns those into the sentence, and nothing else composes it.
//!
//! Pure functions, so the shape is pinned by unit tests rather than by an
//! invoice someone has to generate and look at.

use chrono::NaiveDate;

/// Notes longer than this are cut. An invoice line is a description, not the
/// technician's write-up, and the PDF truncates a cell with an ellipsis at a
/// far shorter width anyway (`crate::pdf`), so what is cut here would not have
/// been read there.
const MAX_NOTES_CHARS: usize = 120;

/// A ticket as an invoice line names it: its number and its title.
pub struct TicketRef<'a> {
    pub number: &'a str,
    pub title: &'a str,
}

/// The description of a time-entry line.
///
/// `{date} {work type}: {ticket number} {ticket title} - {notes}`, with the
/// ticket and the notes each present only when the entry has them, and no
/// colon when neither is. The first line of the notes only, cut at
/// [`MAX_NOTES_CHARS`] with an ellipsis, so a long write-up cannot turn a
/// line into a paragraph.
pub fn time_entry_line(
    date: NaiveDate,
    work_type: &str,
    ticket: Option<TicketRef<'_>>,
    notes: Option<&str>,
) -> String {
    let mut detail: Vec<String> = Vec::with_capacity(2);
    if let Some(ticket) = ticket {
        let number = ticket.number.trim();
        let title = ticket.title.trim();
        match (number.is_empty(), title.is_empty()) {
            (false, false) => detail.push(format!("{number} {title}")),
            (false, true) => detail.push(number.to_string()),
            (true, false) => detail.push(title.to_string()),
            (true, true) => {}
        }
    }
    if let Some(notes) = notes.and_then(first_line) {
        detail.push(notes);
    }
    let head = format!("{date} {}", work_type.trim());
    if detail.is_empty() {
        head
    } else {
        format!("{head}: {}", detail.join(" - "))
    }
}

/// The first non-blank line of a note, cut to [`MAX_NOTES_CHARS`].
fn first_line(notes: &str) -> Option<String> {
    let line = notes.lines().map(str::trim).find(|l| !l.is_empty())?;
    let mut chars = line.chars();
    let cut: String = chars.by_ref().take(MAX_NOTES_CHARS).collect();
    Some(if chars.next().is_some() {
        format!("{}...", cut.trim_end())
    } else {
        cut
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 8, 27).expect("date")
    }

    #[test]
    fn a_full_entry_names_the_date_work_type_ticket_and_notes() {
        let line = time_entry_line(
            day(),
            "Remote support",
            Some(TicketRef {
                number: "T000042",
                title: "Printer offline",
            }),
            Some("Rebooted the print spooler"),
        );
        assert_eq!(
            line,
            "2026-08-27 Remote support: T000042 Printer offline - Rebooted the print spooler"
        );
    }

    #[test]
    fn an_entry_with_neither_ticket_nor_notes_is_the_date_and_work_type() {
        assert_eq!(
            time_entry_line(day(), "  Remote support ", None, None),
            "2026-08-27 Remote support"
        );
        assert_eq!(
            time_entry_line(day(), "Remote support", None, Some("  \n\n ")),
            "2026-08-27 Remote support",
            "blank notes are no notes"
        );
    }

    #[test]
    fn a_ticket_alone_and_notes_alone_each_stand_by_themselves() {
        assert_eq!(
            time_entry_line(
                day(),
                "Remote support",
                Some(TicketRef {
                    number: "T000042",
                    title: "Printer offline",
                }),
                None,
            ),
            "2026-08-27 Remote support: T000042 Printer offline"
        );
        assert_eq!(
            time_entry_line(
                day(),
                "Remote support",
                None,
                Some("Rebooted the print spooler")
            ),
            "2026-08-27 Remote support: Rebooted the print spooler"
        );
    }

    #[test]
    fn only_the_first_line_of_the_notes_is_used_and_it_is_cut() {
        let long = format!("{}\nsecond line never appears", "x".repeat(200));
        let line = time_entry_line(day(), "Remote support", None, Some(&long));
        assert!(line.ends_with("..."), "{line}");
        assert!(!line.contains("second line"), "{line}");
        assert_eq!(
            line.chars().count(),
            "2026-08-27 Remote support: ".chars().count() + MAX_NOTES_CHARS + 3
        );
        let exact = "y".repeat(MAX_NOTES_CHARS);
        let line = time_entry_line(day(), "Remote support", None, Some(&exact));
        assert!(
            !line.ends_with("..."),
            "a note that fits is not cut: {line}"
        );
    }

    /// The reason this module exists.
    #[test]
    fn no_shape_contains_a_uuid() {
        let id = uuid::Uuid::new_v4().to_string();
        let line = time_entry_line(
            day(),
            "Remote support",
            Some(TicketRef {
                number: "T000042",
                title: "Printer offline",
            }),
            Some("notes"),
        );
        assert!(!line.contains(&id));
        assert!(!line.to_lowercase().contains("time entry"));
    }
}
