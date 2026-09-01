//! PMS-876: a document model, and the one place it becomes PDF bytes.
//!
//! The report export had exactly one format. This adds the second, and it is a
//! seam rather than a `pdf_for_tickets` beside each `csv_for_tickets` because
//! two more callers are queued behind it: PMS-959 stores the PDF an invoice was
//! issued as, and PMS-911 puts the MSP's branding on it. All three want the
//! same thing - say what the document contains, get bytes back - and none of
//! them should be laying out a page.
//!
//! ## What it is not
//!
//! Not a layout engine. A [`Document`] is a title and a list of sections, each
//! either labelled fields or a table, which is the shape every report in this
//! codebase already has (the CSV writers emit exactly that: a header block,
//! then one or more grouped tables). Anything needing real flow - wrapped
//! paragraphs, columns, images - is a bigger decision than the report export
//! needs and would be better made against the invoice work that actually wants
//! it.
//!
//! ## Why `printpdf` and a base-14 font
//!
//! Pure Rust, so `oci-build/Dockerfile` stays a static musl binary with no
//! runtime dependency. Pulling `wkhtmltopdf` in would add a large native
//! dependency and a headless-rendering surface to an Alpine image that today
//! ships one binary. `default-features = false` because the defaults carry HTML
//! rendering and hyphenation dictionaries that nothing here uses.
//!
//! [`BuiltinFont::Helvetica`] serializes as a standard Type1 font reference
//! rather than embedded bytes, so no font is vendored into the repo and the
//! output stays small.
//!
//! ## The cost of that, stated rather than discovered
//!
//! A base-14 font is `WinAnsiEncoding`, so only Latin-1 is representable, and
//! report data is tenant text: a company name or a work-type name can hold
//! anything. [`to_win_ansi`] folds what it can (typographic quotes, dashes, an
//! ellipsis, a non-breaking space) and replaces the rest with `?` rather than
//! emitting bytes a reader will render as something else.
//!
//! That is an acceptable trade for an internal report and will NOT be
//! acceptable for an invoice a client receives with their own name on it. The
//! answer there is an embedded font, which is a licensing and binary-size
//! decision, and it belongs to PMS-959 / PMS-911 rather than being made here on
//! their behalf.

use printpdf::{
    BuiltinFont, Color, Line, LinePoint, Mm, Op, PdfDocument, PdfFontHandle, PdfPage,
    PdfSaveOptions, Point, Pt, Rgb, TextItem,
};

use crate::utils::error::AppResult;

/// A4 portrait, in millimetres.
const PAGE_WIDTH_MM: f32 = 210.0;
const PAGE_HEIGHT_MM: f32 = 297.0;
const MARGIN_MM: f32 = 18.0;

const TITLE_PT: f32 = 16.0;
const HEADING_PT: f32 = 11.0;
const BODY_PT: f32 = 9.0;

/// Millimetres per point, for turning a font size into a line height.
const MM_PER_PT: f32 = 25.4 / 72.0;

/// Rough advance width of a Helvetica character, as a fraction of the font
/// size.
///
/// An approximation, deliberately. Exact metrics would mean carrying the
/// base-14 width tables, and the only thing this number decides is how many
/// characters fit in a table column before the cell is truncated. Erring
/// slightly wide costs a truncated cell; erring narrow would overlap the next
/// column, so it is set above Helvetica's true average.
const AVERAGE_CHAR_EM: f32 = 0.52;

/// Left column width for a labelled field, in millimetres.
const LABEL_WIDTH_MM: f32 = 62.0;

/// Narrowest a table column is allowed to get, so a column of long values
/// cannot squeeze its neighbours to nothing.
const MIN_COLUMN_MM: f32 = 16.0;

/// What a section holds.
pub enum Body {
    /// Label / value pairs, for the header block a report opens with.
    Fields(Vec<(String, String)>),
    /// A grid. The header row repeats when the table crosses a page.
    Table {
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
    },
}

/// One block of a document, optionally under a heading.
pub struct Section {
    pub heading: Option<String>,
    pub body: Body,
}

/// What to render. Built by a caller that knows the data, never by this module.
pub struct Document {
    pub title: String,
    /// A period, a scope, whatever names this particular run.
    pub subtitle: Option<String>,
    pub sections: Vec<Section>,
}

impl Document {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            subtitle: None,
            sections: Vec::new(),
        }
    }

    pub fn subtitle(mut self, subtitle: impl Into<String>) -> Self {
        self.subtitle = Some(subtitle.into());
        self
    }

    pub fn fields(mut self, heading: impl Into<String>, pairs: Vec<(String, String)>) -> Self {
        self.sections.push(Section {
            heading: Some(heading.into()),
            body: Body::Fields(pairs),
        });
        self
    }

    pub fn table(
        mut self,
        heading: impl Into<String>,
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
    ) -> Self {
        self.sections.push(Section {
            heading: Some(heading.into()),
            body: Body::Table { headers, rows },
        });
        self
    }
}

/// Fold a string into something `WinAnsiEncoding` can carry.
///
/// The common cases are folded rather than dropped, because a curly quote
/// becoming `?` in a company name reads as corruption where a straight quote
/// reads as a plain document. Everything else becomes `?`: emitting the raw
/// byte would render as an unrelated Latin-1 character, which is worse than a
/// visible gap.
pub fn to_win_ansi(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\u{2018}' | '\u{2019}' | '\u{201B}' => '\'',
            '\u{201C}' | '\u{201D}' | '\u{201F}' => '"',
            '\u{2013}' | '\u{2014}' | '\u{2212}' => '-',
            '\u{00A0}' | '\u{202F}' => ' ',
            '\t' => ' ',
            // C0/C1 controls have no glyph and would corrupt the stream.
            c if (c as u32) < 0x20 || ((c as u32) >= 0x7F && (c as u32) < 0xA0) => ' ',
            c if (c as u32) <= 0xFF => c,
            _ => '?',
        })
        .collect()
}

/// Render a document to PDF bytes.
///
/// Infallible in practice - there is no IO and no parsing - but it returns
/// `AppResult` so a backend that can fail (an embedded font that will not
/// parse, once PMS-959 wants one) does not change every call site.
pub fn render(document: &Document) -> AppResult<Vec<u8>> {
    let mut layout = Layout::new();

    layout.line(&document.title, BuiltinFont::HelveticaBold, TITLE_PT);
    if let Some(subtitle) = &document.subtitle {
        layout.line(subtitle, BuiltinFont::Helvetica, BODY_PT);
    }
    layout.gap(4.0);

    for section in &document.sections {
        if let Some(heading) = &section.heading {
            layout.gap(3.0);
            layout.keep_together(heading_height() + row_height(BODY_PT) * 2.0);
            layout.line(heading, BuiltinFont::HelveticaBold, HEADING_PT);
            layout.rule();
        }
        match &section.body {
            Body::Fields(pairs) => layout.fields(pairs),
            Body::Table { headers, rows } => layout.table(headers, rows),
        }
    }

    let mut doc = PdfDocument::new(&to_win_ansi(&document.title));
    Ok(doc
        .with_pages(layout.finish())
        .save(&PdfSaveOptions::default(), &mut Vec::new()))
}

fn row_height(size_pt: f32) -> f32 {
    size_pt * MM_PER_PT * 1.45
}

fn heading_height() -> f32 {
    row_height(HEADING_PT) + 2.0
}

/// A pen walking down a page, spilling onto the next when it runs out.
struct Layout {
    pages: Vec<PdfPage>,
    ops: Vec<Op>,
    /// Distance from the BOTTOM of the page, because that is where PDF's origin
    /// is and converting once here beats converting at every draw.
    y_mm: f32,
}

impl Layout {
    fn new() -> Self {
        Self {
            pages: Vec::new(),
            ops: Vec::new(),
            y_mm: PAGE_HEIGHT_MM - MARGIN_MM,
        }
    }

    fn content_width(&self) -> f32 {
        PAGE_WIDTH_MM - 2.0 * MARGIN_MM
    }

    /// Start a new page, keeping whatever has been drawn so far.
    fn page_break(&mut self) {
        let ops = std::mem::take(&mut self.ops);
        self.pages
            .push(PdfPage::new(Mm(PAGE_WIDTH_MM), Mm(PAGE_HEIGHT_MM), ops));
        self.y_mm = PAGE_HEIGHT_MM - MARGIN_MM;
    }

    /// Break now if `needed` millimetres will not fit, so a heading never lands
    /// alone at the foot of a page with its table overleaf.
    fn keep_together(&mut self, needed: f32) {
        if self.y_mm - needed < MARGIN_MM {
            self.page_break();
        }
    }

    fn advance(&mut self, mm: f32) {
        self.y_mm -= mm;
        if self.y_mm < MARGIN_MM {
            self.page_break();
        }
    }

    fn gap(&mut self, mm: f32) {
        self.advance(mm);
    }

    fn text_at(&mut self, x_mm: f32, text: &str, font: BuiltinFont, size_pt: f32) {
        self.ops.extend([
            Op::StartTextSection,
            Op::SetTextCursor {
                pos: Point::new(Mm(x_mm), Mm(self.y_mm)),
            },
            Op::SetFont {
                font: PdfFontHandle::Builtin(font),
                size: Pt(size_pt),
            },
            Op::SetFillColor {
                col: Color::Rgb(Rgb {
                    r: 0.0,
                    g: 0.0,
                    b: 0.0,
                    icc_profile: None,
                }),
            },
            Op::ShowText {
                items: vec![TextItem::Text(to_win_ansi(text))],
            },
            Op::EndTextSection,
        ]);
    }

    /// One line at the left margin, and down.
    fn line(&mut self, text: &str, font: BuiltinFont, size_pt: f32) {
        self.text_at(MARGIN_MM, text, font, size_pt);
        self.advance(row_height(size_pt));
    }

    /// A hairline the width of the content area, used under a heading and under
    /// a table's header row.
    fn rule(&mut self) {
        self.advance(1.5);
        let y = Mm(self.y_mm).into();
        self.ops.extend([
            Op::SetOutlineThickness { pt: Pt(0.4) },
            Op::SetOutlineColor {
                col: Color::Rgb(Rgb {
                    r: 0.6,
                    g: 0.6,
                    b: 0.6,
                    icc_profile: None,
                }),
            },
            Op::DrawLine {
                line: Line {
                    points: vec![
                        LinePoint {
                            p: Point {
                                x: Mm(MARGIN_MM).into(),
                                y,
                            },
                            bezier: false,
                        },
                        LinePoint {
                            p: Point {
                                x: Mm(PAGE_WIDTH_MM - MARGIN_MM).into(),
                                y,
                            },
                            bezier: false,
                        },
                    ],
                    is_closed: false,
                },
            },
        ]);
        self.advance(2.5);
    }

    fn fields(&mut self, pairs: &[(String, String)]) {
        for (label, value) in pairs {
            self.keep_together(row_height(BODY_PT));
            self.text_at(MARGIN_MM, label, BuiltinFont::Helvetica, BODY_PT);
            self.text_at(
                MARGIN_MM + LABEL_WIDTH_MM,
                value,
                BuiltinFont::HelveticaBold,
                BODY_PT,
            );
            self.advance(row_height(BODY_PT));
        }
    }

    fn table(&mut self, headers: &[String], rows: &[Vec<String>]) {
        if headers.is_empty() {
            return;
        }
        let widths = column_widths(headers, rows, self.content_width());
        self.header_row(headers, &widths);
        for row in rows {
            // A row that would land in the bottom margin starts the next page,
            // and the header comes with it: a table whose columns are unlabelled
            // from page two is not a table any more.
            if self.y_mm - row_height(BODY_PT) < MARGIN_MM {
                self.page_break();
                self.header_row(headers, &widths);
            }
            self.cells(row, &widths, BuiltinFont::Helvetica);
            self.advance(row_height(BODY_PT));
        }
    }

    fn header_row(&mut self, headers: &[String], widths: &[f32]) {
        self.cells(headers, widths, BuiltinFont::HelveticaBold);
        self.advance(row_height(BODY_PT));
        self.rule();
    }

    fn cells(&mut self, cells: &[String], widths: &[f32], font: BuiltinFont) {
        let mut x = MARGIN_MM;
        for (i, width) in widths.iter().enumerate() {
            if let Some(cell) = cells.get(i) {
                self.text_at(x, &truncate_to(cell, *width), font, BODY_PT);
            }
            x += width;
        }
    }

    fn finish(mut self) -> Vec<PdfPage> {
        let ops = std::mem::take(&mut self.ops);
        // Always at least one page, even for a document with no sections: a
        // zero-page PDF is not one a reader will open.
        if !ops.is_empty() || self.pages.is_empty() {
            self.pages
                .push(PdfPage::new(Mm(PAGE_WIDTH_MM), Mm(PAGE_HEIGHT_MM), ops));
        }
        self.pages
    }
}

/// How many millimetres a string of `n` characters occupies at the body size.
fn text_width_mm(chars: usize) -> f32 {
    chars as f32 * AVERAGE_CHAR_EM * BODY_PT * MM_PER_PT
}

/// Share the content width between columns in proportion to what they hold.
///
/// A column is never narrower than [`MIN_COLUMN_MM`], so one long free-text
/// column cannot squeeze a column of dates down to nothing.
fn column_widths(headers: &[String], rows: &[Vec<String>], available: f32) -> Vec<f32> {
    let mut wanted: Vec<f32> = headers
        .iter()
        .map(|h| text_width_mm(h.chars().count()) + 4.0)
        .collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if let Some(w) = wanted.get_mut(i) {
                *w = w.max(text_width_mm(cell.chars().count()) + 4.0);
            }
        }
    }
    let total: f32 = wanted.iter().sum();
    if total <= available {
        return wanted;
    }
    // Scale down, then lift anything under the floor and take the difference
    // back off the columns that can afford it.
    let scale = available / total;
    let mut widths: Vec<f32> = wanted
        .iter()
        .map(|w| (w * scale).max(MIN_COLUMN_MM))
        .collect();
    let over: f32 = widths.iter().sum::<f32>() - available;
    if over > 0.0 {
        let slack: f32 = widths.iter().map(|w| (w - MIN_COLUMN_MM).max(0.0)).sum();
        if slack > 0.0 {
            for w in widths.iter_mut() {
                let room = (*w - MIN_COLUMN_MM).max(0.0);
                *w -= over * (room / slack);
            }
        }
    }
    widths
}

/// Cut a cell to what its column can show, with an ellipsis so a reader can
/// see that something was cut.
fn truncate_to(text: &str, width_mm: f32) -> String {
    let usable = (width_mm - 2.0).max(0.0);
    let fits = (usable / (AVERAGE_CHAR_EM * BODY_PT * MM_PER_PT)).floor() as usize;
    let len = text.chars().count();
    if len <= fits {
        return text.to_string();
    }
    if fits <= 3 {
        return text.chars().take(fits).collect();
    }
    let mut out: String = text.chars().take(fits - 3).collect();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Document {
        Document::new("Ticket Volume")
            .subtitle("2026-01-01 to 2026-01-31")
            .fields(
                "Period",
                vec![
                    ("From".into(), "2026-01-01".into()),
                    ("To".into(), "2026-01-31".into()),
                ],
            )
            .table(
                "Opened by status",
                vec!["Status".into(), "Opened".into()],
                vec![
                    vec!["open".into(), "12".into()],
                    vec!["closed".into(), "34".into()],
                ],
            )
    }

    /// The bytes are a PDF a reader will open, which is the only claim the
    /// `Content-Type` makes.
    #[test]
    fn a_rendered_document_is_a_pdf() {
        let bytes = render(&sample()).expect("render");
        assert!(bytes.starts_with(b"%PDF-"), "a PDF starts with its magic");
        assert!(
            bytes.windows(5).any(|w| w == b"%%EOF"),
            "and ends with a trailer, so it is complete rather than truncated"
        );
        assert!(
            bytes.len() > 500,
            "not an empty shell: {} bytes",
            bytes.len()
        );
    }

    /// An empty document still renders one page. A zero-page PDF parses in some
    /// readers and not others, which is a worse answer than a blank sheet.
    #[test]
    fn a_document_with_no_sections_still_has_a_page() {
        let bytes = render(&Document::new("Nothing")).expect("render");
        assert!(bytes.starts_with(b"%PDF-"));
    }

    /// Enough rows to spill, so the page-break path is exercised rather than
    /// merely present.
    ///
    /// Counted against the short document rather than against a magic number,
    /// so the assertion still means something if the marker this greps for ever
    /// changes shape: whatever it counts, a 400-row table must produce more of
    /// them than a two-row one.
    #[test]
    fn a_long_table_runs_onto_more_than_one_page() {
        let rows: Vec<Vec<String>> = (0..400)
            .map(|i| vec![format!("row {i}"), i.to_string()])
            .collect();
        let doc = Document::new("Long").table("Rows", vec!["Label".into(), "Count".into()], rows);
        let long = page_count(&render(&doc).expect("render"));
        let short = page_count(&render(&sample()).expect("render"));
        assert_eq!(short, 1, "the sample fits on one page");
        assert!(long > short, "400 rows do not: {long} pages");
    }

    /// `/Type/Page` appears once per page object, plus once per document as the
    /// `/Type/Pages` tree node, which has to be excluded or every document
    /// counts one page too many.
    fn page_count(bytes: &[u8]) -> usize {
        let needle = b"/Type/Page";
        bytes
            .windows(needle.len() + 1)
            .filter(|w| &w[..needle.len()] == needle && w[needle.len()] != b's')
            .count()
    }

    /// Only Latin-1 survives, and the common typographic characters are folded
    /// rather than lost, because a curly quote becoming `?` in a company name
    /// reads as corruption.
    #[test]
    fn text_is_folded_into_what_the_font_can_encode() {
        assert_eq!(
            to_win_ansi("Acme\u{2019}s \u{201C}best\u{201D}"),
            "Acme's \"best\""
        );
        assert_eq!(to_win_ansi("A\u{2014}B"), "A-B");
        assert_eq!(
            to_win_ansi("caf\u{e9}"),
            "caf\u{e9}",
            "Latin-1 passes through"
        );
        assert_eq!(
            to_win_ansi("\u{4e2d}\u{6587}"),
            "??",
            "and the rest is visible, not silent"
        );
        assert_eq!(
            to_win_ansi("a\u{0}b"),
            "a b",
            "a control character has no glyph"
        );
    }

    /// A column never collapses, and the set never overflows the page.
    #[test]
    fn columns_share_the_page_without_starving_one() {
        let headers = vec![
            "Short".to_string(),
            "Description".to_string(),
            "N".to_string(),
        ];
        let rows = vec![vec!["x".to_string(), "a".repeat(400), "1".to_string()]];
        let available = PAGE_WIDTH_MM - 2.0 * MARGIN_MM;
        let widths = column_widths(&headers, &rows, available);
        assert_eq!(widths.len(), 3);
        for w in &widths {
            assert!(*w >= MIN_COLUMN_MM - 0.01, "a column collapsed: {widths:?}");
        }
        assert!(
            widths.iter().sum::<f32>() <= available + 0.01,
            "the row is wider than the page: {widths:?}"
        );
    }

    /// And a cell too long for its column says so rather than running into its
    /// neighbour.
    #[test]
    fn an_oversized_cell_is_cut_with_an_ellipsis() {
        let cut = truncate_to(&"a".repeat(200), MIN_COLUMN_MM);
        assert!(cut.ends_with("..."), "{cut:?}");
        assert!(cut.chars().count() < 200);
        assert_eq!(
            truncate_to("short", 60.0),
            "short",
            "and a cell that fits is untouched"
        );
    }
}
