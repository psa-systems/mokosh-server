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
//! labelled fields, plain lines, a table, or (PMS-1004) the two shapes an
//! invoice wanted that a report did not: headed line blocks side by side and a
//! totals block at the right margin. That is the shape every report in this
//! codebase already has (the CSV writers emit exactly that: a header block,
//! then one or more grouped tables) plus what a commercial document adds to it.
//! Anything needing real flow - wrapped paragraphs, nested blocks - is a bigger
//! decision than either needs and would be made against the work that wants it.
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
    PdfSaveOptions, Point, Pt, RawImage, Rgb, TextItem, XObjectId, XObjectTransform,
};

use sha2::{Digest, Sha256};

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

/// Width of a totals block, measured in from the right margin (PMS-1004).
/// Room for "Balance due" and a seven-figure amount with its currency code.
const TOTALS_WIDTH_MM: f32 = 80.0;

/// Space between side-by-side column blocks (PMS-1004).
const COLUMN_GUTTER_MM: f32 = 8.0;

/// Inset of a cell's text from its column edge.
const CELL_PAD_MM: f32 = 2.0;

/// Narrowest a table column is allowed to get, so a column of long values
/// cannot squeeze its neighbours to nothing.
const MIN_COLUMN_MM: f32 = 16.0;

/// A column whose widest cell fits in this keeps its width when the table
/// overflows (PMS-1004): dates, quantities and amounts are never cut to make
/// room for a description.
const NARROW_COLUMN_MM: f32 = 34.0;

/// What a section holds.
pub enum Body {
    /// Label / value pairs, for the header block a report opens with.
    Fields(Vec<(String, String)>),
    /// Plain lines, for an address block: the issuer's, or the one an invoice
    /// is billed to (PMS-911). Not `Fields`, because an address has no labels.
    Lines(Vec<String>),
    /// A grid. The header row repeats when the table crosses a page.
    /// `align` has one entry per column; a missing entry is `Left`.
    Table {
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
        align: Vec<Align>,
    },
    /// PMS-1004: several headed line blocks side by side, sharing the content
    /// width equally. An invoice's From and Bill to belong beside each other,
    /// not one under the other: stacked, the two blocks push the items table
    /// down the page for no reason a reader can see.
    Columns(Vec<(String, Vec<String>)>),
    /// PMS-1004: label / value pairs set against the RIGHT margin, values
    /// flush right, with a rule above the last pair. Where an invoice puts
    /// its totals, so the balance due sits under the amount column that
    /// produced it.
    Totals(Vec<(String, String)>),
}

/// How a table column sets its cells.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Align {
    #[default]
    Left,
    /// For a column of numbers, so the units line up under each other.
    Right,
}

/// One block of a document, optionally under a heading.
pub struct Section {
    pub heading: Option<String>,
    pub body: Body,
}

/// An image placed in the top-right of the first page (PMS-911).
///
/// Bytes rather than a path, because the caller is the one that knows where an
/// object lives and this module deliberately never touches storage. For an
/// invoice those bytes come out of the branding snapshot, so they are the logo
/// as it was when the invoice was sent rather than whatever is current.
pub struct Logo {
    pub bytes: Vec<u8>,
    /// The box it is fitted inside, preserving aspect ratio.
    pub max_width_mm: f32,
    pub max_height_mm: f32,
}

/// What to render. Built by a caller that knows the data, never by this module.
pub struct Document {
    pub title: String,
    /// A period, a scope, whatever names this particular run.
    pub subtitle: Option<String>,
    /// PMS-911: the issuer's mark, top right of the first page.
    pub logo: Option<Logo>,
    pub sections: Vec<Section>,
}

impl Document {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            subtitle: None,
            logo: None,
            sections: Vec::new(),
        }
    }

    /// PMS-911: an optional mark. `None` is the ordinary case, not a fallback:
    /// an MSP that never uploaded one still gets a valid document with its name
    /// as text.
    pub fn logo(mut self, logo: Option<Logo>) -> Self {
        self.logo = logo;
        self
    }

    pub fn lines(mut self, heading: impl Into<String>, lines: Vec<String>) -> Self {
        self.sections.push(Section {
            heading: Some(heading.into()),
            body: Body::Lines(lines),
        });
        self
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

    /// A table with every column set left.
    pub fn table(
        self,
        heading: impl Into<String>,
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
    ) -> Self {
        self.table_aligned(heading, headers, rows, Vec::new())
    }

    /// PMS-1004: a table that says how each column is set. `align` is
    /// positional and may be shorter than `headers`; the rest are `Left`.
    pub fn table_aligned(
        mut self,
        heading: impl Into<String>,
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
        align: Vec<Align>,
    ) -> Self {
        self.sections.push(Section {
            heading: Some(heading.into()),
            body: Body::Table {
                headers,
                rows,
                align,
            },
        });
        self
    }

    /// PMS-1004: headed line blocks side by side. Each block carries its own
    /// heading, so the section itself has none.
    pub fn columns(mut self, blocks: Vec<(String, Vec<String>)>) -> Self {
        self.sections.push(Section {
            heading: None,
            body: Body::Columns(blocks),
        });
        self
    }

    /// PMS-1004: a totals block at the right margin. No heading: the block
    /// closes the table above it, and "Totals" over a column of totals says
    /// nothing the reader did not know.
    pub fn totals(mut self, pairs: Vec<(String, String)>) -> Self {
        self.sections.push(Section {
            heading: None,
            body: Body::Totals(pairs),
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
    let mut doc = PdfDocument::new(&to_win_ansi(&document.title));
    let mut layout = Layout::new();

    // The logo is placed before the title so the title block can start below
    // it if it is the taller of the two. A logo that will not decode is
    // dropped rather than fatal: an invoice with no mark is a valid invoice,
    // and refusing to render one because an image is corrupt would withhold
    // the document over its decoration.
    let logo_height = match &document.logo {
        Some(logo) => match place_logo(&mut doc, &mut layout, logo) {
            Ok(height) => height,
            Err(reason) => {
                tracing::warn!(reason = %reason, "pdf: could not place the logo; rendering without it");
                0.0
            }
        },
        None => 0.0,
    };

    let title_top = layout.y_mm;
    layout.line(&document.title, BuiltinFont::HelveticaBold, TITLE_PT);
    if let Some(subtitle) = &document.subtitle {
        layout.line(subtitle, BuiltinFont::Helvetica, HEADING_PT);
    }
    // Whichever of the two blocks is taller decides where the body starts.
    layout.y_mm = layout.y_mm.min(title_top - logo_height);
    layout.gap(4.0);

    for section in &document.sections {
        layout.gap(4.0);
        if let Some(heading) = &section.heading {
            layout.keep_together(heading_height() + row_height(BODY_PT) * 2.0);
            layout.heading(heading);
        }
        match &section.body {
            Body::Fields(pairs) => layout.fields(pairs),
            Body::Lines(lines) => layout.text_block(lines),
            Body::Table {
                headers,
                rows,
                align,
            } => layout.table(headers, rows, align),
            Body::Columns(blocks) => layout.columns(blocks),
            Body::Totals(pairs) => layout.totals(pairs),
        }
    }

    let mut bytes = doc
        .with_pages(layout.finish())
        .save(&PdfSaveOptions::default(), &mut Vec::new());
    stamp_deterministic_id(&mut bytes);
    Ok(bytes)
}

/// Replace the random `/ID` printpdf writes with one derived from the file.
///
/// PMS-911 requires that a rebrand leaves an already-sent invoice unchanged,
/// which is only checkable if rendering the same document twice gives the same
/// bytes. Everything printpdf emits is deterministic already - the document
/// dates default to the unix epoch rather than `now()`, and deflate is
/// reproducible - except the trailer's file identifier, which is two
/// unconditionally random 32-character strings with no option to seed or
/// suppress them (`serialize.rs` calls `random_character_string_32` twice).
///
/// So it is rewritten afterwards, from a digest of the file with the two
/// identifier slots blanked. Both halves get the same value, which is what the
/// PDF specification says a newly created file should carry anyway: the pair is
/// "original" and "current", and for a document that has never been updated
/// they are equal.
///
/// The replacement is the same length as what it replaces, so no byte offset
/// moves and the cross-reference table stays valid. A change in printpdf that
/// altered the identifier's length or literal syntax would stop this matching,
/// and the function would leave the file untouched rather than corrupt it -
/// caught by `rendering_is_deterministic` rather than shipped.
fn stamp_deterministic_id(bytes: &mut [u8]) {
    const ID_LEN: usize = 32;
    let Some(open) = find(bytes, b"/ID[(") else {
        return;
    };
    let first = open + b"/ID[(".len();
    let second = first + ID_LEN + b")(".len();
    let end = second + ID_LEN;
    if end + b")]".len() > bytes.len()
        || &bytes[first + ID_LEN..second] != b")("
        || &bytes[end..end + 2] != b")]"
    {
        return;
    }

    // Blank both slots first so the digest is over a file that does not
    // contain the value being computed.
    for slot in [first, second] {
        bytes[slot..slot + ID_LEN].fill(b'A');
    }
    let digest = <Sha256 as Digest>::digest(&bytes[..]);
    let hex: String = digest
        .iter()
        .take(ID_LEN / 2)
        .map(|b| format!("{b:02X}"))
        .collect();
    for slot in [first, second] {
        bytes[slot..slot + ID_LEN].copy_from_slice(hex.as_bytes());
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Decode a logo, register it, and draw it in the top-right corner.
///
/// Returns the height it occupied, so the caller can start the body below
/// whichever of the logo and the title block reaches lower.
///
/// The image is scaled by DPI rather than by `scale_x` / `scale_y`, because
/// printpdf derives an image's physical size from its pixel count and its DPI:
/// asking for a width in millimetres is the same as asking for the DPI at which
/// that many pixels measure that many millimetres.
fn place_logo(doc: &mut PdfDocument, layout: &mut Layout, logo: &Logo) -> Result<f32, String> {
    let image = RawImage::decode_from_bytes(&logo.bytes, &mut Vec::new())?;
    let (px_w, px_h) = (image.width as f32, image.height as f32);
    if px_w <= 0.0 || px_h <= 0.0 {
        return Err("the image has no pixels".to_string());
    }
    // Fit inside the box, preserving aspect ratio.
    let scale = (logo.max_width_mm / px_w).min(logo.max_height_mm / px_h);
    let width_mm = px_w * scale;
    let height_mm = px_h * scale;
    let dpi = px_w * 25.4 / width_mm;

    // NOT `doc.add_image`, which mints a random `XObjectId`. That id becomes
    // the resource NAME in the page's dictionary and in its content stream, so
    // a random one makes two renders of the same document differ in a
    // compressed stream that cannot be patched afterwards - which is what
    // `rendering_is_deterministic` caught. A digest of the image is
    // deterministic AND collision-free, so two documents carrying the same
    // logo agree and two carrying different ones do not.
    let digest = <Sha256 as Digest>::digest(&logo.bytes);
    let name: String = digest.iter().take(12).map(|b| format!("{b:02X}")).collect();
    let id = XObjectId(format!("IMG{name}"));
    doc.resources
        .xobjects
        .map
        .insert(id.clone(), printpdf::XObject::Image(image));
    let left = PAGE_WIDTH_MM - MARGIN_MM - width_mm;
    layout.ops.push(Op::UseXobject {
        id,
        transform: XObjectTransform {
            translate_x: Some(Mm(left).into()),
            // The origin is the bottom-left of the image, so subtract its
            // height from the top of the content area.
            translate_y: Some(Mm(layout.y_mm - height_mm).into()),
            rotate: None,
            scale_x: None,
            scale_y: None,
            dpi: Some(dpi),
            no_auto_scale: false,
        },
    });
    Ok(height_mm)
}

fn row_height(size_pt: f32) -> f32 {
    size_pt * MM_PER_PT * 1.45
}

/// A heading with its rule: the text, then what [`Layout::rule`] advances.
fn heading_height() -> f32 {
    row_height(HEADING_PT) + RULE_ABOVE_MM + RULE_BELOW_MM
}

/// Where a rule sits relative to the text either side of it (PMS-1004). The
/// text cursor is a BASELINE, so the rule needs only descender clearance
/// above it and a full ascent plus breathing room below, where the next
/// baseline lands. Before this the rule was set a full row below the
/// heading and the next baseline a hair below the rule, so every heading
/// floated above its rule and every body sat on it.
const RULE_ABOVE_MM: f32 = 2.0;
const RULE_BELOW_MM: f32 = 4.5;

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

    /// A section heading with its rule beneath.
    fn heading(&mut self, text: &str) {
        self.text_at(MARGIN_MM, text, BuiltinFont::HelveticaBold, HEADING_PT);
        self.rule();
    }

    /// A hairline the width of the content area, used under a heading and under
    /// a table's header row.
    fn rule(&mut self) {
        self.rule_between(MARGIN_MM, PAGE_WIDTH_MM - MARGIN_MM);
    }

    /// A hairline from `x0` to `x1`, spaced for text above and below it.
    fn rule_between(&mut self, x0: f32, x1: f32) {
        self.advance(RULE_ABOVE_MM);
        self.hairline(x0, x1);
        self.advance(RULE_BELOW_MM);
    }

    /// The line itself at the current cursor, with no spacing of its own.
    fn hairline(&mut self, x0: f32, x1: f32) {
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
                                x: Mm(x0).into(),
                                y,
                            },
                            bezier: false,
                        },
                        LinePoint {
                            p: Point {
                                x: Mm(x1).into(),
                                y,
                            },
                            bezier: false,
                        },
                    ],
                    is_closed: false,
                },
            },
        ]);
    }

    /// PMS-1004: headed line blocks side by side.
    ///
    /// Kept together as one unit: an address block is a handful of lines, and
    /// a From on one page with its Bill to overleaf is not side by side.
    fn columns(&mut self, blocks: &[(String, Vec<String>)]) {
        if blocks.is_empty() {
            return;
        }
        let count = blocks.len() as f32;
        let width = (self.content_width() - COLUMN_GUTTER_MM * (count - 1.0)) / count;
        let tallest = blocks.iter().map(|(_, l)| l.len()).max().unwrap_or(0);
        let needed = heading_height() + row_height(BODY_PT) * tallest as f32;
        self.keep_together(needed);
        let top = self.y_mm;
        let mut lowest = top;
        for (i, (heading, lines)) in blocks.iter().enumerate() {
            let x = MARGIN_MM + i as f32 * (width + COLUMN_GUTTER_MM);
            self.y_mm = top;
            self.text_at(
                x,
                &truncate_to(heading, width),
                BuiltinFont::HelveticaBold,
                HEADING_PT,
            );
            self.rule_between(x, x + width);
            for line in lines {
                self.text_at(
                    x,
                    &truncate_to(line, width),
                    BuiltinFont::Helvetica,
                    BODY_PT,
                );
                self.y_mm -= row_height(BODY_PT);
            }
            lowest = lowest.min(self.y_mm);
        }
        self.y_mm = lowest;
    }

    /// PMS-1004: a totals block against the right margin.
    fn totals(&mut self, pairs: &[(String, String)]) {
        let x0 = PAGE_WIDTH_MM - MARGIN_MM - TOTALS_WIDTH_MM;
        let right = PAGE_WIDTH_MM - MARGIN_MM;
        self.keep_together(row_height(BODY_PT) * (pairs.len() as f32 + 1.0) + RULE_BELOW_MM);
        for (i, (label, value)) in pairs.iter().enumerate() {
            if i + 1 == pairs.len() && pairs.len() > 1 {
                // The rule that says "this one is the answer".
                self.rule_between(x0, right);
            }
            self.text_at(x0, label, BuiltinFont::Helvetica, BODY_PT);
            let value = truncate_to(value, TOTALS_WIDTH_MM - LABEL_WIDTH_MM / 2.0);
            self.text_at(
                right_aligned_x(right, &value),
                &value,
                BuiltinFont::HelveticaBold,
                BODY_PT,
            );
            self.advance(row_height(BODY_PT));
        }
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

    /// PMS-911: plain lines at the left margin, for an address block.
    fn text_block(&mut self, lines: &[String]) {
        for line in lines {
            self.keep_together(row_height(BODY_PT));
            self.text_at(MARGIN_MM, line, BuiltinFont::Helvetica, BODY_PT);
            self.advance(row_height(BODY_PT));
        }
    }

    fn table(&mut self, headers: &[String], rows: &[Vec<String>], align: &[Align]) {
        if headers.is_empty() {
            return;
        }
        let widths = column_widths(headers, rows, self.content_width());
        self.header_row(headers, &widths, align);
        for row in rows {
            // A row that would land in the bottom margin starts the next page,
            // and the header comes with it: a table whose columns are unlabelled
            // from page two is not a table any more.
            if self.y_mm - row_height(BODY_PT) < MARGIN_MM {
                self.page_break();
                self.header_row(headers, &widths, align);
            }
            self.cells(row, &widths, align, BuiltinFont::Helvetica);
            self.advance(row_height(BODY_PT));
        }
        // PMS-1004: a closing rule, so the table has a bottom as well as a
        // top and what follows it (a totals block, the next section) reads as
        // separate from the last row.
        self.advance(RULE_ABOVE_MM - row_height(BODY_PT) * 0.4);
        self.hairline(MARGIN_MM, PAGE_WIDTH_MM - MARGIN_MM);
        self.advance(RULE_BELOW_MM);
    }

    fn header_row(&mut self, headers: &[String], widths: &[f32], align: &[Align]) {
        self.cells(headers, widths, align, BuiltinFont::HelveticaBold);
        self.rule();
    }

    fn cells(&mut self, cells: &[String], widths: &[f32], align: &[Align], font: BuiltinFont) {
        let mut x = MARGIN_MM;
        for (i, width) in widths.iter().enumerate() {
            if let Some(cell) = cells.get(i) {
                let text = truncate_to(cell, *width);
                let at = match align.get(i).copied().unwrap_or_default() {
                    Align::Left => x,
                    Align::Right => right_aligned_x(x + width - CELL_PAD_MM, &text),
                };
                self.text_at(at, &text, font, BODY_PT);
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

/// Where text has to START so that it ENDS at `right_mm` (PMS-1004).
///
/// Estimated from [`AVERAGE_CHAR_EM`] like every other width here, which is
/// set above Helvetica's true average, so the estimate errs towards ending
/// short of the edge rather than past it. Digits are 0.556 em in Helvetica,
/// close enough to the 0.52 that a column of amounts lines up to within a
/// character.
fn right_aligned_x(right_mm: f32, text: &str) -> f32 {
    (right_mm - text_width_mm(text.chars().count())).max(MARGIN_MM)
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
    // PMS-1004: a narrow column keeps its width and only the wide ones give
    // way. Scaling every column by the same factor let one long description
    // squeeze "150.00 USD" down to "150.0..." on an invoice, which is the one
    // cell a customer reads. A column is narrow when everything in it fits
    // in NARROW_COLUMN_MM; the rest share what is left, in proportion.
    let narrow = |w: &f32| *w <= NARROW_COLUMN_MM;
    let fixed: f32 = wanted
        .iter()
        .filter(|w| narrow(w))
        .map(|w| w.max(MIN_COLUMN_MM))
        .sum();
    let flexible: f32 = wanted.iter().filter(|w| !narrow(w)).sum();
    let flexible_count = wanted.iter().filter(|w| !narrow(w)).count() as f32;
    let room = available - fixed;
    if flexible_count > 0.0 && room >= MIN_COLUMN_MM * flexible_count {
        return wanted
            .iter()
            .map(|w| {
                if narrow(w) {
                    w.max(MIN_COLUMN_MM)
                } else {
                    (w * room / flexible).max(MIN_COLUMN_MM)
                }
            })
            .collect();
    }
    // Every column is wide, or the narrow ones alone overflow the page: scale
    // down, then lift anything under the floor and take the difference back
    // off the columns that can afford it.
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
    let usable = (width_mm - CELL_PAD_MM).max(0.0);
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

    /// A one-pixel PNG: a real image of a type `utils::inline_image` accepts,
    /// so the codec that decodes it here is one an upload can actually produce.
    const PNG: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];

    fn logo() -> Logo {
        Logo {
            bytes: PNG.to_vec(),
            max_width_mm: 40.0,
            max_height_mm: 20.0,
        }
    }

    /// Rendering the same document twice produces the same bytes.
    ///
    /// PMS-911 rests on this: "a later rebrand leaves the rendered invoice
    /// byte-identical" is only checkable if rendering is deterministic in the
    /// first place. It is, because printpdf's `PdfDocumentInfo::default()` sets
    /// the creation, modification and metadata dates to the unix epoch rather
    /// than to `now()`. That is a property of a dependency rather than of this
    /// code, which is exactly why it is pinned: an upgrade that started
    /// stamping the real time would break the acceptance criterion silently,
    /// and every test of it would keep passing while comparing two documents
    /// rendered in the same second.
    #[test]
    fn rendering_is_deterministic() {
        let first = render(&sample()).expect("render");
        let second = render(&sample()).expect("render");
        assert_eq!(first, second, "two renders of one document must agree");

        let with_logo = render(&sample().logo(Some(logo()))).expect("render");
        assert_eq!(
            with_logo,
            render(&sample().logo(Some(logo()))).expect("render"),
            "and so must two renders carrying an image"
        );
        assert_ne!(
            first, with_logo,
            "a logo has to actually reach the document, or the test above proves nothing"
        );
    }

    /// An unreadable logo costs the mark, not the document.
    ///
    /// Refusing to render an invoice because its decoration will not decode
    /// would withhold a commercial document over an image.
    #[test]
    fn a_logo_that_will_not_decode_is_dropped_rather_than_fatal() {
        let broken = Logo {
            bytes: b"this is not an image".to_vec(),
            max_width_mm: 40.0,
            max_height_mm: 20.0,
        };
        let rendered = render(&sample().logo(Some(broken))).expect("still renders");
        assert!(rendered.starts_with(b"%PDF-"));
        assert_eq!(
            rendered,
            render(&sample()).expect("render"),
            "and what comes out is exactly the document with no logo"
        );
    }

    /// A block of lines, for an address, which has no labels to hang on
    /// `Fields`.
    #[test]
    fn an_address_block_renders_as_lines() {
        let doc = Document::new("Invoice").lines(
            "From",
            vec![
                "Acme IT Services Pty Ltd".into(),
                "12 Example Street".into(),
                "Sydney NSW 2000".into(),
            ],
        );
        let bytes = render(&doc).expect("render");
        assert!(bytes.starts_with(b"%PDF-"));
        assert!(bytes.len() > render(&Document::new("Invoice")).expect("render").len());
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

    /// PMS-1004: the invoice shapes. Side-by-side blocks, a right-aligned
    /// amount column and a totals block all render, on one page, and two
    /// renders still agree: none of it may introduce randomness, because
    /// PMS-911's byte-identical rule rests on `rendering_is_deterministic`.
    #[test]
    fn the_invoice_shapes_render_on_one_page_and_deterministically() {
        let doc = Document::new("Invoice")
            .subtitle("INV-000001")
            .columns(vec![
                (
                    "From".to_string(),
                    vec!["Acme IT".to_string(), "12 Example St".to_string()],
                ),
                (
                    "Bill to".to_string(),
                    vec![
                        "NiceGuy IT".to_string(),
                        "1 Customer Way".to_string(),
                        "Attn: Bill Payer".to_string(),
                    ],
                ),
            ])
            .table_aligned(
                "Items",
                vec!["Description".into(), "Qty".into(), "Amount".into()],
                vec![vec![
                    "2026-08-27 Remote support: T000042 Printer offline".into(),
                    "2".into(),
                    "300.00 USD".into(),
                ]],
                vec![Align::Left, Align::Right, Align::Right],
            )
            .totals(vec![
                ("Subtotal".into(), "300.00 USD".into()),
                ("Tax".into(), "0.00 USD".into()),
                ("Balance due".into(), "300.00 USD".into()),
            ]);
        let first = render(&doc).expect("render");
        let second = render(&doc).expect("render");
        assert!(first.starts_with(b"%PDF-"));
        assert_eq!(first, second, "the new shapes are deterministic");
        assert_eq!(page_count(&first), 1);
        assert!(
            first.len() > render(&Document::new("Invoice")).expect("render").len(),
            "and they drew something"
        );
    }

    /// Right-aligned text ends where it was told to, within the width
    /// estimate, and never runs off the left margin.
    #[test]
    fn right_aligned_text_ends_at_the_edge_it_was_given() {
        let right = 120.0;
        let text = "300.00 USD";
        let x = right_aligned_x(right, text);
        assert!(x < right);
        assert!(
            (x + text_width_mm(text.chars().count()) - right).abs() < 0.01,
            "start plus width is the edge: {x}"
        );
        assert_eq!(
            right_aligned_x(20.0, &"9".repeat(500)),
            MARGIN_MM,
            "an impossible fit is pinned to the margin rather than off the page"
        );
    }

    /// PMS-1004: the money columns of an invoice keep their width; only the
    /// description gives way. Before this every column scaled by the same
    /// factor and "150.00 USD" came out as "150.0...".
    #[test]
    fn a_long_description_does_not_cut_the_amount_beside_it() {
        let headers = vec![
            "Description".to_string(),
            "Qty".to_string(),
            "Unit price".to_string(),
            "Amount".to_string(),
        ];
        let rows = vec![vec![
            "2026-08-24 Remote support: T000042 Printer offline - Rebooted the print spooler"
                .to_string(),
            "2".to_string(),
            "150.00 USD".to_string(),
            "1300.00 USD".to_string(),
        ]];
        let available = PAGE_WIDTH_MM - 2.0 * MARGIN_MM;
        let widths = column_widths(&headers, &rows, available);
        for (i, cell) in rows[0].iter().enumerate().skip(1) {
            assert_eq!(
                truncate_to(cell, widths[i]),
                *cell,
                "column {i} was cut: {widths:?}"
            );
        }
        assert!(
            widths.iter().sum::<f32>() <= available + 0.01,
            "the row is wider than the page: {widths:?}"
        );
        assert!(
            widths[0] > widths[3],
            "the description still gets the most room: {widths:?}"
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
