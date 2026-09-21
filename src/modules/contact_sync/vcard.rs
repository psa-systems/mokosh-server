//! PMS-1289: an uploaded `.vcf` file, read into canonical [`SourceContact`]s.
//!
//! A vCard file (RFC 6350 for 4.0, RFC 2426 for 3.0, the 1996 Versit spec for
//! 2.1) is the file equivalent of a contact directory: an iPhone, Outlook,
//! Google and every CardDAV server can export one. This module turns one into
//! the same [`SourceContact`] the Google provider produces, so the mapping,
//! the matching and the review queue are the ones that already exist.
//!
//! # A library parses; this module only frames
//!
//! Property parsing is [`calcard`]'s: line unfolding, `\,` `\;` `\n` escapes,
//! 2.1 quoted-printable with `CHARSET=`, bare 2.1 types, 4.0 `PREF=1`, and
//! Apple's `item1.` groups. A hand-written vCard parser is a well-known source
//! of bugs, and this one is the parser behind a production CardDAV server.
//!
//! What sits in front of it is framing, for the two things probing it against
//! messy files showed it does not do, plus the resource bounds an untrusted
//! upload needs:
//!
//! * **One card at a time.** Handed a whole file, a card missing its
//!   `END:VCARD` swallowed the next card's `BEGIN` and that valid card was
//!   lost, and a truncated last card was accepted silently. So the file is
//!   split at `BEGIN:VCARD` / `END:VCARD` here, and each card is parsed on its
//!   own: an unterminated card is reported and its neighbour survives.
//! * **Bytes before text.** The parser takes `&str`, and an Outlook export is
//!   often raw 8-bit Windows-1252 rather than quoted-printable, which a lossy
//!   UTF-8 read turns into `M�ller`. Each card is decoded with its own
//!   `CHARSET` label through `encoding_rs`, else as Windows-1252 (the WHATWG
//!   reading of `latin1`); a UTF-16 file (some Windows exports) is transcoded
//!   whole, found by its byte-order mark.
//! * **Photos never reach the parser.** `PHOTO`, `LOGO`, `SOUND` and `KEY`
//!   are measured as they stream past and then discarded, so a card's memory
//!   is its text and not its embedded image. A photo that is a link is kept
//!   as text for the preview and is never requested: a `.vcf` can name any
//!   address, and fetching it server-side is an SSRF vector (PMS-805). This
//!   module holds no HTTP client, and a test says so.
//!
//! # Bounded
//!
//! The file is read through `Read::take` at [`Limits::max_file_bytes`], cards
//! are counted against [`Limits::max_cards`], and a card's text is capped at
//! [`Limits::max_card_bytes`]. The first two refuse the whole file with a
//! message a person can act on; an oversized card is reported and skipped.
//! Parsing is synchronous CPU work: a caller serving a request runs it on a
//! blocking thread, never on the async executor.
//!
//! # Identity
//!
//! A file import is one-shot, not a sync, so the identity only has to make a
//! re-import of the same file a no-op. The vCard `UID` is the external id
//! when there is one. When there is not, nothing in the card is stable, so the
//! external id is a digest of the card's content ([`content_hash`]), which
//! recognises the same card in the same file again and makes a changed card a
//! new record for the matching policy to place. The etag is always the digest,
//! so a card with a `UID` whose content is unchanged is the engine's existing
//! "nothing to do".

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read};

use calcard::vcard::{
    VCard, VCardEntry, VCardKind, VCardParameterName, VCardParameterValue, VCardProperty,
    VCardType, VCardValue,
};
use calcard::{Entry, Parser};
use sha2::{Digest, Sha256};

use super::provider::{SourceContact, SourceEmail, SourceGroup, SourcePhone, SourcePhoto};
use crate::utils::text::sanitize_invisible;

/// How much of an untrusted file the reader will look at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The whole file. Over it, nothing is imported.
    pub max_file_bytes: u64,
    /// Cards in one file. Over it, nothing is imported.
    pub max_cards: usize,
    /// One card's text, excluding its photo. Over it, that card is skipped
    /// and reported.
    pub max_card_bytes: usize,
    /// One embedded photo, decoded. Photos are not imported; over this the
    /// card still imports and the preview says the photo was too large.
    pub max_photo_bytes: usize,
}

impl Limits {
    pub const DEFAULT: Self = Self {
        max_file_bytes: 10 * 1024 * 1024,
        max_cards: 5_000,
        max_card_bytes: 256 * 1024,
        max_photo_bytes: 1024 * 1024,
    };
}

/// Why a whole file was refused. Per-card trouble is a [`CardProblem`]
/// instead, so one bad card never costs the rest of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    FileTooLarge { limit_bytes: u64 },
    TooManyCards { limit: usize },
    Unreadable(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileTooLarge { limit_bytes } => write!(
                f,
                "This file is larger than {} MB, the most one import accepts. Export the contacts in smaller groups and import each file.",
                limit_bytes / (1024 * 1024)
            ),
            Self::TooManyCards { limit } => write!(
                f,
                "This file holds more than {limit} contacts, the most one import accepts. Export the contacts in smaller groups and import each file."
            ),
            Self::Unreadable(reason) => write!(f, "The file could not be read: {reason}."),
        }
    }
}

/// Something wrong with one card, located well enough for a person to find it
/// in the file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CardProblem {
    /// The card's position in the file, from 1.
    pub card: u32,
    /// The line its `BEGIN:VCARD` is on, from 1.
    pub line: u32,
    /// A name or the card's first property, so the report is recognisable.
    pub hint: String,
    pub reason: String,
}

/// What a file held.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VcardFile {
    pub contacts: Vec<SourceContact>,
    /// The file's distinct `CATEGORIES`, with how many contacts carry each:
    /// the file equivalent of Google's contact groups, and the unit of the
    /// opt-in selection.
    pub groups: Vec<SourceGroup>,
    /// Cards that were not imported, and why.
    pub failures: Vec<CardProblem>,
    /// Cards that were imported with something worth saying.
    pub warnings: Vec<CardProblem>,
    /// Cards describing a group rather than a person (vCard 4.0 `KIND:group`,
    /// Apple's `X-ADDRESSBOOKSERVER-KIND:group`). Not contacts, not failures.
    pub group_cards: u32,
    /// Every `BEGIN:VCARD` seen.
    pub cards: u32,
}

/// Read a `.vcf` file.
pub fn read_vcards<R: Read>(reader: R, limits: Limits) -> Result<VcardFile, ReadError> {
    let mut input = BufReader::new(reader.take(limits.max_file_bytes + 1));
    let head = input
        .fill_buf()
        .map_err(|e| ReadError::Unreadable(e.kind().to_string()))?;
    let utf16 = encoding_rs::Encoding::for_bom(head)
        .map(|(encoding, _)| encoding)
        .filter(|e| *e == encoding_rs::UTF_16LE || *e == encoding_rs::UTF_16BE);

    let mut file = VcardFile::default();
    match utf16 {
        // A UTF-16 file cannot be split on b'\n', so it is transcoded whole.
        // Still bounded: `take` stops it one byte past the limit.
        Some(encoding) => {
            let mut raw = Vec::new();
            input
                .read_to_end(&mut raw)
                .map_err(|e| ReadError::Unreadable(e.kind().to_string()))?;
            if raw.len() as u64 > limits.max_file_bytes {
                return Err(ReadError::FileTooLarge {
                    limit_bytes: limits.max_file_bytes,
                });
            }
            let (text, _) = encoding.decode_with_bom_removal(&raw);
            frame(text.as_bytes(), limits, &mut file)?;
        }
        None => frame(input, limits, &mut file)?,
    }
    canonicalise_groups(&mut file);
    Ok(file)
}

/// Split the byte stream into cards and convert each.
fn frame<B: BufRead>(mut input: B, limits: Limits, file: &mut VcardFile) -> Result<(), ReadError> {
    let mut open: Option<CardBuilder> = None;
    let mut buf = Vec::new();
    let mut total: u64 = 0;
    let mut line_no: u32 = 0;
    loop {
        buf.clear();
        let n = input
            .read_until(b'\n', &mut buf)
            .map_err(|e| ReadError::Unreadable(e.kind().to_string()))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > limits.max_file_bytes {
            return Err(ReadError::FileTooLarge {
                limit_bytes: limits.max_file_bytes,
            });
        }
        line_no += 1;
        let mut line = trim_eol(&buf);
        if line_no == 1 {
            line = line.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(line);
        }
        let continuation = line.first().is_some_and(|b| *b == b' ' || *b == b'\t');

        if !continuation && line.trim_ascii_end().eq_ignore_ascii_case(b"BEGIN:VCARD") {
            if let Some(unterminated) = open.take() {
                file.failures.push(unterminated.problem(
                    "The card has no END:VCARD before the next card begins, so it was skipped.",
                ));
            }
            file.cards += 1;
            if file.cards as usize > limits.max_cards {
                return Err(ReadError::TooManyCards {
                    limit: limits.max_cards,
                });
            }
            open = Some(CardBuilder::new(file.cards, line_no));
            continue;
        }
        let Some(card) = open.as_mut() else {
            // Text between cards is not a contact and not an error.
            continue;
        };
        if !continuation && line.trim_ascii_end().eq_ignore_ascii_case(b"END:VCARD") {
            let card = open.take().expect("a card is open");
            finish(card, limits, file);
            continue;
        }
        card.push_line(line, limits);
    }
    if let Some(truncated) = open.take() {
        file.failures.push(truncated.problem(
            "The file ends before this card's END:VCARD, so it was skipped. The export may be incomplete.",
        ));
    }
    Ok(())
}

fn trim_eol(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// The properties that carry binary payloads, measured and discarded by the
/// framer rather than handed to the parser.
const BINARY_PROPERTIES: &[&str] = &["PHOTO", "LOGO", "SOUND", "KEY"];

/// How much of a binary property's value is kept, so a link can be shown. The
/// rest is only counted.
const URI_KEEP: usize = 2048;

/// A binary property as it streams past.
struct BinaryProperty {
    name: String,
    params: String,
    head: String,
    base64_chars: usize,
    /// 2.1 writes an unindented base64 block ended by a blank line.
    block: bool,
}

impl BinaryProperty {
    fn absorb(&mut self, value: &[u8]) {
        if self.head.len() < URI_KEEP {
            let room = URI_KEEP - self.head.len();
            self.head
                .push_str(&String::from_utf8_lossy(&value[..value.len().min(room)]));
        }
        self.base64_chars += value
            .iter()
            .filter(|b| b.is_ascii_alphanumeric() || **b == b'+' || **b == b'/')
            .count();
    }

    fn decoded_len(&self) -> usize {
        self.base64_chars * 3 / 4
    }

    /// What this property says about the contact's photo. `None` for an empty
    /// value.
    fn classify(&self) -> Option<SourcePhoto> {
        let value = self.head.trim();
        if value.is_empty() {
            return None;
        }
        let lower = value.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("data:") {
            let media_type = rest
                .split([';', ','])
                .next()
                .filter(|m| !m.is_empty())
                .map(str::to_string);
            let payload = value.split_once(',').map_or("", |(_, p)| p);
            let chars = payload
                .bytes()
                .filter(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
                .count();
            // The head is capped, so a long data URI is measured by the
            // running count instead.
            let chars = chars.max(
                self.base64_chars
                    .saturating_sub(value.len() - payload.len()),
            );
            return Some(SourcePhoto::Inline {
                media_type,
                byte_len: chars * 3 / 4,
            });
        }
        let params = self.params.to_ascii_uppercase();
        let is_link = lower.starts_with("http://")
            || lower.starts_with("https://")
            || params.contains("VALUE=URI")
            || params.contains("VALUE=URL");
        if is_link {
            return Some(SourcePhoto::Uri(sanitize_invisible(value).into_owned()));
        }
        Some(SourcePhoto::Inline {
            media_type: media_type_from_params(&params),
            byte_len: self.decoded_len(),
        })
    }
}

/// `TYPE=JPEG` (2.1, 3.0) or `MEDIATYPE=image/jpeg` (4.0), as a media type.
fn media_type_from_params(params: &str) -> Option<String> {
    for param in params.split(';') {
        let Some((name, value)) = param.split_once('=') else {
            // 2.1 writes a bare `;JPEG`.
            if matches!(param, "JPEG" | "PNG" | "GIF" | "BMP") {
                return Some(format!("image/{}", param.to_ascii_lowercase()));
            }
            continue;
        };
        let value = value.trim_matches('"');
        match name {
            "MEDIATYPE" => return Some(value.to_ascii_lowercase()),
            "TYPE" if !value.contains('/') => {
                return Some(format!("image/{}", value.to_ascii_lowercase()));
            }
            "TYPE" => return Some(value.to_ascii_lowercase()),
            _ => {}
        }
    }
    None
}

/// One card as its lines arrive.
struct CardBuilder {
    ordinal: u32,
    line: u32,
    text: Vec<u8>,
    over_cap: bool,
    binary: Option<BinaryProperty>,
    /// The previous line was a quoted-printable soft break, so this one
    /// continues it without a leading space (2.1).
    qp_continues: bool,
    photo: Option<SourcePhoto>,
    photo_too_large: bool,
    dropped_binary: BTreeSet<String>,
    first_property: Option<String>,
}

impl CardBuilder {
    fn new(ordinal: u32, line: u32) -> Self {
        Self {
            ordinal,
            line,
            text: Vec::new(),
            over_cap: false,
            binary: None,
            qp_continues: false,
            photo: None,
            photo_too_large: false,
            dropped_binary: BTreeSet::new(),
            first_property: None,
        }
    }

    fn push_line(&mut self, line: &[u8], limits: Limits) {
        let continuation = line.first().is_some_and(|b| *b == b' ' || *b == b'\t');
        if let Some(binary) = self.binary.as_mut() {
            if continuation {
                binary.absorb(&line[1..]);
                return;
            }
            if binary.block && !line.is_empty() && !line.contains(&b':') {
                binary.absorb(line);
                return;
            }
            self.end_binary(limits);
            if line.is_empty() {
                return;
            }
        }
        if self.qp_continues || continuation {
            self.qp_continues = self.qp_continues && line.ends_with(b"=");
            self.append(line, limits);
            return;
        }
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            // Not a property line. The parser skips it; kept so it does.
            self.append(line, limits);
            return;
        };
        let header = &line[..colon];
        let name_end = header
            .iter()
            .position(|b| *b == b';')
            .unwrap_or(header.len());
        let qualified = String::from_utf8_lossy(&header[..name_end]).to_ascii_uppercase();
        let name = qualified.rsplit('.').next().unwrap_or("").to_string();
        let params = String::from_utf8_lossy(&header[name_end..]).into_owned();

        if BINARY_PROPERTIES.contains(&name.as_str()) {
            let upper = params.to_ascii_uppercase();
            let mut binary = BinaryProperty {
                name,
                block: upper.contains("ENCODING=BASE64") || upper.contains("ENCODING=B"),
                params,
                head: String::new(),
                base64_chars: 0,
            };
            binary.absorb(&line[colon + 1..]);
            self.binary = Some(binary);
            return;
        }
        if name != "VERSION" && self.first_property.is_none() {
            let shown: String = String::from_utf8_lossy(line).chars().take(80).collect();
            self.first_property = Some(sanitize_invisible(&shown).trim().to_string());
        }
        self.qp_continues =
            params.to_ascii_uppercase().contains("QUOTED-PRINTABLE") && line.ends_with(b"=");
        self.append(line, limits);
    }

    fn append(&mut self, line: &[u8], limits: Limits) {
        if self.over_cap {
            return;
        }
        if self.text.len() + line.len() + 2 > limits.max_card_bytes {
            self.over_cap = true;
            return;
        }
        self.text.extend_from_slice(line);
        self.text.extend_from_slice(b"\r\n");
    }

    fn end_binary(&mut self, limits: Limits) {
        let Some(binary) = self.binary.take() else {
            return;
        };
        if binary.name == "PHOTO" && self.photo.is_none() {
            let photo = binary.classify();
            if let Some(SourcePhoto::Inline { byte_len, .. }) = &photo {
                self.photo_too_large = *byte_len > limits.max_photo_bytes;
            }
            self.photo = photo;
        } else if binary.name != "PHOTO" && !binary.head.trim().is_empty() {
            self.dropped_binary.insert(binary.name);
        }
    }

    fn problem(&self, reason: &str) -> CardProblem {
        CardProblem {
            card: self.ordinal,
            line: self.line,
            hint: self
                .first_property
                .clone()
                .unwrap_or_else(|| "(empty card)".to_string()),
            reason: reason.to_string(),
        }
    }
}

/// Decode, parse and convert one complete card.
fn finish(mut card: CardBuilder, limits: Limits, file: &mut VcardFile) {
    card.end_binary(limits);
    if card.over_cap {
        file.failures.push(card.problem(&format!(
            "The card is larger than {} KB, not counting its photo, so it was skipped.",
            limits.max_card_bytes / 1024
        )));
        return;
    }
    let text = decode_card(&card.text);
    let wrapped = format!("BEGIN:VCARD\r\n{text}END:VCARD\r\n");
    let mut parser = Parser::new(&wrapped);
    let vcard = loop {
        match parser.entry() {
            Entry::VCard(vcard) => break Some(vcard),
            Entry::Eof => break None,
            // Lines the parser could not place are skipped by it, the
            // lenient behaviour this module relies on.
            _ => continue,
        }
    };
    let Some(vcard) = vcard else {
        file.failures
            .push(card.problem("The card could not be read as a vCard, so it was skipped."));
        return;
    };
    match convert(&vcard, &text, &card) {
        Converted::Contact(contact) => {
            if card.photo_too_large {
                file.warnings.push(card.problem(&format!(
                    "The photo is larger than {} MB and was ignored. Photos are not imported.",
                    limits.max_photo_bytes / (1024 * 1024)
                )));
            }
            file.contacts.push(*contact);
        }
        Converted::GroupCard => file.group_cards += 1,
        Converted::Empty => file.failures.push(card.problem(
            "The card has no name, email address, phone number or organisation, so it was skipped.",
        )),
    }
}

/// A card's bytes as text: UTF-8 when they are, else the card's own
/// `CHARSET`, else Windows-1252.
fn decode_card(bytes: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }
    let encoding = charset_label(bytes)
        .and_then(|label| encoding_rs::Encoding::for_label(label.as_bytes()))
        .unwrap_or(encoding_rs::WINDOWS_1252);
    encoding.decode_without_bom_handling(bytes).0.into_owned()
}

/// The first `CHARSET=` parameter's value.
fn charset_label(bytes: &[u8]) -> Option<String> {
    let at = bytes
        .windows(8)
        .position(|w| w.eq_ignore_ascii_case(b"CHARSET="))?;
    let rest = &bytes[at + 8..];
    let end = rest
        .iter()
        .position(|b| matches!(b, b';' | b':' | b'\r' | b'\n'))
        .unwrap_or(rest.len());
    let label = std::str::from_utf8(&rest[..end])
        .ok()?
        .trim_matches('"')
        .trim();
    (!label.is_empty()).then(|| label.to_string())
}

/// A digest of what a card says, stable across the things that do not change
/// what it says: property order, line folding, and the `REV` / `PRODID` an
/// exporter stamps on every export.
pub fn content_hash(text: &str) -> String {
    let unfolded = text
        .replace("\r\n ", "")
        .replace("\r\n\t", "")
        .replace("\n ", "")
        .replace("\n\t", "");
    let mut lines: Vec<&str> = unfolded
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.trim().is_empty())
        .filter(|l| {
            let name = l.split([';', ':']).next().unwrap_or("");
            let name = name.rsplit('.').next().unwrap_or("");
            !name.eq_ignore_ascii_case("REV") && !name.eq_ignore_ascii_case("PRODID")
        })
        .collect();
    lines.sort_unstable();
    hex(&Sha256::digest(lines.join("\n").as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A `UID` longer than this is stored as its digest, so an external id always
/// fits `contact_sync_links.external_id` (VARCHAR 255) with its prefix.
const UID_MAX: usize = 200;

enum Converted {
    Contact(Box<SourceContact>),
    GroupCard,
    Empty,
}

fn clean(value: &str) -> Option<String> {
    let clean = sanitize_invisible(value);
    let trimmed = clean.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn texts(entry: &VCardEntry) -> impl Iterator<Item = &str> {
    entry.values.iter().filter_map(|v| match v {
        VCardValue::Text(t) => Some(t.as_str()),
        _ => None,
    })
}

fn first_text(entry: &VCardEntry) -> Option<String> {
    texts(entry).find_map(clean)
}

fn text_at(entry: &VCardEntry, index: usize) -> Option<String> {
    match entry.values.get(index) {
        Some(VCardValue::Text(t)) => clean(t),
        _ => None,
    }
}

/// Apple writes its built-in labels as `_$!<Mobile>!$_` and a person's own as
/// plain text. Both come out lowercased, which is how `mapping` reads a label.
fn apple_label(raw: &str) -> Option<String> {
    let inner = raw
        .strip_prefix("_$!<")
        .and_then(|r| r.strip_suffix(">!$_"))
        .unwrap_or(raw);
    clean(inner).map(|l| l.to_lowercase())
}

/// How strongly a property is marked preferred: lower is stronger, and an
/// unmarked property sorts after every marked one.
fn pref_rank(entry: &VCardEntry) -> u32 {
    let mut rank = u32::MAX;
    for param in &entry.params {
        match (&param.name, &param.value) {
            (VCardParameterName::Pref, VCardParameterValue::Integer(n)) => rank = rank.min(*n),
            (VCardParameterName::Pref, _) => rank = rank.min(1),
            (VCardParameterName::Type, VCardParameterValue::Text(t))
                if t.eq_ignore_ascii_case("pref") =>
            {
                rank = rank.min(1)
            }
            (VCardParameterName::Other(name), VCardParameterValue::Null)
                if name.eq_ignore_ascii_case("pref") =>
            {
                rank = rank.min(1)
            }
            _ => {}
        }
    }
    rank
}

/// The `TYPE` words on a property, lowercased, including 2.1's bare ones.
fn type_words(entry: &VCardEntry) -> Vec<String> {
    let mut words = Vec::new();
    for param in &entry.params {
        match (&param.name, &param.value) {
            (VCardParameterName::Type, VCardParameterValue::Type(t)) => {
                words.push(type_word(t).to_string())
            }
            (VCardParameterName::Type, VCardParameterValue::Text(t)) => {
                words.extend(t.split(',').map(|w| w.trim().to_lowercase()))
            }
            (VCardParameterName::Other(name), VCardParameterValue::Null) => {
                words.push(name.to_lowercase())
            }
            _ => {}
        }
    }
    words.retain(|w| !matches!(w.as_str(), "" | "pref" | "internet" | "x400" | "voice"));
    words
}

fn type_word(t: &VCardType) -> &'static str {
    match t {
        VCardType::Work => "work",
        VCardType::Home => "home",
        VCardType::Cell => "cell",
        VCardType::Fax => "fax",
        VCardType::Voice => "voice",
        VCardType::Pager => "pager",
        VCardType::Text => "text",
        VCardType::Video => "video",
        VCardType::Textphone => "textphone",
        VCardType::MainNumber => "main",
        VCardType::Billing => "billing",
        _ => "",
    }
}

/// A phone's label in the words `mapping::MappedPhoneType::from_label` reads.
fn phone_label(types: &[String]) -> Option<String> {
    let has = |w: &str| types.iter().any(|t| t == w);
    if has("fax") {
        return Some(match (has("home"), has("work")) {
            (true, _) => "home fax".into(),
            (_, true) => "work fax".into(),
            _ => "fax".into(),
        });
    }
    if has("cell") {
        return Some("mobile".into());
    }
    for word in ["work", "home"] {
        if has(word) {
            return Some(word.into());
        }
    }
    types.first().cloned()
}

fn is_group_card(card: &VCard) -> bool {
    card.entries.iter().any(|e| match &e.name {
        VCardProperty::Kind => e
            .values
            .iter()
            .any(|v| matches!(v, VCardValue::Kind(VCardKind::Group))),
        VCardProperty::Other(name) if name.eq_ignore_ascii_case("X-ADDRESSBOOKSERVER-KIND") => {
            texts(e).any(|t| t.trim().eq_ignore_ascii_case("group"))
        }
        _ => false,
    })
}

fn convert(card: &VCard, text: &str, raw: &CardBuilder) -> Converted {
    if is_group_card(card) {
        return Converted::GroupCard;
    }
    // Apple's custom labels live on a sibling property in the same group.
    let mut labels: BTreeMap<String, String> = BTreeMap::new();
    for entry in &card.entries {
        if let (VCardProperty::Other(name), Some(group)) = (&entry.name, &entry.group) {
            if name.eq_ignore_ascii_case("X-ABLABEL") {
                if let Some(label) = texts(entry).find_map(apple_label) {
                    labels.insert(group.to_lowercase(), label);
                }
            }
        }
    }
    let group_label = |entry: &VCardEntry| {
        entry
            .group
            .as_ref()
            .and_then(|g| labels.get(&g.to_lowercase()).cloned())
    };

    let mut uid = None;
    let mut display_name = None;
    let (mut given_name, mut family_name) = (None, None);
    let mut emails: Vec<(u32, SourceEmail)> = Vec::new();
    let mut phones: Vec<SourcePhone> = Vec::new();
    let (mut organization, mut department, mut title) = (None, None, None);
    let mut categories: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut dropped: BTreeSet<String> = raw.dropped_binary.clone();

    for entry in &card.entries {
        match &entry.name {
            VCardProperty::Uid => uid = uid.or_else(|| first_text(entry)),
            VCardProperty::Fn => display_name = display_name.or_else(|| first_text(entry)),
            VCardProperty::N if given_name.is_none() && family_name.is_none() => {
                family_name = text_at(entry, 0);
                given_name = text_at(entry, 1);
            }
            VCardProperty::Email => {
                if let Some(address) = first_text(entry) {
                    let label = group_label(entry).or_else(|| type_words(entry).first().cloned());
                    emails.push((pref_rank(entry), SourceEmail { address, label }));
                }
            }
            VCardProperty::Tel => {
                if let Some(value) = first_text(entry) {
                    let number = value
                        .strip_prefix("tel:")
                        .or_else(|| value.strip_prefix("TEL:"))
                        .map(str::to_string)
                        .unwrap_or(value);
                    let label = group_label(entry).or_else(|| phone_label(&type_words(entry)));
                    phones.push(SourcePhone {
                        number,
                        canonical: None,
                        label,
                        is_primary: pref_rank(entry) != u32::MAX,
                    });
                }
            }
            VCardProperty::Org if organization.is_none() => {
                organization = text_at(entry, 0);
                department = text_at(entry, 1);
            }
            VCardProperty::Title => title = title.or_else(|| first_text(entry)),
            VCardProperty::Categories => {
                for category in texts(entry).filter_map(clean) {
                    if !categories
                        .iter()
                        .any(|c| c.to_lowercase() == category.to_lowercase())
                    {
                        categories.push(category);
                    }
                }
            }
            VCardProperty::Note => notes.extend(texts(entry).filter_map(clean)),
            VCardProperty::Version
            | VCardProperty::Prodid
            | VCardProperty::Rev
            | VCardProperty::Begin
            | VCardProperty::End
            | VCardProperty::Kind
            | VCardProperty::N
            | VCardProperty::Org
            | VCardProperty::Photo => {}
            // Vendor extensions (`X-ABUID`, `X-SOCIALPROFILE`, ...) are
            // noise to a person reading what an import left behind.
            VCardProperty::Other(name) if name.to_ascii_uppercase().starts_with("X-") => {}
            other => {
                dropped.insert(other.as_str().to_ascii_uppercase());
            }
        }
    }

    if display_name.is_none()
        && given_name.is_none()
        && family_name.is_none()
        && emails.is_empty()
        && phones.is_empty()
        && organization.is_none()
    {
        return Converted::Empty;
    }

    // Stable, so equally ranked addresses keep the file's order.
    emails.sort_by_key(|(rank, _)| *rank);
    let digest = content_hash(text);
    let external_id = match uid {
        Some(uid) if uid.chars().count() <= UID_MAX => uid,
        Some(uid) => format!("uid-sha256:{}", hex(&Sha256::digest(uid.as_bytes()))),
        None => format!("sha256:{digest}"),
    };

    Converted::Contact(Box::new(SourceContact {
        external_id,
        etag: Some(digest),
        display_name,
        given_name,
        family_name,
        emails: emails.into_iter().map(|(_, e)| e).collect(),
        phones,
        organization,
        title,
        department,
        group_ids: categories,
        note: (!notes.is_empty()).then(|| notes.join("\n\n")),
        photo: raw.photo.clone(),
        dropped_properties: dropped.into_iter().collect(),
        deleted: false,
    }))
}

/// One spelling per category across the file (the first seen), so `Client`
/// on one card and `client` on another are one group with one count, and
/// every contact names it the way the group list does.
fn canonicalise_groups(file: &mut VcardFile) {
    let mut spelling: BTreeMap<String, String> = BTreeMap::new();
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for contact in &mut file.contacts {
        for id in &mut contact.group_ids {
            let key = id.to_lowercase();
            let canonical = spelling.entry(key.clone()).or_insert_with(|| id.clone());
            *id = canonical.clone();
            *counts.entry(key).or_default() += 1;
        }
    }
    file.groups = spelling
        .into_iter()
        .map(|(key, name)| SourceGroup {
            id: name.clone(),
            name,
            member_count: counts.get(&key).copied(),
        })
        .collect();
}

#[cfg(test)]
mod tests {
    use super::super::mapping::{map_contact, MappedPhoneType};
    use super::*;

    fn read(bytes: &[u8]) -> VcardFile {
        read_vcards(bytes, Limits::DEFAULT).expect("readable")
    }

    fn only(file: &VcardFile) -> &SourceContact {
        assert_eq!(file.contacts.len(), 1, "{file:#?}");
        &file.contacts[0]
    }

    /// Outlook 2.1: quoted-printable with a `CHARSET`, a soft line break, bare
    /// types, `ORG` units.
    #[test]
    fn an_outlook_2_1_card_decodes_quoted_printable_and_its_charset() {
        let file = read(
            b"BEGIN:VCARD\r\nVERSION:2.1\r\n\
N;CHARSET=ISO-8859-1;ENCODING=QUOTED-PRINTABLE:M=FCller;J=F6rg\r\n\
FN;CHARSET=ISO-8859-1;ENCODING=QUOTED-PRINTABLE:J=F6rg M=FCller\r\n\
TEL;WORK;VOICE:+1 555 0100\r\nTEL;CELL;PREF:+1 555 0101\r\nTEL;HOME;FAX:+1 555 0102\r\n\
EMAIL;PREF;INTERNET:jorg@example.com\r\nORG:Acme;Sales;EMEA\r\n\
NOTE;ENCODING=QUOTED-PRINTABLE:line one=0D=0Aline =\r\ntwo\r\nEND:VCARD\r\n",
        );
        let c = only(&file);
        assert_eq!(c.family_name.as_deref(), Some("Müller"));
        assert_eq!(c.given_name.as_deref(), Some("Jörg"));
        assert_eq!(c.organization.as_deref(), Some("Acme"));
        assert_eq!(c.department.as_deref(), Some("Sales"));
        assert_eq!(c.note.as_deref(), Some("line one\r\nline two"));
        let labels: Vec<_> = c.phones.iter().map(|p| p.label.as_deref()).collect();
        assert_eq!(labels, vec![Some("work"), Some("mobile"), Some("home fax")]);
        assert!(c.phones[1].is_primary && !c.phones[0].is_primary);
        let mapped = map_contact(c);
        assert_eq!(
            (mapped.first_name.as_str(), mapped.last_name.as_str()),
            ("Jörg", "Müller")
        );
        let types: Vec<_> = mapped.phones.iter().map(|p| p.phone_type).collect();
        assert_eq!(
            types,
            vec![
                MappedPhoneType::Work,
                MappedPhoneType::Mobile,
                MappedPhoneType::Fax
            ]
        );
    }

    /// Outlook also writes raw 8-bit Windows-1252, which is not UTF-8.
    #[test]
    fn a_raw_8_bit_windows_1252_card_is_transcoded_not_mangled() {
        let mut bytes = b"BEGIN:VCARD\r\nVERSION:2.1\r\nN;CHARSET=Windows-1252:M".to_vec();
        bytes.extend_from_slice(&[0xFC]);
        bytes.extend_from_slice(b"ller;J");
        bytes.extend_from_slice(&[0xF6]);
        bytes.extend_from_slice(b"rg\r\nORG:Acme ");
        bytes.extend_from_slice(&[0x96]);
        bytes.extend_from_slice(b" GmbH\r\nEND:VCARD\r\n");
        let file = read(&bytes);
        let c = only(&file);
        assert_eq!(c.family_name.as_deref(), Some("Müller"));
        assert_eq!(c.organization.as_deref(), Some("Acme – GmbH"));
    }

    /// With no `CHARSET` label at all, Windows-1252 is the reading.
    #[test]
    fn an_unlabelled_8_bit_card_is_read_as_windows_1252() {
        let mut bytes = b"BEGIN:VCARD\r\nVERSION:2.1\r\nFN:Ren".to_vec();
        bytes.push(0xE9);
        bytes.extend_from_slice(b"e\r\nEND:VCARD\r\n");
        assert_eq!(only(&read(&bytes)).display_name.as_deref(), Some("Renée"));
    }

    /// Some Windows exports are UTF-16 with a byte-order mark.
    #[test]
    fn a_utf_16_file_is_read() {
        let text = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Zoë Ångström\r\nEND:VCARD\r\n";
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(
            only(&read(&bytes)).display_name.as_deref(),
            Some("Zoë Ångström")
        );
    }

    /// iPhone 3.0: folded lines, escapes, a UTF-8 BOM, non-Latin script, and
    /// Apple's grouped custom labels kept on the property they belong to.
    #[test]
    fn an_iphone_card_keeps_grouped_labels_on_the_right_property() {
        let file = read(
            "\u{FEFF}BEGIN:VCARD\r\nVERSION:3.0\r\nPRODID:-//Apple Inc.//iPhone OS 17.0//EN\r\n\
N:王;小明;;;\r\nFN:王小明\r\n\
item1.TEL;type=pref:+86 10 1234 5678\r\nitem1.X-ABLabel:_$!<Mobile>!$_\r\n\
item2.EMAIL;type=INTERNET:wang@example.cn\r\nitem2.X-ABLabel:Billing desk\r\n\
item3.EMAIL;type=INTERNET;type=pref:wang.pref@example.cn\r\nitem3.X-ABLabel:_$!<Work>!$_\r\n\
NOTE:a\\, b\\; c\\nnext line that is long enough to have been folded by the\r\n  exporter\r\n\
X-ABUID:1234:ABPerson\r\nEND:VCARD\r\n"
                .as_bytes(),
        );
        let c = only(&file);
        assert_eq!(c.display_name.as_deref(), Some("王小明"));
        assert_eq!(c.given_name.as_deref(), Some("小明"));
        assert_eq!(c.phones[0].label.as_deref(), Some("mobile"));
        assert!(c.phones[0].is_primary);
        let emails: Vec<_> = c
            .emails
            .iter()
            .map(|e| (e.address.as_str(), e.label.as_deref()))
            .collect();
        assert_eq!(
            emails,
            vec![
                ("wang.pref@example.cn", Some("work")),
                ("wang@example.cn", Some("billing desk"))
            ],
            "the preferred address first, each with its own label"
        );
        assert_eq!(
            c.note.as_deref(),
            Some("a, b; c\nnext line that is long enough to have been folded by the exporter")
        );
        assert!(
            c.dropped_properties.is_empty(),
            "{:?}",
            c.dropped_properties
        );
    }

    /// 4.0: `PREF=1` outranks `PREF=2`, a `tel:` URI is a number, and the
    /// properties with no Mokosh home are named.
    #[test]
    fn a_4_0_card_orders_by_pref_and_names_what_it_leaves_behind() {
        let c = read(
            b"BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Grace Hopper\r\n\
EMAIL;TYPE=home;PREF=2:grace@home.example\r\nEMAIL;TYPE=work;PREF=1:grace@navy.example\r\n\
TEL;VALUE=uri;TYPE=\"voice,cell\":tel:+1-555-0100\r\n\
ADR;TYPE=work:;;1 Navy Way;Arlington;VA;22201;USA\r\nBDAY:19061209\r\nURL:https://navy.example\r\n\
END:VCARD\r\n",
        );
        let c = only(&c);
        assert_eq!(c.emails[0].address, "grace@navy.example");
        assert_eq!(c.phones[0].number, "+1-555-0100");
        assert_eq!(c.phones[0].label.as_deref(), Some("mobile"));
        assert_eq!(c.dropped_properties, vec!["ADR", "BDAY", "URL"]);
    }

    /// Either name property can be missing.
    #[test]
    fn a_card_with_only_fn_and_a_card_with_only_n_both_import() {
        let file = read(
            b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Prince\r\nEND:VCARD\r\n\
BEGIN:VCARD\r\nVERSION:3.0\r\nN:Lovelace;Ada;;;\r\nEND:VCARD\r\n",
        );
        assert_eq!(file.contacts.len(), 2);
        assert_eq!(map_contact(&file.contacts[0]).first_name, "Prince");
        let ada = map_contact(&file.contacts[1]);
        assert_eq!(
            (ada.first_name.as_str(), ada.last_name.as_str()),
            ("Ada", "Lovelace")
        );
    }

    /// The case the whole-file parser lost: an unterminated card no longer
    /// swallows its neighbour, and a truncated last card is reported rather
    /// than accepted.
    #[test]
    fn a_broken_card_is_reported_and_the_rest_of_the_file_imports() {
        let file = read(
            b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:First\r\nEND:VCARD\r\n\
BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Broken\r\n\
BEGIN:VCARD\r\nVERSION:4.0\r\nN:Kept;Neighbour;;;\r\nEND:VCARD\r\n\
BEGIN:VCARD\r\nVERSION:3.0\r\nEND:VCARD\r\n\
BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Truncated\r\n",
        );
        let names: Vec<_> = file
            .contacts
            .iter()
            .map(|c| map_contact(c).first_name)
            .collect();
        assert_eq!(names, vec!["First", "Neighbour"]);
        assert_eq!(file.cards, 5);
        let failed: Vec<(u32, &str)> = file
            .failures
            .iter()
            .map(|p| (p.card, p.hint.as_str()))
            .collect();
        assert_eq!(
            failed,
            vec![(2, "FN:Broken"), (4, "(empty card)"), (5, "FN:Truncated")]
        );
        assert!(file.failures[0].reason.contains("no END:VCARD"));
        assert_eq!(file.failures[0].line, 5);
        assert!(file.failures[2].reason.contains("ends before"));
    }

    /// A photo link is carried as text for the preview and never requested,
    /// and a card with one still imports.
    #[test]
    fn a_remote_photo_is_kept_as_text_and_not_fetched() {
        let c = read(
            b"BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Linked\r\n\
PHOTO:http://169.254.169.254/latest/meta-data/\r\nEND:VCARD\r\n",
        );
        assert_eq!(
            only(&c).photo,
            Some(SourcePhoto::Uri(
                "http://169.254.169.254/latest/meta-data/".into()
            ))
        );
    }

    /// The module that reads the photo link cannot fetch it: it holds no
    /// network client of any kind. A source scan, because "no outbound
    /// request" is a property of what this code is able to do, and a behaviour
    /// test can only sample it.
    #[test]
    fn this_module_has_no_way_to_make_a_request() {
        let source = include_str!("vcard.rs");
        let code = source.split("#[cfg(test)]").next().expect("code half");
        for client in [
            "reqwest",
            "hyper",
            "ureq",
            "TcpStream",
            "UdpSocket",
            "ToSocketAddrs",
            "lookup_host",
            "guard_outbound_url",
        ] {
            assert!(!code.contains(client), "vcard.rs names {client}");
        }
    }

    /// An embedded photo is measured and discarded before the parser sees it,
    /// in the folded 3.0 form and the unindented 2.1 block form.
    #[test]
    fn an_embedded_photo_is_measured_and_never_kept() {
        let file = read(
            b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Folded\r\n\
PHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQSkZJRgABAQ\r\n AAAQABAAD/2wBDAAgGBgcG\r\nEND:VCARD\r\n\
BEGIN:VCARD\r\nVERSION:2.1\r\nFN:Block\r\nPHOTO;JPEG;ENCODING=BASE64:\r\n\
/9j/4AAQSkZJRgABAQ\r\nAAAQABAAD/2wBDAAgGBgcG\r\n\r\nEMAIL:block@example.com\r\nEND:VCARD\r\n",
        );
        assert_eq!(file.contacts.len(), 2, "{file:#?}");
        for c in &file.contacts {
            match &c.photo {
                Some(SourcePhoto::Inline {
                    media_type,
                    byte_len,
                }) => {
                    assert_eq!(media_type.as_deref(), Some("image/jpeg"));
                    assert_eq!(*byte_len, 30);
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(
            file.contacts[1].emails[0].address, "block@example.com",
            "the property after a 2.1 base64 block is read"
        );
        assert!(file.warnings.is_empty());
    }

    /// A photo over the limit costs the photo (which is never imported) and a
    /// warning, not the contact.
    #[test]
    fn an_oversized_photo_is_a_warning_not_a_failure() {
        let limits = Limits {
            max_photo_bytes: 10,
            ..Limits::DEFAULT
        };
        let file = read_vcards(
            &b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Big Photo\r\n\
PHOTO;ENCODING=b;TYPE=PNG:iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB\r\nEND:VCARD\r\n"[..],
            limits,
        )
        .expect("readable");
        assert_eq!(file.contacts.len(), 1);
        assert!(file.warnings[0].reason.contains("photo"), "{file:#?}");
    }

    /// The whole file and its card count are bounded, with messages a person
    /// can act on.
    #[test]
    fn a_file_over_the_limits_is_refused_with_a_clear_message() {
        let card = b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:A\r\nEND:VCARD\r\n";
        let big = card.repeat(100);
        let refused = read_vcards(
            &big[..],
            Limits {
                max_file_bytes: 1024,
                ..Limits::DEFAULT
            },
        );
        assert_eq!(refused, Err(ReadError::FileTooLarge { limit_bytes: 1024 }));
        let many = read_vcards(
            &big[..],
            Limits {
                max_cards: 10,
                ..Limits::DEFAULT
            },
        );
        assert_eq!(many, Err(ReadError::TooManyCards { limit: 10 }));
        assert!(ReadError::TooManyCards { limit: 5000 }
            .to_string()
            .contains("more than 5000 contacts"));
        assert!(ReadError::FileTooLarge {
            limit_bytes: 10 * 1024 * 1024
        }
        .to_string()
        .contains("larger than 10 MB"));
    }

    /// One oversized card is skipped; its neighbours are not.
    #[test]
    fn an_oversized_card_is_skipped_and_reported() {
        let mut bytes = b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Huge\r\nNOTE:".to_vec();
        bytes.extend(std::iter::repeat_n(b'x', 2048));
        bytes.extend_from_slice(
            b"\r\nEND:VCARD\r\nBEGIN:VCARD\r\nVERSION:3.0\r\nFN:Small\r\nEND:VCARD\r\n",
        );
        let file = read_vcards(
            &bytes[..],
            Limits {
                max_card_bytes: 1024,
                ..Limits::DEFAULT
            },
        )
        .expect("readable");
        assert_eq!(file.contacts.len(), 1);
        assert_eq!(file.failures[0].hint, "FN:Huge");
        assert!(file.failures[0].reason.contains("larger than 1 KB"));
    }

    /// `UID` is the identity when present; without one, the content digest
    /// is, and it ignores order, folding and the exporter's stamps.
    #[test]
    fn identity_is_the_uid_else_a_digest_that_ignores_what_does_not_matter() {
        let with_uid = read(b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:A\r\nUID:abc-123\r\nEND:VCARD\r\n");
        assert_eq!(only(&with_uid).external_id, "abc-123");

        let a = read(
            b"BEGIN:VCARD\r\nVERSION:3.0\r\nPRODID:x\r\nREV:2024-01-01\r\nFN:Ada\r\nEMAIL:ada@x.example\r\nEND:VCARD\r\n",
        );
        let b = read(
            b"BEGIN:VCARD\r\nVERSION:3.0\r\nEMAIL:ada@x.exa\r\n mple\r\nFN:Ada\r\nREV:2025-06-01\r\nEND:VCARD\r\n",
        );
        let changed =
            read(b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Ada\r\nEMAIL:ada@y.example\r\nEND:VCARD\r\n");
        let (a, b, changed) = (only(&a), only(&b), only(&changed));
        assert!(a.external_id.starts_with("sha256:"));
        assert_eq!(a.external_id, b.external_id);
        assert_eq!(a.etag, b.etag);
        assert_ne!(a.external_id, changed.external_id);

        let long_uid = format!(
            "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:A\r\nUID:{}\r\nEND:VCARD\r\n",
            "u".repeat(300)
        );
        let long = read(long_uid.as_bytes());
        assert!(only(&long).external_id.starts_with("uid-sha256:"));
        assert!(only(&long).external_id.len() <= 255);
    }

    /// `CATEGORIES` are the file's groups, counted, one spelling each.
    #[test]
    fn categories_become_the_selectable_groups() {
        let file = read(
            b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:A\r\nCATEGORIES:Client,VIP\r\nEND:VCARD\r\n\
BEGIN:VCARD\r\nVERSION:3.0\r\nFN:B\r\nCATEGORIES:client\r\nEND:VCARD\r\n\
BEGIN:VCARD\r\nVERSION:3.0\r\nFN:C\r\nEND:VCARD\r\n",
        );
        let groups: Vec<_> = file
            .groups
            .iter()
            .map(|g| (g.id.as_str(), g.member_count))
            .collect();
        assert_eq!(groups, vec![("Client", Some(2)), ("VIP", Some(1))]);
        assert_eq!(file.contacts[1].group_ids, vec!["Client"]);
    }

    /// A card describing a group is neither a contact nor a failure.
    #[test]
    fn a_group_card_is_counted_and_not_imported() {
        let file = read(
            b"BEGIN:VCARD\r\nVERSION:4.0\r\nKIND:group\r\nFN:Family\r\nEND:VCARD\r\n\
BEGIN:VCARD\r\nVERSION:3.0\r\nX-ADDRESSBOOKSERVER-KIND:group\r\nFN:Team\r\nEND:VCARD\r\n",
        );
        assert!(file.contacts.is_empty() && file.failures.is_empty());
        assert_eq!(file.group_cards, 2);
    }

    /// Cutting a real-shaped file at every byte never panics and never
    /// reports more contacts than the whole file holds.
    #[test]
    fn a_file_cut_at_any_byte_is_read_without_panicking() {
        let whole = "BEGIN:VCARD\r\nVERSION:2.1\r\n\
N;CHARSET=ISO-8859-1;ENCODING=QUOTED-PRINTABLE:M=FCller;J=F6rg\r\n\
PHOTO;JPEG;ENCODING=BASE64:\r\n/9j/4AAQ\r\n\r\nEND:VCARD\r\n\
BEGIN:VCARD\r\nVERSION:3.0\r\nitem1.TEL:+1\r\nitem1.X-ABLabel:_$!<Mobile>!$_\r\n\
NOTE:a\\,b\r\n c\r\nCATEGORIES:X,Y\r\nEND:VCARD\r\n\
BEGIN:VCARD\r\nVERSION:4.0\r\nFN:王小明\r\nPHOTO:https://x.example/p.png\r\nEND:VCARD\r\n"
            .as_bytes();
        for cut in 0..=whole.len() {
            let file = read(&whole[..cut]);
            assert!(file.contacts.len() <= 3, "cut at {cut}");
        }
    }
}
