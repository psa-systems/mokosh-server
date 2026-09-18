//! PMS-1200: the one money formatter every rendered surface (a PDF cell, a
//! JSON `_display` field) calls, promoted out of `billing::documents` so
//! `reports::routes` and `billing::routes` can reach it too. `documents.rs`
//! kept its own copy and a JSON field grew a second, narrower one
//! (`format!("${:.2}", amount)` for USD); both are the same defect on
//! different surfaces, so there is exactly one definition now.

use rust_decimal::Decimal;

/// Always suffixed with the currency code; no special-cased `$` for USD,
/// because a document or a field that special-cases one currency disagrees
/// with every other currency it also has to print.
pub fn money(amount: Decimal, currency: Option<&str>) -> String {
    let code = currency.unwrap_or("USD");
    format!("{amount:.2} {code}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn money_says_what_it_means() {
        assert_eq!(money(Decimal::new(120000, 2), Some("AUD")), "1200.00 AUD");
        assert_eq!(money(Decimal::new(1200, 0), None), "1200.00 USD");
    }
}
