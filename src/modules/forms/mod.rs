//! PMS-731: form definitions with per-field validation.
//!
//! The substrate the PMS-730 MACD request flow consumes: define a form,
//! describe its ordered field set, validate a submission field by field, and
//! store the submission tenant-scoped.
//!
//! Built here rather than extracted from eForm. eForm's whole form-definition
//! surface is a three-field struct with no required flag and no rules, stored
//! as an opaque JSON blob; its validation is one hardcoded "email is
//! required". There was nothing to extract, and a cross-repo dependency would
//! have bought four lines.
//!
//! Scope is bounded by the MACD field list reviewed on PMS-731: six field
//! types and five rules, with numeric range and file upload deliberately
//! absent because nothing in that list needs them. See migration 100.

mod models;
mod validation;

pub use models::*;
pub use validation::validate_submission;
