//! MAPPS-617 (mokosh-branding prompt 001): shared branding helpers.
//!
//! Owns the tenant + Company brand merge (`effective::effective_branding`).
//! Prompt 002 extends this module with the parameterized asset store
//! (logo / favicon / background at tenant + Company scope) and the
//! Company-scoped multipart handlers; prompts 003/004 are client-side.

pub mod assets;
pub mod effective;
pub mod routes;
