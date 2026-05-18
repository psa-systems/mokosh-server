//! Time-tracking service. Endpoints land incrementally across PMS-42.

use crate::db::Database;

#[derive(Clone)]
pub struct TimeTrackingService {
    pub(super) db: Database,
}

impl TimeTrackingService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }
}
