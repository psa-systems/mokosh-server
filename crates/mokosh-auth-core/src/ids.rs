//! Strongly-typed identifiers. Each is a thin newtype around `uuid::Uuid`.
//!
//! Using distinct types (rather than passing raw `Uuid` everywhere)
//! prevents whole classes of mix-up bugs at compile time, e.g. accidentally
//! using a `ClientId` where a `UserId` is expected.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! id_newtype {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
            pub fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl From<Uuid> for $name {
            fn from(u: Uuid) -> Self {
                Self(u)
            }
        }
        impl From<$name> for Uuid {
            fn from(n: $name) -> Uuid {
                n.0
            }
        }
    };
}

id_newtype!(TenantId, "Identifier for a tenant.");
id_newtype!(UserId, "Identifier for a user.");
id_newtype!(ClientId, "Identifier for an OAuth client (the public `client_id`).");
id_newtype!(OpSessionId, "Identifier for an OP-side authentication session.");
id_newtype!(RefreshFamilyId, "Identifier for a refresh-token family.");
id_newtype!(RefreshTokenId, "Identifier for a single refresh token row.");
id_newtype!(AuthCodeId, "Identifier for an authorization-code row (logical, not the hash).");
