//! Re-export of the shared time-tracking DTOs from `mokosh-types`.
//! See [`mokosh_types`] and PMS-129.

pub use mokosh_types::time_tracking::*;

/// PMS-1145: who may correct a recorded work-day segment
/// (`timesheets/segment_editing`).
///
/// Deliberately the [`NoteEditPolicy`](crate::modules::tickets::NoteEditPolicy)
/// shape rather than a new one, because it is the same question: a closed set
/// of names, validated at the write so a value outside it is refused instead
/// of read as the default, and tenant-level because the tenant IS the MSP.
///
/// Unset means [`OwnerOrAdmin`](Self::OwnerOrAdmin). There is no prior
/// behaviour to preserve - before this nobody could correct a segment at all -
/// so the default is chosen rather than inherited: the person whose day it is
/// is the one who notices the mistake, and an admin is who they would
/// otherwise have to ask.
///
/// The strict option is `off` and not "admin only", for a reason worth
/// stating: a one-person MSP has no second person to ask, so a policy that
/// excluded the owner would make a mis-tap unfixable on exactly the tenant
/// least able to absorb it. A tenant that wants attendance immutable says
/// `off` and means it for everybody.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SegmentEditPolicy {
    /// Nobody corrects a segment, the person whose day it is included. The
    /// record is append-only.
    Off,
    /// The default: the segment's own user, or an admin.
    #[default]
    OwnerOrAdmin,
    /// The segment's own user, or anyone who can manage users (`manager` and
    /// above).
    OwnerOrManager,
}

impl SegmentEditPolicy {
    /// The stored spelling, which `validate_setting_value` refuses anything
    /// outside of. `None` for a value that is none of them.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "off" => Some(Self::Off),
            "owner_or_admin" => Some(Self::OwnerOrAdmin),
            "owner_or_manager" => Some(Self::OwnerOrManager),
            _ => None,
        }
    }

    /// The stored spelling of this policy.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::OwnerOrAdmin => "owner_or_admin",
            Self::OwnerOrManager => "owner_or_manager",
        }
    }

    /// May `user` correct a segment belonging to `owner` under this policy?
    pub fn permits(self, user: &mokosh_types::auth::CurrentUser, owner: uuid::Uuid) -> bool {
        match self {
            Self::Off => false,
            Self::OwnerOrAdmin => user.id == owner || user.role.is_admin(),
            Self::OwnerOrManager => user.id == owner || user.role.can_manage_users(),
        }
    }
}

#[cfg(test)]
mod segment_edit_policy_tests {
    use super::SegmentEditPolicy;

    /// The set is closed and round-trips, because the stored string is what a
    /// tenant's row holds and a spelling that parsed one way and printed
    /// another would drift the moment anything read it back.
    #[test]
    fn the_policy_round_trips_through_its_stored_spelling() {
        for policy in [
            SegmentEditPolicy::Off,
            SegmentEditPolicy::OwnerOrAdmin,
            SegmentEditPolicy::OwnerOrManager,
        ] {
            assert_eq!(SegmentEditPolicy::parse(policy.as_str()), Some(policy));
        }
        assert_eq!(SegmentEditPolicy::parse("author_or_admin"), None);
        assert_eq!(SegmentEditPolicy::parse(""), None);
        assert_eq!(SegmentEditPolicy::parse("OWNER_OR_ADMIN"), None);
    }

    /// Unset is the permissive-enough default, not `off`: before PMS-1145
    /// nobody could correct a segment at all, so a tenant that configures
    /// nothing gets the capability rather than a locked door it never chose.
    #[test]
    fn the_default_is_owner_or_admin() {
        assert_eq!(
            SegmentEditPolicy::default(),
            SegmentEditPolicy::OwnerOrAdmin
        );
    }
}
