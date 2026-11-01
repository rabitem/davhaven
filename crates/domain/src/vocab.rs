//! iCalendar vocabulary shared by the object index, `EventData`, the entities and the mail model.
//!
//! Every enum has two textual forms: the RFC 5545/5546 token (`as_ical`/`from_ical`, upper case, used when
//! reading or writing iCalendar and in database columns) and the `snake_case` JSON form produced by serde (used by
//! the management API, MCP and webhooks).

use core::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Error returned when text is not a known value of an enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown {kind} value")]
pub struct UnknownVariant {
    kind: &'static str,
}

impl UnknownVariant {
    /// Creates the error for the named enumeration.
    pub(crate) const fn new(kind: &'static str) -> Self {
        Self { kind }
    }

    /// The name of the enumeration that rejected the value.
    pub const fn kind(&self) -> &'static str {
        self.kind
    }
}

/// Defines a closed vocabulary enum with RFC tokens, `ALL`, `Display` and `snake_case` serde.
macro_rules! ical_enum {
    (
        $(#[$meta:meta])*
        $name:ident [$($extra:ident),*] {
            $( $(#[$vmeta:meta])* $variant:ident => $token:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema $(, $extra)*)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $( $(#[$vmeta])* $variant ),+
        }

        impl $name {
            /// Every value, in declaration order.
            pub const ALL: &'static [Self] = &[ $( Self::$variant ),+ ];

            /// The RFC token in upper case, as written in iCalendar data.
            pub const fn as_ical(self) -> &'static str {
                match self {
                    $( Self::$variant => $token ),+
                }
            }

            /// Parses the RFC token, ignoring ASCII case; `None` for unknown values.
            pub fn from_ical(token: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|value| value.as_ical().eq_ignore_ascii_case(token))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_ical())
            }
        }
    };
}

ical_enum!(
    /// Calendar component types that can be stored in a calendar object resource.
    ComponentKind [] {
        /// `VEVENT`.
        Event => "VEVENT",
        /// `VTODO`.
        Todo => "VTODO",
        /// `VJOURNAL`.
        Journal => "VJOURNAL",
    }
);

ical_enum!(
    /// Participation status of an attendee (`PARTSTAT`).
    PartStat [Default] {
        /// `NEEDS-ACTION`: no answer yet.
        #[default]
        NeedsAction => "NEEDS-ACTION",
        /// `ACCEPTED`.
        Accepted => "ACCEPTED",
        /// `DECLINED`.
        Declined => "DECLINED",
        /// `TENTATIVE`.
        Tentative => "TENTATIVE",
        /// `DELEGATED`.
        Delegated => "DELEGATED",
        /// `COMPLETED` (to-dos).
        Completed => "COMPLETED",
        /// `IN-PROCESS` (to-dos).
        InProcess => "IN-PROCESS",
    }
);

impl PartStat {
    /// Whether an attendee may answer with this value on the RSVP page and in MCP/API responses.
    pub const fn is_answer(self) -> bool {
        matches!(self, Self::Accepted | Self::Declined | Self::Tentative)
    }
}

ical_enum!(
    /// Calendar user type of an attendee (`CUTYPE`).
    CuType [Default] {
        /// `INDIVIDUAL` (the default).
        #[default]
        Individual => "INDIVIDUAL",
        /// `GROUP`.
        Group => "GROUP",
        /// `RESOURCE`.
        Resource => "RESOURCE",
        /// `ROOM`.
        Room => "ROOM",
        /// `UNKNOWN`.
        Unknown => "UNKNOWN",
    }
);

ical_enum!(
    /// Participation role of an attendee (`ROLE`).
    Role [Default] {
        /// `CHAIR`.
        Chair => "CHAIR",
        /// `REQ-PARTICIPANT` (the default).
        #[default]
        ReqParticipant => "REQ-PARTICIPANT",
        /// `OPT-PARTICIPANT`.
        OptParticipant => "OPT-PARTICIPANT",
        /// `NON-PARTICIPANT`.
        NonParticipant => "NON-PARTICIPANT",
    }
);

ical_enum!(
    /// Who performs scheduling for an attendee (`SCHEDULE-AGENT`, RFC 6638).
    ScheduleAgent [Default] {
        /// `SERVER` (the default): the server delivers scheduling messages.
        #[default]
        Server => "SERVER",
        /// `CLIENT`: the client takes care of it; the server never delivers.
        Client => "CLIENT",
        /// `NONE`: no scheduling messages at all.
        None => "NONE",
    }
);

ical_enum!(
    /// Whether an event blocks time (`TRANSP`).
    Transparency [Default] {
        /// `OPAQUE` (the default): counts as busy.
        #[default]
        Opaque => "OPAQUE",
        /// `TRANSPARENT`: does not block time.
        Transparent => "TRANSPARENT",
    }
);

ical_enum!(
    /// Access classification of an object (`CLASS`).
    Classification [Default] {
        /// `PUBLIC` (the default).
        #[default]
        Public => "PUBLIC",
        /// `PRIVATE`: busy-only for everyone but the owner in feeds and free-busy.
        Private => "PRIVATE",
        /// `CONFIDENTIAL`: treated like `PRIVATE`.
        Confidential => "CONFIDENTIAL",
    }
);

impl Classification {
    /// Whether non-owners may only see that the time is busy.
    pub const fn is_restricted(self) -> bool {
        matches!(self, Self::Private | Self::Confidential)
    }
}

ical_enum!(
    /// Status of an event (`STATUS` on a `VEVENT`).
    EventStatus [] {
        /// `TENTATIVE`.
        Tentative => "TENTATIVE",
        /// `CONFIRMED`.
        Confirmed => "CONFIRMED",
        /// `CANCELLED`.
        Cancelled => "CANCELLED",
    }
);

ical_enum!(
    /// The `METHOD` of an iTIP message (RFC 5546).
    ItipMethod [] {
        /// `PUBLISH`.
        Publish => "PUBLISH",
        /// `REQUEST`: an invitation or update from the organizer.
        Request => "REQUEST",
        /// `REPLY`: an attendee's answer.
        Reply => "REPLY",
        /// `ADD`.
        Add => "ADD",
        /// `CANCEL`: the organizer cancels the event or instances.
        Cancel => "CANCEL",
        /// `REFRESH`.
        Refresh => "REFRESH",
        /// `COUNTER`.
        Counter => "COUNTER",
        /// `DECLINECOUNTER`.
        DeclineCounter => "DECLINECOUNTER",
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_round_trip_for_every_value() {
        for value in ComponentKind::ALL {
            assert_eq!(ComponentKind::from_ical(value.as_ical()), Some(*value));
        }
        for value in PartStat::ALL {
            assert_eq!(PartStat::from_ical(value.as_ical()), Some(*value));
        }
        for value in CuType::ALL {
            assert_eq!(CuType::from_ical(value.as_ical()), Some(*value));
        }
        for value in Role::ALL {
            assert_eq!(Role::from_ical(value.as_ical()), Some(*value));
        }
        for value in ScheduleAgent::ALL {
            assert_eq!(ScheduleAgent::from_ical(value.as_ical()), Some(*value));
        }
        for value in Transparency::ALL {
            assert_eq!(Transparency::from_ical(value.as_ical()), Some(*value));
        }
        for value in Classification::ALL {
            assert_eq!(Classification::from_ical(value.as_ical()), Some(*value));
        }
        for value in EventStatus::ALL {
            assert_eq!(EventStatus::from_ical(value.as_ical()), Some(*value));
        }
        for value in ItipMethod::ALL {
            assert_eq!(ItipMethod::from_ical(value.as_ical()), Some(*value));
        }
    }

    #[test]
    fn parsing_ignores_case_and_rejects_unknown_tokens() {
        assert_eq!(PartStat::from_ical("needs-action"), Some(PartStat::NeedsAction));
        assert_eq!(ComponentKind::from_ical("vEvent"), Some(ComponentKind::Event));
        assert_eq!(PartStat::from_ical("MAYBE"), None);
        assert_eq!(ItipMethod::from_ical(""), None);
    }

    #[test]
    fn json_form_is_snake_case() {
        assert_eq!(
            serde_json::to_string(&PartStat::NeedsAction).unwrap(),
            "\"needs_action\""
        );
        assert_eq!(
            serde_json::to_string(&Role::ReqParticipant).unwrap(),
            "\"req_participant\""
        );
        assert_eq!(
            serde_json::to_string(&ItipMethod::DeclineCounter).unwrap(),
            "\"decline_counter\""
        );
        assert_eq!(
            serde_json::from_str::<ComponentKind>("\"journal\"").unwrap(),
            ComponentKind::Journal
        );
    }

    #[test]
    fn defaults_match_the_rfcs() {
        assert_eq!(PartStat::default(), PartStat::NeedsAction);
        assert_eq!(CuType::default(), CuType::Individual);
        assert_eq!(Role::default(), Role::ReqParticipant);
        assert_eq!(ScheduleAgent::default(), ScheduleAgent::Server);
        assert_eq!(Transparency::default(), Transparency::Opaque);
        assert_eq!(Classification::default(), Classification::Public);
    }

    #[test]
    fn answers_and_restrictions() {
        assert!(PartStat::Accepted.is_answer());
        assert!(PartStat::Declined.is_answer());
        assert!(PartStat::Tentative.is_answer());
        assert!(!PartStat::NeedsAction.is_answer());
        assert!(!PartStat::Delegated.is_answer());
        assert!(!Classification::Public.is_restricted());
        assert!(Classification::Private.is_restricted());
        assert!(Classification::Confidential.is_restricted());
    }
}
