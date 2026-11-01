//! Why an inbound message is quarantined: the one spelling of every reason.

use crate::itip::Rejection;

/// Why an inbound message was quarantined instead of applied. The reason is what the gateway is told (`reason`), what
/// `scheduling.reply_rejected` carries and what the audit record says; `docs/interop.md` lists them all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuarantineReason {
    /// The gateway did not report a DMARC pass.
    DmarcNotPassed,
    /// The tenant does not accept this method from mail.
    MethodNotEnabled,
    /// The method is none the endpoint takes (only `REPLY`, `REQUEST` and `CANCEL` can be forwarded).
    MethodNotSupported,
    /// `From` is not the replying attendee (or, for an invitation, the organizer).
    SenderMismatch,
    /// The reply is for a person of the tenant, who answers in their calendar.
    InternalAttendee,
    /// The `UID` names no organizer object of the tenant, or the invitation reaches nobody who has it.
    UnknownEvent,
    /// The attendee is not on the event.
    UnknownAttendee,
    /// The answer is about another version of the event than the organizer's copy.
    SequenceMismatch,
    /// An invitation or cancellation that claims a principal of the tenant as organizer.
    OrganizerIsInternal,
    /// The reply does not fit the copy (or does not have one organizer and one attendee).
    InvalidReply,
    /// An invitation or cancellation without a `UID` or an `ORGANIZER`.
    InvalidMessage,
    /// The message is not about an event.
    UnsupportedComponent,
    /// An invitation or cancellation that names nobody in the tenant.
    NoInternalRecipient,
    /// A content scanner refused an attachment of the message.
    ContentRejected,
}

impl QuarantineReason {
    /// Every reason, for the documentation check and the tests.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 14] = [
        Self::DmarcNotPassed,
        Self::MethodNotEnabled,
        Self::MethodNotSupported,
        Self::SenderMismatch,
        Self::InternalAttendee,
        Self::UnknownEvent,
        Self::UnknownAttendee,
        Self::SequenceMismatch,
        Self::OrganizerIsInternal,
        Self::InvalidReply,
        Self::InvalidMessage,
        Self::UnsupportedComponent,
        Self::NoInternalRecipient,
        Self::ContentRejected,
    ];

    /// The machine-readable reason.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::DmarcNotPassed => "dmarc_not_passed",
            Self::MethodNotEnabled => "method_not_enabled",
            Self::MethodNotSupported => "method_not_supported",
            Self::SenderMismatch => "sender_mismatch",
            Self::InternalAttendee => "internal_attendee",
            Self::UnknownEvent => "unknown_event",
            Self::UnknownAttendee => "unknown_attendee",
            Self::SequenceMismatch => "sequence_mismatch",
            Self::OrganizerIsInternal => "organizer_is_internal",
            Self::InvalidReply => "invalid_reply",
            Self::InvalidMessage => "invalid_message",
            Self::UnsupportedComponent => "unsupported_component",
            Self::NoInternalRecipient => "no_internal_recipient",
            Self::ContentRejected => "content_rejected",
        }
    }
}

impl From<Rejection> for QuarantineReason {
    fn from(rejection: Rejection) -> Self {
        match rejection {
            Rejection::UnknownEvent => Self::UnknownEvent,
            Rejection::StaleSequence => Self::SequenceMismatch,
            Rejection::InvalidReply => Self::InvalidReply,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn every_reason_has_its_own_snake_case_spelling() {
        let spellings: HashSet<&str> = QuarantineReason::ALL.iter().map(|reason| reason.as_str()).collect();
        assert_eq!(spellings.len(), QuarantineReason::ALL.len());
        for spelling in spellings {
            assert!(
                spelling.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "{spelling}"
            );
        }
    }

    #[test]
    fn a_rejected_reply_keeps_the_reason_it_always_had() {
        assert_eq!(
            QuarantineReason::from(Rejection::UnknownEvent).as_str(),
            "unknown_event"
        );
        assert_eq!(
            QuarantineReason::from(Rejection::StaleSequence).as_str(),
            "sequence_mismatch"
        );
        assert_eq!(
            QuarantineReason::from(Rejection::InvalidReply).as_str(),
            "invalid_reply"
        );
    }
}
