//! Calendar user address resolution and classification (internal, external).
//!
//! Scheduling needs to know, for every address an event names, where a message for it has to go (PLAN 2.8). The
//! addresses of an organizer's write (both versions of the attendee list, the organizer, everybody the event lists)
//! are looked up once, together (`Directory::load`: one query for the mail addresses, a few more for the other
//! forms), and each one lands in exactly one `Class`. The paths that deal with one address only (the organizer an
//! attendee answers to, the organizer of an invitation) load that one:
//!
//! | Class | Address | Message goes to |
//! | --- | --- | --- |
//! | `Class::Internal` | a user or service principal of the tenant | the principal's scheduling inbox and, by policy, a copy in the principal's calendar |
//! | `Class::Resource` | a resource principal of the tenant | like an internal one; the policy may answer for the resource |
//! | `Class::Group` | a group principal, or `CUTYPE=GROUP` | nowhere: groups are not expanded in 1.0 (`SCHEDULE-STATUS` 3.7) |
//! | `Class::External` | a mail address nobody in the tenant owns, including the addresses of other tenants | an iMIP mail |
//! | `Class::Unknown` | anything that cannot be delivered: a principal URL or `urn:uuid` that names nobody here, an address a deleted principal still holds | nowhere (`SCHEDULE-STATUS` 3.7) |
//!
//! Principal URLs and `urn:uuid` addresses name principals of this deployment only; they never leave the server
//! (PLAN 2.6). `Directory::wire_map` gives the `mailto` address every resolved principal is known by outside, which
//! `davhaven_ical::itip::rewrite_addresses` applies before a message is built.

use std::collections::{HashMap, HashSet};

use davhaven_domain::{AddressKind, CalendarUserAddress, CuType, Principal, PrincipalKind, PublicUrls, Tenant};
use davhaven_ports::Tx;

use crate::error::AppResult;
use crate::principals::find_by_addresses;

/// How scheduling treats a calendar user address.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Class {
    /// A user or service principal of the tenant: the message is delivered inside the server.
    Internal(Box<Principal>),
    /// A resource principal of the tenant: delivered inside the server, and the scheduling policy may answer.
    Resource(Box<Principal>),
    /// A group: not expanded in 1.0, the organizer's copy says `3.7`.
    Group,
    /// A mail address outside the tenant: an iMIP mail.
    External,
    /// An address that cannot be delivered anywhere.
    Unknown,
}

impl Class {
    /// The principal behind an internal or resource address.
    pub(crate) fn principal(&self) -> Option<&Principal> {
        match self {
            Self::Internal(principal) | Self::Resource(principal) => Some(principal),
            Self::Group | Self::External | Self::Unknown => None,
        }
    }
}

/// The addresses of one scheduling operation, looked up.
#[derive(Debug, Clone, Default)]
pub(crate) struct Directory {
    found: HashMap<CalendarUserAddress, Principal>,
    reserved: HashSet<CalendarUserAddress>,
}

impl Directory {
    /// Looks up `addresses` in the tenant of the transaction.
    ///
    /// Addresses that name an active principal resolve to it. A mail address that no live principal owns but a
    /// deleted one still holds stays *reserved* until the purge (PLAN 2.6): mail to it must not leave the server as
    /// if nobody owned it, so it is [`Class::Unknown`].
    ///
    /// # Errors
    ///
    /// Store failures.
    pub(crate) async fn load(
        tx: &mut dyn Tx,
        tenant: &Tenant,
        urls: &PublicUrls,
        addresses: &[CalendarUserAddress],
    ) -> AppResult<Self> {
        if addresses.is_empty() {
            return Ok(Self::default());
        }
        let found: HashMap<CalendarUserAddress, Principal> = find_by_addresses(tx, tenant, urls, addresses)
            .await?
            .into_iter()
            .collect();
        let unresolved: Vec<CalendarUserAddress> = addresses
            .iter()
            .filter(|address| address.kind() == AddressKind::Mailto && !found.contains_key(*address))
            .cloned()
            .collect();
        let reserved = if unresolved.is_empty() {
            HashSet::new()
        } else {
            // The store answers for every status, deleted principals included: whatever it finds is reserved.
            tx.principals()
                .find_by_addresses(&unresolved)
                .await?
                .into_iter()
                .map(|(address, _)| address)
                .collect()
        };
        Ok(Self { found, reserved })
    }

    /// The principal an address names, when it names one.
    pub(crate) fn principal(&self, address: &CalendarUserAddress) -> Option<&Principal> {
        self.found.get(address)
    }

    /// Whether the address is outside the tenant: [`Class::External`], without building the class (which clones the
    /// principal of an internal address).
    pub(crate) fn is_external(&self, address: &CalendarUserAddress, cutype: CuType) -> bool {
        !self.found.contains_key(address)
            && !self.reserved.contains(address)
            && cutype != CuType::Group
            && address.kind() == AddressKind::Mailto
    }

    /// Classifies an address; `cutype` is the calendar user type the event states for it.
    pub(crate) fn classify(&self, address: &CalendarUserAddress, cutype: CuType) -> Class {
        if let Some(principal) = self.found.get(address) {
            return match (principal.kind, cutype) {
                (PrincipalKind::Group, _) | (_, CuType::Group) => Class::Group,
                (PrincipalKind::Resource, _) => Class::Resource(Box::new(principal.clone())),
                (PrincipalKind::User | PrincipalKind::Service, _) => Class::Internal(Box::new(principal.clone())),
            };
        }
        if self.reserved.contains(address) {
            return Class::Unknown;
        }
        if cutype == CuType::Group {
            return Class::Group;
        }
        if address.kind() == AddressKind::Mailto {
            Class::External
        } else {
            Class::Unknown
        }
    }

    /// The `mailto` address every resolved principal is known by outside the server, keyed by the address the
    /// event uses: principal URLs and `urn:uuid` addresses map to the principal's primary e-mail address, and
    /// addresses that are mail addresses already map to themselves (so they are left alone).
    pub(crate) fn wire_map(&self) -> HashMap<CalendarUserAddress, CalendarUserAddress> {
        self.found
            .iter()
            .filter_map(|(address, principal)| {
                let email = principal.email.as_ref()?;
                (address.kind() != AddressKind::Mailto).then(|| (address.clone(), CalendarUserAddress::mailto(email)))
            })
            .collect()
    }

    /// Adds addresses that are known without a lookup (the actor's own, in every form).
    pub(crate) fn with_known(mut self, principal: &Principal, addresses: &[CalendarUserAddress]) -> Self {
        for address in addresses {
            self.found.entry(address.clone()).or_insert_with(|| principal.clone());
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;
    use davhaven_domain::{Email, PrincipalId, PrincipalName, PrincipalStatus, TenantId};
    use uuid::Uuid;

    use super::*;

    fn principal(n: u128, name: &str, kind: PrincipalKind, email: Option<&str>) -> Principal {
        let at = DateTime::UNIX_EPOCH;
        Principal {
            id: PrincipalId::from_uuid(Uuid::from_u128(n)),
            tenant_id: TenantId::from_uuid(Uuid::from_u128(1)),
            kind,
            name: PrincipalName::parse(name).unwrap(),
            display_name: name.to_owned(),
            email: email.map(|email| Email::parse(email).unwrap()),
            locale: None,
            timezone: None,
            external_ref: None,
            status: PrincipalStatus::Active,
            deleted_at: None,
            credential_generation: 0,
            created_at: at,
            updated_at: at,
            version: 1,
        }
    }

    fn address(text: &str) -> CalendarUserAddress {
        CalendarUserAddress::parse(text).unwrap()
    }

    fn directory() -> Directory {
        let anna = principal(2, "anna", PrincipalKind::User, Some("anna@acme.example"));
        let room = principal(3, "room", PrincipalKind::Resource, Some("room@acme.example"));
        let team = principal(4, "team", PrincipalKind::Group, None);
        let mut found = HashMap::new();
        found.insert(address("mailto:anna@acme.example"), anna.clone());
        found.insert(address("/dav/principals/acme/anna/"), anna);
        found.insert(address("mailto:room@acme.example"), room);
        found.insert(address("/dav/principals/acme/team/"), team);
        let reserved = HashSet::from([address("mailto:gone@acme.example")]);
        Directory { found, reserved }
    }

    #[test]
    fn every_address_lands_in_exactly_one_class() {
        let directory = directory();
        let class = |text: &str, cutype| directory.classify(&address(text), cutype);
        assert!(matches!(
            class("mailto:anna@acme.example", CuType::Individual),
            Class::Internal(_)
        ));
        assert!(matches!(
            class("/dav/principals/acme/anna/", CuType::Individual),
            Class::Internal(_)
        ));
        assert!(matches!(
            class("mailto:room@acme.example", CuType::Room),
            Class::Resource(_)
        ));
        assert_eq!(class("/dav/principals/acme/team/", CuType::Individual), Class::Group);
        assert_eq!(
            class("mailto:anna@acme.example", CuType::Group),
            Class::Group,
            "CUTYPE=GROUP wins: groups are not expanded"
        );
        assert_eq!(class("mailto:guest@example.net", CuType::Individual), Class::External);
        assert_eq!(
            class("mailto:list@example.net", CuType::Group),
            Class::Group,
            "a mailing list is a group as well"
        );
        assert_eq!(
            class("mailto:gone@acme.example", CuType::Individual),
            Class::Unknown,
            "the address of a deleted principal is reserved, not external"
        );
        assert_eq!(
            class("urn:uuid:11111111-1111-1111-1111-111111111111", CuType::Individual),
            Class::Unknown
        );
        assert_eq!(
            class("/dav/principals/acme/nobody/", CuType::Individual),
            Class::Unknown
        );
    }

    #[test]
    fn the_external_test_agrees_with_the_classification() {
        let directory = directory();
        for (text, cutype) in [
            ("mailto:anna@acme.example", CuType::Individual),
            ("/dav/principals/acme/anna/", CuType::Individual),
            ("mailto:room@acme.example", CuType::Room),
            ("/dav/principals/acme/team/", CuType::Individual),
            ("mailto:anna@acme.example", CuType::Group),
            ("mailto:guest@example.net", CuType::Individual),
            ("mailto:list@example.net", CuType::Group),
            ("mailto:gone@acme.example", CuType::Individual),
            ("urn:uuid:11111111-1111-1111-1111-111111111111", CuType::Individual),
            ("/dav/principals/acme/nobody/", CuType::Individual),
        ] {
            let address = address(text);
            assert_eq!(
                directory.is_external(&address, cutype),
                directory.classify(&address, cutype) == Class::External,
                "{text} {cutype:?}"
            );
        }
    }

    #[test]
    fn the_wire_map_names_the_mail_address_of_principals_only_where_it_differs() {
        let map = directory().wire_map();
        assert_eq!(
            map.get(&address("/dav/principals/acme/anna/")),
            Some(&address("mailto:anna@acme.example"))
        );
        assert!(!map.contains_key(&address("mailto:anna@acme.example")));
        assert!(
            !map.contains_key(&address("/dav/principals/acme/team/")),
            "a group without a mail address has no wire form"
        );
    }

    #[test]
    fn known_addresses_are_added_without_overriding() {
        let anna = principal(2, "anna", PrincipalKind::User, Some("anna@acme.example"));
        let ben = principal(5, "ben", PrincipalKind::User, None);
        let directory = directory().with_known(&ben, &[address("urn:uuid:55555555-5555-5555-5555-555555555555")]);
        assert!(
            directory
                .principal(&address("urn:uuid:55555555-5555-5555-5555-555555555555"))
                .is_some_and(|found| found.name == ben.name)
        );
        let directory = directory.with_known(&ben, &[address("mailto:anna@acme.example")]);
        assert_eq!(
            directory
                .principal(&address("mailto:anna@acme.example"))
                .map(|found| found.id),
            Some(anna.id),
            "what the lookup found stays"
        );
    }
}
