//! Repositories for CalendarServer notifications and the scheduling inbox.
//!
//! Both collections have a change log: `create`, `update` and `delete` advance the sequence of the recipient's
//! notification collection or inbox, so clients that sync them see the change. Quarantined inbox items are the
//! exception: they are never shown to clients, so creating, deleting or expiring one neither advances the inbox
//! sequence nor writes a change-log row (the inbox's `CTag` and sync token say nothing about rejected inbound
//! messages).

use async_trait::async_trait;
use davhaven_domain::{InboxItem, InboxItemId, Notification, NotificationId, ObjectUri, PrincipalId, Uid};

use crate::error::StoreError;

/// Notifications (share invitations and replies) in a principal's notification collection.
#[async_trait]
pub trait NotificationRepo: Send {
    /// The notification with `id`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get(&mut self, id: NotificationId) -> Result<Notification, StoreError>;

    /// The notification of `principal` at `uri`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get_by_uri(&mut self, principal: PrincipalId, uri: &ObjectUri) -> Result<Notification, StoreError>;

    /// The notifications of `principal` at `uris` that exist, in the order of `uris` (a name that is asked twice is
    /// answered once, one that names nothing is left out). Additive method: the default reads one notification per
    /// name, an adapter that can read them in one query overrides it.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn get_many_by_uri(
        &mut self,
        principal: PrincipalId,
        uris: &[ObjectUri],
    ) -> Result<Vec<Notification>, StoreError> {
        let mut found: Vec<Notification> = Vec::with_capacity(uris.len());
        for uri in uris {
            if found.iter().any(|known| &known.uri == uri) {
                continue;
            }
            match self.get_by_uri(principal, uri).await {
                Ok(notification) => found.push(notification),
                Err(StoreError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(found)
    }

    /// The notification of `principal` about the invitation `uid`, if any.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn find_by_uid(&mut self, principal: PrincipalId, uid: &Uid) -> Result<Option<Notification>, StoreError>;

    /// All notifications of `principal`, in id order.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn list(&mut self, principal: PrincipalId) -> Result<Vec<Notification>, StoreError>;

    /// Creates a notification.
    ///
    /// # Errors
    ///
    /// `NotFound` when the principal does not exist and `UniqueViolation` of `NotificationUri`.
    async fn create(&mut self, notification: Notification) -> Result<Notification, StoreError>;

    /// Replaces the notification (new body and ETag) if the stored version equals `expected_version`.
    ///
    /// # Errors
    ///
    /// `NotFound` and `PreconditionFailed`.
    async fn update(&mut self, notification: Notification, expected_version: i64) -> Result<Notification, StoreError>;

    /// Deletes the notification.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn delete(&mut self, id: NotificationId) -> Result<(), StoreError>;
}

/// Which items of the scheduling inbox to list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InboxScope {
    /// Items shown to clients (not quarantined).
    Delivered,
    /// Quarantined items, kept for inspection and never shown to clients.
    Quarantined,
}

/// Items in a principal's scheduling inbox (iTIP messages waiting for the principal).
#[async_trait]
pub trait InboxRepo: Send {
    /// The item with `id`.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get(&mut self, id: InboxItemId) -> Result<InboxItem, StoreError>;

    /// The item of `principal` at `uri`; quarantined items are found too.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn get_by_uri(&mut self, principal: PrincipalId, uri: &ObjectUri) -> Result<InboxItem, StoreError>;

    /// The items of `principal` at `uris` that exist (quarantined ones too, as [`get_by_uri`](Self::get_by_uri)
    /// finds them), in the order of `uris`; a name that is asked twice is answered once and one that names nothing
    /// is left out. Additive method: the default reads one item per name, an adapter that can read them in one
    /// query overrides it.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn get_many_by_uri(
        &mut self,
        principal: PrincipalId,
        uris: &[ObjectUri],
    ) -> Result<Vec<InboxItem>, StoreError> {
        let mut found: Vec<InboxItem> = Vec::with_capacity(uris.len());
        for uri in uris {
            if found.iter().any(|known| &known.uri == uri) {
                continue;
            }
            match self.get_by_uri(principal, uri).await {
                Ok(item) => found.push(item),
                Err(StoreError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(found)
    }

    /// The items of `principal` in the given scope, in id order.
    ///
    /// # Errors
    ///
    /// Store failures only.
    async fn list(&mut self, principal: PrincipalId, scope: InboxScope) -> Result<Vec<InboxItem>, StoreError>;

    /// Adds an item. Deterministic names let callers deduplicate (inbound iTIP derives the name from the
    /// `Message-ID`). A delivered item advances the inbox sequence and is logged; a quarantined one is stored
    /// without either.
    ///
    /// # Errors
    ///
    /// `NotFound` when the principal does not exist and `UniqueViolation` of `InboxUri`.
    async fn create(&mut self, item: InboxItem) -> Result<InboxItem, StoreError>;

    /// Deletes the item; the deletion of a delivered item is logged, that of a quarantined one is not.
    ///
    /// # Errors
    ///
    /// `NotFound`.
    async fn delete(&mut self, id: InboxItemId) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;
    use davhaven_domain::{ETag, NotificationKind};
    use uuid::Uuid;

    use super::*;

    fn id<T: From<Uuid>>(n: u128) -> T {
        T::from(Uuid::from_u128(n))
    }

    fn uri(name: &str) -> ObjectUri {
        ObjectUri::parse(name).unwrap()
    }

    fn notification(n: u128, principal: PrincipalId, name: &str) -> Notification {
        Notification {
            id: id(n),
            tenant_id: id(1),
            principal_id: principal,
            uri: uri(name),
            uid: Uid::parse("invite-1").unwrap(),
            etag: ETag::from_bytes(name.as_bytes()),
            kind: NotificationKind::Invite,
            body_xml: "<invite/>".to_owned(),
            created_at: DateTime::UNIX_EPOCH,
            updated_at: DateTime::UNIX_EPOCH,
            version: 1,
        }
    }

    fn item(n: u128, principal: PrincipalId, name: &str, quarantined: bool) -> InboxItem {
        InboxItem {
            id: id(n),
            tenant_id: id(1),
            principal_id: principal,
            uri: uri(name),
            etag: ETag::from_bytes(name.as_bytes()),
            data: "BEGIN:VCALENDAR
END:VCALENDAR
"
            .to_owned(),
            quarantined,
            created_at: DateTime::UNIX_EPOCH,
            updated_at: DateTime::UNIX_EPOCH,
            version: 1,
        }
    }

    /// Repositories that implement only the single read by name, over a fixed list, so that the default bodies of the
    /// batch reads run. A read of `broken.xml` or `broken.ics` fails like a store that went away.
    #[derive(Default)]
    struct SingleReads {
        notifications: Vec<Notification>,
        inbox: Vec<InboxItem>,
        reads: u32,
    }

    fn broken(uri: &ObjectUri) -> bool {
        uri.as_str().starts_with("broken.")
    }

    #[async_trait]
    impl NotificationRepo for SingleReads {
        async fn get(&mut self, _id: NotificationId) -> Result<Notification, StoreError> {
            Err(StoreError::Unsupported)
        }

        async fn get_by_uri(&mut self, principal: PrincipalId, uri: &ObjectUri) -> Result<Notification, StoreError> {
            self.reads += 1;
            if broken(uri) {
                return Err(StoreError::Unavailable);
            }
            self.notifications
                .iter()
                .find(|known| known.principal_id == principal && &known.uri == uri)
                .cloned()
                .ok_or(StoreError::NotFound)
        }

        async fn find_by_uid(
            &mut self,
            _principal: PrincipalId,
            _uid: &Uid,
        ) -> Result<Option<Notification>, StoreError> {
            Err(StoreError::Unsupported)
        }

        async fn list(&mut self, _principal: PrincipalId) -> Result<Vec<Notification>, StoreError> {
            Err(StoreError::Unsupported)
        }

        async fn create(&mut self, _notification: Notification) -> Result<Notification, StoreError> {
            Err(StoreError::Unsupported)
        }

        async fn update(
            &mut self,
            _notification: Notification,
            _expected_version: i64,
        ) -> Result<Notification, StoreError> {
            Err(StoreError::Unsupported)
        }

        async fn delete(&mut self, _id: NotificationId) -> Result<(), StoreError> {
            Err(StoreError::Unsupported)
        }
    }

    #[async_trait]
    impl InboxRepo for SingleReads {
        async fn get(&mut self, _id: InboxItemId) -> Result<InboxItem, StoreError> {
            Err(StoreError::Unsupported)
        }

        async fn get_by_uri(&mut self, principal: PrincipalId, uri: &ObjectUri) -> Result<InboxItem, StoreError> {
            self.reads += 1;
            if broken(uri) {
                return Err(StoreError::Unavailable);
            }
            self.inbox
                .iter()
                .find(|known| known.principal_id == principal && &known.uri == uri)
                .cloned()
                .ok_or(StoreError::NotFound)
        }

        async fn list(&mut self, _principal: PrincipalId, _scope: InboxScope) -> Result<Vec<InboxItem>, StoreError> {
            Err(StoreError::Unsupported)
        }

        async fn create(&mut self, _item: InboxItem) -> Result<InboxItem, StoreError> {
            Err(StoreError::Unsupported)
        }

        async fn delete(&mut self, _id: InboxItemId) -> Result<(), StoreError> {
            Err(StoreError::Unsupported)
        }
    }

    #[tokio::test]
    async fn the_default_batch_read_of_notifications_answers_each_existing_name_once_in_the_order_asked() {
        let (mia, olivia): (PrincipalId, PrincipalId) = (id(10), id(11));
        let mut repo = SingleReads {
            notifications: vec![
                notification(1, mia, "n1.xml"),
                notification(2, mia, "n2.xml"),
                notification(3, olivia, "n3.xml"),
            ],
            ..SingleReads::default()
        };
        let found = NotificationRepo::get_many_by_uri(
            &mut repo,
            mia,
            &[
                uri("n2.xml"),
                uri("gone.xml"),
                uri("n1.xml"),
                uri("n2.xml"),
                uri("n3.xml"),
            ],
        )
        .await
        .unwrap();
        assert_eq!(
            found.iter().map(|known| known.id).collect::<Vec<NotificationId>>(),
            vec![id(2), id(1)],
            "a missing name is left out, a repeated one answered once, another principal's notification never"
        );
        assert_eq!(repo.reads, 4, "the repeated name is not read again");
        assert_eq!(
            NotificationRepo::get_many_by_uri(&mut repo, mia, &[]).await,
            Ok(Vec::new())
        );
    }

    #[tokio::test]
    async fn the_default_batch_read_of_the_inbox_finds_quarantined_items_too() {
        let mia: PrincipalId = id(10);
        let delivered = item(1, mia, "i1.ics", false);
        let quarantined = item(2, mia, "i2.ics", true);
        let mut repo = SingleReads {
            inbox: vec![delivered.clone(), quarantined.clone()],
            ..SingleReads::default()
        };
        assert_eq!(
            InboxRepo::get_many_by_uri(
                &mut repo,
                mia,
                &[uri("i2.ics"), uri("gone.ics"), uri("i1.ics"), uri("i2.ics")]
            )
            .await,
            Ok(vec![quarantined, delivered])
        );
        assert_eq!(
            InboxRepo::get_many_by_uri(&mut repo, id(11), &[uri("i1.ics")]).await,
            Ok(Vec::new()),
            "the name of another principal's item finds nothing"
        );
    }

    #[tokio::test]
    async fn a_store_failure_in_a_default_batch_read_is_not_taken_for_a_missing_name() {
        let mia: PrincipalId = id(10);
        let mut repo = SingleReads {
            notifications: vec![notification(1, mia, "n1.xml")],
            inbox: vec![item(1, mia, "i1.ics", false)],
            ..SingleReads::default()
        };
        assert_eq!(
            NotificationRepo::get_many_by_uri(&mut repo, mia, &[uri("n1.xml"), uri("broken.xml")]).await,
            Err(StoreError::Unavailable)
        );
        assert_eq!(
            InboxRepo::get_many_by_uri(&mut repo, mia, &[uri("broken.ics"), uri("i1.ics")]).await,
            Err(StoreError::Unavailable)
        );
    }
}
