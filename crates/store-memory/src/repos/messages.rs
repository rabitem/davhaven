//! CalendarServer notifications and the scheduling inbox.
//!
//! Both collections have a change log: every create, update and delete advances the recipient's sequence and
//! logs the change.

use async_trait::async_trait;
use davhaven_domain::{
    CollectionKind, InboxItem, InboxItemId, Notification, NotificationId, ObjectUri, PrincipalId, Uid,
};
use davhaven_ports::{ChangeKind, InboxRepo, InboxScope, NotificationRepo, StoreError, UniqueKey};

use super::{misuse, no_nul};
use crate::tx::MemTx;

#[async_trait]
impl NotificationRepo for MemTx {
    async fn get(&mut self, id: NotificationId) -> Result<Notification, StoreError> {
        observed!(
            "notifications.get",
            self.view().notifications.get(&id).cloned().ok_or(StoreError::NotFound)
        )
    }

    async fn get_by_uri(&mut self, principal: PrincipalId, uri: &ObjectUri) -> Result<Notification, StoreError> {
        observed!(
            "notifications.get_by_uri",
            self.view()
                .notifications
                .values()
                .find(|notification| notification.principal_id == principal && &notification.uri == uri)
                .cloned()
                .ok_or(StoreError::NotFound)
        )
    }

    async fn get_many_by_uri(
        &mut self,
        principal: PrincipalId,
        uris: &[ObjectUri],
    ) -> Result<Vec<Notification>, StoreError> {
        observed!("notifications.get_many_by_uri", {
            let mut stored: std::collections::HashMap<&ObjectUri, &Notification> = self
                .view()
                .notifications
                .values()
                .filter(|notification| notification.principal_id == principal)
                .map(|notification| (&notification.uri, notification))
                .collect();
            Ok(uris.iter().filter_map(|uri| stored.remove(uri)).cloned().collect())
        })
    }

    async fn find_by_uid(&mut self, principal: PrincipalId, uid: &Uid) -> Result<Option<Notification>, StoreError> {
        observed!(
            "notifications.find_by_uid",
            Ok(self
                .view()
                .notifications
                .values()
                .find(|notification| notification.principal_id == principal && &notification.uid == uid)
                .cloned())
        )
    }

    async fn list(&mut self, principal: PrincipalId) -> Result<Vec<Notification>, StoreError> {
        observed!(
            "notifications.list",
            Ok(self
                .view()
                .notifications
                .values()
                .filter(|notification| notification.principal_id == principal)
                .cloned()
                .collect())
        )
    }

    async fn create(&mut self, notification: Notification) -> Result<Notification, StoreError> {
        observed!("notifications.create", {
            no_nul("notification body", [Some(notification.body_xml.as_str())])?;
            let now = self.now();
            let tenant = self.tenant;
            let data = self.writable()?;
            if data.notifications.contains_key(&notification.id) {
                return Err(misuse("a notification with this id exists already"));
            }
            if data
                .notifications
                .values()
                .any(|other| other.principal_id == notification.principal_id && other.uri == notification.uri)
            {
                return Err(StoreError::UniqueViolation(UniqueKey::NotificationUri));
            }
            let stored = Notification {
                tenant_id: tenant,
                created_at: now,
                updated_at: now,
                version: 1,
                ..notification
            };
            data.record_principal_change(
                stored.principal_id,
                CollectionKind::Notifications,
                stored.uri.as_str(),
                ChangeKind::Upsert,
                now,
            )?;
            data.notifications.insert(stored.id, stored.clone());
            Ok(stored)
        })
    }

    async fn update(&mut self, notification: Notification, expected_version: i64) -> Result<Notification, StoreError> {
        observed!("notifications.update", {
            let now = self.now();
            let data = self.writable()?;
            let stored = data
                .notifications
                .get_mut(&notification.id)
                .ok_or(StoreError::NotFound)?;
            if stored.version != expected_version {
                return Err(StoreError::PreconditionFailed);
            }
            stored.uid = notification.uid;
            stored.etag = notification.etag;
            stored.kind = notification.kind;
            stored.body_xml = notification.body_xml;
            stored.updated_at = now;
            stored.version += 1;
            let updated = stored.clone();
            data.record_principal_change(
                updated.principal_id,
                CollectionKind::Notifications,
                updated.uri.as_str(),
                ChangeKind::Upsert,
                now,
            )?;
            Ok(updated)
        })
    }

    async fn delete(&mut self, id: NotificationId) -> Result<(), StoreError> {
        observed!("notifications.delete", {
            let now = self.now();
            let data = self.writable()?;
            let removed = data.notifications.get(&id).cloned().ok_or(StoreError::NotFound)?;
            data.record_principal_change(
                removed.principal_id,
                CollectionKind::Notifications,
                removed.uri.as_str(),
                ChangeKind::Delete,
                now,
            )?;
            data.notifications.remove(&id);
            Ok(())
        })
    }
}

#[async_trait]
impl InboxRepo for MemTx {
    async fn get(&mut self, id: InboxItemId) -> Result<InboxItem, StoreError> {
        observed!(
            "inbox.get",
            self.view().inbox.get(&id).cloned().ok_or(StoreError::NotFound)
        )
    }

    async fn get_by_uri(&mut self, principal: PrincipalId, uri: &ObjectUri) -> Result<InboxItem, StoreError> {
        observed!(
            "inbox.get_by_uri",
            self.view()
                .inbox
                .values()
                .find(|item| item.principal_id == principal && &item.uri == uri)
                .cloned()
                .ok_or(StoreError::NotFound)
        )
    }

    async fn get_many_by_uri(
        &mut self,
        principal: PrincipalId,
        uris: &[ObjectUri],
    ) -> Result<Vec<InboxItem>, StoreError> {
        observed!("inbox.get_many_by_uri", {
            let mut stored: std::collections::HashMap<&ObjectUri, &InboxItem> = self
                .view()
                .inbox
                .values()
                .filter(|item| item.principal_id == principal)
                .map(|item| (&item.uri, item))
                .collect();
            Ok(uris.iter().filter_map(|uri| stored.remove(uri)).cloned().collect())
        })
    }

    async fn list(&mut self, principal: PrincipalId, scope: InboxScope) -> Result<Vec<InboxItem>, StoreError> {
        observed!(
            "inbox.list",
            Ok(self
                .view()
                .inbox
                .values()
                .filter(|item| item.principal_id == principal && item.quarantined == (scope == InboxScope::Quarantined))
                .cloned()
                .collect())
        )
    }

    async fn create(&mut self, item: InboxItem) -> Result<InboxItem, StoreError> {
        observed!("inbox.create", {
            no_nul("inbox item", [Some(item.data.as_str())])?;
            let now = self.now();
            let tenant = self.tenant;
            let data = self.writable()?;
            if data.inbox.contains_key(&item.id) {
                return Err(misuse("an inbox item with this id exists already"));
            }
            if data
                .inbox
                .values()
                .any(|other| other.principal_id == item.principal_id && other.uri == item.uri)
            {
                return Err(StoreError::UniqueViolation(UniqueKey::InboxUri));
            }
            let stored = InboxItem {
                tenant_id: tenant,
                created_at: now,
                updated_at: now,
                version: 1,
                ..item
            };
            // A quarantined item is never shown to clients: it does not move the inbox's sync token.
            if !stored.quarantined {
                data.record_principal_change(
                    stored.principal_id,
                    CollectionKind::Inbox,
                    stored.uri.as_str(),
                    ChangeKind::Upsert,
                    now,
                )?;
            }
            data.inbox.insert(stored.id, stored.clone());
            Ok(stored)
        })
    }

    async fn delete(&mut self, id: InboxItemId) -> Result<(), StoreError> {
        observed!("inbox.delete", {
            let now = self.now();
            let data = self.writable()?;
            let removed = data.inbox.get(&id).cloned().ok_or(StoreError::NotFound)?;
            if !removed.quarantined {
                data.record_principal_change(
                    removed.principal_id,
                    CollectionKind::Inbox,
                    removed.uri.as_str(),
                    ChangeKind::Delete,
                    now,
                )?;
            }
            data.inbox.remove(&id);
            Ok(())
        })
    }
}
