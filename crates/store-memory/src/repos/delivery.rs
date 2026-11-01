//! The outbox, webhook subscriptions and deliveries, provider accounts and OAuth states.

use async_trait::async_trait;
use davhaven_domain::{
    DeliveryId, EventType, ExternalAccount, ExternalAccountId, OutboxId, WebhookId, WebhookSubscription,
};
use davhaven_ports::{
    DeliveryRecord, ExternalAccountFilter, ExternalAccountRepo, NewOutbox, OAuthState, OAuthStateRepo, OutboxFilter,
    OutboxRecord, OutboxRepo, OutboxStatus, PageReq, StoreError, StorePage, UniqueKey, WebhookRepo,
};

use super::{micros, misuse, no_nul, paginate};
use crate::tx::MemTx;

#[async_trait]
impl OutboxRepo for MemTx {
    async fn enqueue(&mut self, message: NewOutbox) -> Result<(), StoreError> {
        observed!("outbox.enqueue", {
            let (kind, schema_version, payload) = message
                .message
                .to_parts()
                .map_err(|error| StoreError::internal(format!("outbox message cannot be serialized: {error}")))?;
            let now = self.now();
            let tenant = self.tenant;
            let due = message.not_before.map_or(now, micros);
            let data = self.writable()?;
            if data.outbox.contains_key(&message.id) {
                return Err(misuse("an outbox message with this id exists already"));
            }
            data.outbox.insert(
                message.id,
                OutboxRecord {
                    id: message.id,
                    tenant_id: tenant,
                    kind: kind.to_owned(),
                    schema_version,
                    payload,
                    status: OutboxStatus::Pending,
                    attempts: 0,
                    next_attempt_at: due,
                    locked_until: None,
                    last_error: None,
                    created_at: now,
                    updated_at: now,
                },
            );
            Ok(())
        })
    }

    async fn get(&mut self, id: OutboxId) -> Result<OutboxRecord, StoreError> {
        observed!(
            "outbox.get",
            self.view().outbox.get(&id).cloned().ok_or(StoreError::NotFound)
        )
    }

    async fn list(&mut self, filter: &OutboxFilter, page: PageReq) -> Result<StorePage<OutboxRecord>, StoreError> {
        observed!("outbox.list", {
            let matching = self.view().outbox.values().filter(|record| {
                filter.status.is_none_or(|status| record.status == status)
                    && filter.kind.as_ref().is_none_or(|kind| &record.kind == kind)
            });
            Ok(paginate(matching.cloned(), &page, |record| record.id.as_uuid()))
        })
    }

    async fn requeue(&mut self, id: OutboxId) -> Result<(), StoreError> {
        observed!("outbox.requeue", {
            let now = self.now();
            let record = self.writable()?.outbox.get_mut(&id).ok_or(StoreError::NotFound)?;
            if record.status != OutboxStatus::Dead {
                return Err(StoreError::PreconditionFailed);
            }
            record.status = OutboxStatus::Pending;
            record.attempts = 0;
            record.next_attempt_at = now;
            record.locked_until = None;
            record.updated_at = now;
            Ok(())
        })
    }
}

#[async_trait]
impl WebhookRepo for MemTx {
    async fn get(&mut self, id: WebhookId) -> Result<WebhookSubscription, StoreError> {
        observed!(
            "webhooks.get",
            self.view().webhooks.get(&id).cloned().ok_or(StoreError::NotFound)
        )
    }

    async fn list(&mut self, page: PageReq) -> Result<StorePage<WebhookSubscription>, StoreError> {
        observed!(
            "webhooks.list",
            Ok(paginate(
                self.view().webhooks.values().cloned(),
                &page,
                |subscription| { subscription.id.as_uuid() }
            ))
        )
    }

    async fn subscribed_to(&mut self, event_type: EventType) -> Result<Vec<WebhookSubscription>, StoreError> {
        observed!(
            "webhooks.subscribed_to",
            Ok(self
                .view()
                .webhooks
                .values()
                .filter(|subscription| subscription.active && subscription.events.contains(&event_type))
                .cloned()
                .collect())
        )
    }

    async fn create(&mut self, subscription: WebhookSubscription) -> Result<WebhookSubscription, StoreError> {
        observed!("webhooks.create", {
            no_nul(
                "webhook text",
                [
                    subscription.description.as_deref(),
                    subscription.disabled_reason.as_deref(),
                ],
            )?;
            let now = self.now();
            let tenant = self.tenant;
            let data = self.writable()?;
            if data.webhooks.contains_key(&subscription.id) {
                return Err(misuse("a webhook with this id exists already"));
            }
            let stored = WebhookSubscription {
                tenant_id: tenant,
                secret_rotated_at: subscription.secret_rotated_at.map(micros),
                created_at: now,
                updated_at: now,
                version: 1,
                ..subscription
            };
            data.webhooks.insert(stored.id, stored.clone());
            Ok(stored)
        })
    }

    async fn update(
        &mut self,
        subscription: WebhookSubscription,
        expected_version: i64,
    ) -> Result<WebhookSubscription, StoreError> {
        observed!("webhooks.update", {
            no_nul(
                "webhook text",
                [
                    subscription.description.as_deref(),
                    subscription.disabled_reason.as_deref(),
                ],
            )?;
            let now = self.now();
            let data = self.writable()?;
            let stored = data.webhooks.get_mut(&subscription.id).ok_or(StoreError::NotFound)?;
            if stored.version != expected_version {
                return Err(StoreError::PreconditionFailed);
            }
            stored.url = subscription.url;
            stored.description = subscription.description;
            stored.sealed_secret = subscription.sealed_secret;
            stored.sealed_secret_previous = subscription.sealed_secret_previous;
            stored.secret_rotated_at = subscription.secret_rotated_at.map(micros);
            stored.events = subscription.events;
            stored.include_details = subscription.include_details;
            // The failure counter belongs to `record_failure` and `record_success`: a stale copy must not erase
            // concurrent failures. Re-enabling a deactivated subscription starts the count again.
            if subscription.active && !stored.active {
                stored.failure_count = 0;
            }
            stored.active = subscription.active;
            stored.disabled_reason = subscription.disabled_reason;
            stored.updated_at = now;
            stored.version += 1;
            Ok(stored.clone())
        })
    }

    async fn delete(&mut self, id: WebhookId) -> Result<(), StoreError> {
        observed!("webhooks.delete", {
            let data = self.writable()?;
            data.webhooks.remove(&id).ok_or(StoreError::NotFound)?;
            data.deliveries.retain(|_, delivery| delivery.subscription_id != id);
            Ok(())
        })
    }

    async fn record_success(&mut self, id: WebhookId) -> Result<(), StoreError> {
        observed!("webhooks.record_success", {
            self.writable()?
                .webhooks
                .get_mut(&id)
                .ok_or(StoreError::NotFound)?
                .failure_count = 0;
            Ok(())
        })
    }

    async fn record_failure(&mut self, id: WebhookId) -> Result<u32, StoreError> {
        observed!("webhooks.record_failure", {
            let stored = self.writable()?.webhooks.get_mut(&id).ok_or(StoreError::NotFound)?;
            stored.failure_count = stored.failure_count.saturating_add(1);
            Ok(stored.failure_count)
        })
    }

    async fn disable(&mut self, id: WebhookId, reason: &str) -> Result<(), StoreError> {
        observed!("webhooks.disable", {
            let now = self.now();
            let stored = self.writable()?.webhooks.get_mut(&id).ok_or(StoreError::NotFound)?;
            stored.active = false;
            stored.disabled_reason = Some(reason.to_owned());
            stored.updated_at = now;
            stored.version += 1;
            Ok(())
        })
    }

    async fn create_delivery(&mut self, delivery: DeliveryRecord) -> Result<DeliveryRecord, StoreError> {
        observed!("webhooks.create_delivery", {
            let now = self.now();
            let tenant = self.tenant;
            let data = self.writable()?;
            if !data.webhooks.contains_key(&delivery.subscription_id) {
                return Err(StoreError::NotFound);
            }
            if let Some(existing) = data.deliveries.values().find(|existing| {
                existing.subscription_id == delivery.subscription_id && existing.event_id == delivery.event_id
            }) {
                // The event was fanned out to this subscription before: that record stands.
                return Ok(existing.clone());
            }
            if data.deliveries.contains_key(&delivery.id) {
                return Err(misuse("a delivery with this id exists already"));
            }
            let stored = DeliveryRecord {
                tenant_id: tenant,
                at: micros(delivery.at),
                created_at: now,
                updated_at: now,
                version: 1,
                ..delivery
            };
            data.deliveries.insert(stored.id, stored.clone());
            Ok(stored)
        })
    }

    async fn get_delivery(&mut self, id: DeliveryId) -> Result<DeliveryRecord, StoreError> {
        observed!(
            "webhooks.get_delivery",
            self.view().deliveries.get(&id).cloned().ok_or(StoreError::NotFound)
        )
    }

    async fn list_deliveries(
        &mut self,
        subscription: WebhookId,
        page: PageReq,
    ) -> Result<StorePage<DeliveryRecord>, StoreError> {
        observed!("webhooks.list_deliveries", {
            let data = self.view();
            if !data.webhooks.contains_key(&subscription) {
                return Err(StoreError::NotFound);
            }
            let matching = data
                .deliveries
                .values()
                .filter(|delivery| delivery.subscription_id == subscription);
            Ok(paginate(matching.cloned(), &page, |delivery| delivery.id.as_uuid()))
        })
    }

    async fn update_delivery(
        &mut self,
        delivery: DeliveryRecord,
        expected_version: i64,
    ) -> Result<DeliveryRecord, StoreError> {
        observed!("webhooks.update_delivery", {
            let now = self.now();
            let stored = self
                .writable()?
                .deliveries
                .get_mut(&delivery.id)
                .ok_or(StoreError::NotFound)?;
            if stored.version != expected_version {
                return Err(StoreError::PreconditionFailed);
            }
            stored.status = delivery.status;
            stored.attempts = delivery.attempts;
            stored.response_status = delivery.response_status;
            stored.last_error = delivery.last_error;
            stored.at = micros(delivery.at);
            stored.updated_at = now;
            stored.version += 1;
            Ok(stored.clone())
        })
    }
}

#[async_trait]
impl ExternalAccountRepo for MemTx {
    async fn get(&mut self, id: ExternalAccountId) -> Result<ExternalAccount, StoreError> {
        observed!(
            "external_accounts.get",
            self.view()
                .external_accounts
                .get(&id)
                .cloned()
                .ok_or(StoreError::NotFound)
        )
    }

    async fn list(
        &mut self,
        filter: &ExternalAccountFilter,
        page: PageReq,
    ) -> Result<StorePage<ExternalAccount>, StoreError> {
        observed!("external_accounts.list", {
            let matching = self.view().external_accounts.values().filter(|account| {
                filter
                    .principal
                    .is_none_or(|principal| account.principal_id == principal)
                    && filter
                        .provider
                        .as_ref()
                        .is_none_or(|provider| &account.provider == provider)
            });
            Ok(paginate(matching.cloned(), &page, |account| account.id.as_uuid()))
        })
    }

    async fn create(&mut self, account: ExternalAccount) -> Result<ExternalAccount, StoreError> {
        observed!("external_accounts.create", {
            let now = self.now();
            let tenant = self.tenant;
            let data = self.writable()?;
            if !data.principals.contains_key(&account.principal_id)
                || account
                    .mirror_calendar_id
                    .is_some_and(|calendar| !data.calendars.contains_key(&calendar))
            {
                return Err(StoreError::NotFound);
            }
            if data.external_accounts.contains_key(&account.id) {
                return Err(misuse("an external account with this id exists already"));
            }
            let stored = ExternalAccount {
                tenant_id: tenant,
                created_at: now,
                updated_at: now,
                version: 1,
                ..account
            };
            data.external_accounts.insert(stored.id, stored.clone());
            Ok(stored)
        })
    }

    async fn update(&mut self, account: ExternalAccount, expected_version: i64) -> Result<ExternalAccount, StoreError> {
        observed!("external_accounts.update", {
            let now = self.now();
            let data = self.writable()?;
            let stored = data.external_accounts.get(&account.id).ok_or(StoreError::NotFound)?;
            if stored.version != expected_version {
                return Err(StoreError::PreconditionFailed);
            }
            if account
                .mirror_calendar_id
                .is_some_and(|calendar| !data.calendars.contains_key(&calendar))
            {
                return Err(StoreError::NotFound);
            }
            let stored = data
                .external_accounts
                .get_mut(&account.id)
                .ok_or(StoreError::NotFound)?;
            stored.account_ref = account.account_ref;
            stored.sealed_tokens = account.sealed_tokens;
            stored.mirror_calendar_id = account.mirror_calendar_id;
            stored.sync_state = account.sync_state;
            stored.status = account.status;
            stored.last_error = account.last_error;
            stored.updated_at = now;
            stored.version += 1;
            Ok(stored.clone())
        })
    }

    async fn delete(&mut self, id: ExternalAccountId) -> Result<(), StoreError> {
        observed!("external_accounts.delete", {
            self.writable()?
                .external_accounts
                .remove(&id)
                .map(|_| ())
                .ok_or(StoreError::NotFound)
        })
    }
}

#[async_trait]
impl OAuthStateRepo for MemTx {
    async fn create(&mut self, state: OAuthState) -> Result<OAuthState, StoreError> {
        observed!("oauth_states.create", {
            let now = self.now();
            let tenant = self.tenant;
            let taken = self.guard.tenants.values().any(|entry| {
                entry
                    .data
                    .oauth_states
                    .values()
                    .any(|other| other.state_hash == state.state_hash)
            });
            if taken {
                return Err(StoreError::UniqueViolation(UniqueKey::OAuthState));
            }
            let data = self.writable()?;
            if !data.principals.contains_key(&state.principal_id) {
                return Err(StoreError::NotFound);
            }
            if data.oauth_states.contains_key(&state.id) {
                return Err(misuse("an OAuth state with this id exists already"));
            }
            let stored = OAuthState {
                tenant_id: tenant,
                expires_at: micros(state.expires_at),
                used_at: state.used_at.map(micros),
                created_at: now,
                ..state
            };
            data.oauth_states.insert(stored.id, stored.clone());
            Ok(stored)
        })
    }

    async fn consume(&mut self, state_hash: &[u8]) -> Result<OAuthState, StoreError> {
        observed!("oauth_states.consume", {
            let now = self.now();
            let data = self.writable()?;
            let stored = data
                .oauth_states
                .values_mut()
                .find(|state| state.state_hash == state_hash && state.used_at.is_none() && state.expires_at > now)
                .ok_or(StoreError::NotFound)?;
            stored.used_at = Some(now);
            Ok(stored.clone())
        })
    }
}
