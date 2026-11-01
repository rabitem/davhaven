//! Sealed values and their resealing under the active key (`davhaven admin rotate-keys`).
//!
//! The secrets the application stores at rest are sealed with an AEAD whose key id travels with the value. Retiring a key
//! from `security.keys` is only safe when no stored value names it any more, so a rotation opens every sealed value and
//! seals it again under the active key. That knowledge belongs to the code that seals, not to the binary that runs the
//! command: **every module that seals a column contributes a [`Resealer`]** (the same registration pattern as
//! `workers::build`), [`resealers`] lists them, and [`reseal_all`] runs them over every tenant.
//!
//! | Sealed column | Resealer | Notes |
//! | --- | --- | --- |
//! | `webhook_subscriptions.sealed_secret`, `sealed_secret_previous` | [`WebhookSecrets`] | |
//! | `external_accounts.sealed_tokens` | [`ExternalAccountTokens`] | The OAuth tokens of a connected provider account. |
//! | `oauth_states.pkce_verifier_sealed` | none ([`SHORT_LIVED_TABLES`]) | Single use and valid for ten minutes: wait that long after a rotation before the retired key is removed. |
//!
//! A test reads `SealAad` in `davhaven-ports` and fails for a sealed table that is neither covered by a resealer, nor guarded
//! (see [`COVERAGE`]), nor one of the short-lived tables ([`SHORT_LIVED_TABLES`]), so a new sealed column cannot ship without
//! one of them. A table that is guarded and covered at the same time fails the test as well: the guard goes when a resealer
//! for its table exists.
//!
//! A run is idempotent: a value that is sealed under the active key is left alone, and a run that was interrupted is
//! finished by the next one. A value that cannot be resealed (its key is missing from the ring, or the row changed
//! concurrently) is counted as failed and logged with the row, never lost; the operator keeps the retired key until a run
//! reports no failure. Counts are per sealed value: a webhook subscription with a current and a previous secret has two.

use std::sync::Arc;

use async_trait::async_trait;
use davhaven_domain::audit::KeyRotationAudit;
use davhaven_domain::{AuditActor, AuditEvent, TenantId};
use davhaven_ports::{
    ExternalAccountFilter, KeyPurpose, NewAudit, PageReq, PortError, SealAad, Sealed, StoreError, TxMode,
};
use secrecy::ExposeSecret as _;

use super::MaintenanceError;
use crate::wiring::{AppCore, AppDeps};

/// Which key a sealed value names; `None` when the bytes are not a value of the sealer in use.
///
/// The format of a sealed value is the sealer's business, so the caller that knows the sealer (the server) passes this.
pub type KeyIdOf<'a> = &'a (dyn Fn(&Sealed) -> Option<String> + Send + Sync);

/// What resealing did, per sealed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    /// Values that named another key and are sealed under the active one now.
    pub resealed: u64,
    /// Values that were sealed under the active key already.
    pub current: u64,
    /// Values that could not be resealed.
    pub failed: u64,
}

impl Counts {
    fn add(&mut self, other: Self) {
        self.resealed = self.resealed.saturating_add(other.resealed);
        self.current = self.current.saturating_add(other.current);
        self.failed = self.failed.saturating_add(other.failed);
    }
}

/// What a resealer declares about the sealed tables: the part a test can read without a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coverage {
    /// A short name for the report and the logs (`webhook_secrets`).
    pub name: &'static str,
    /// The tables whose sealed columns the resealer seals again.
    pub tables: &'static [&'static str],
    /// Tables that hold sealed values this build cannot seal again yet. A resealer that lists one only guards it: it
    /// reports a failure while the table holds values, so that no key is retired under them.
    pub awaiting: &'static [&'static str],
}

/// The declarations of every resealer of [`resealers`], in the same order.
pub const COVERAGE: &[Coverage] = &[WebhookSecrets::COVERAGE, ExternalAccountTokens::COVERAGE];

/// Tables whose sealed values live for minutes and need no resealer: the PKCE verifier of an authorization is single use and
/// valid for ten minutes (`oauth_states`), and a rotation that falls inside that window ends in a login that has to be started
/// again. The operator waits that long before the retired key is removed (`docs/operations/keys.md`).
pub const SHORT_LIVED_TABLES: &[&str] = &["oauth_states"];

/// The sealed values one module of the application owns.
#[async_trait]
pub trait Resealer: Send + Sync {
    /// What the resealer declares; one of the entries of [`COVERAGE`].
    fn coverage(&self) -> &'static Coverage;

    /// Seals every value of `tenant` under `active`.
    ///
    /// # Errors
    ///
    /// The store failures that stop the tenant; a value that cannot be resealed is counted in [`Counts::failed`].
    async fn reseal_tenant(&self, tenant: TenantId, active: &str, key_of: KeyIdOf<'_>) -> Result<Counts, StoreError>;
}

/// The resealers of the application: one line for every module that seals a column, and one entry of [`COVERAGE`].
pub fn resealers(core: &AppCore) -> Vec<Arc<dyn Resealer>> {
    vec![
        Arc::new(WebhookSecrets::new(core.clone())),
        Arc::new(ExternalAccountTokens::new(core.clone())),
    ]
}

/// What a rotation did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationReport {
    /// The key that seals new data and that the values were moved to.
    pub active_key: String,
    /// The totals over every resealer and tenant.
    pub total: Counts,
    /// The totals per resealer, in the order of [`resealers`].
    pub by_resealer: Vec<(&'static str, Counts)>,
}

impl RotationReport {
    fn add(&mut self, name: &'static str, counts: Counts) {
        self.total.add(counts);
        if let Some((_, existing)) = self.by_resealer.iter_mut().find(|(known, _)| *known == name) {
            existing.add(counts);
        } else {
            self.by_resealer.push((name, counts));
        }
    }

    /// Counts one value that could not be reached at all (a tenant whose transaction failed).
    fn fail(&mut self, name: &'static str) {
        self.add(
            name,
            Counts {
                failed: 1,
                ..Counts::default()
            },
        );
    }
}

/// Seals `stored` under the active key again. `Ok(None)` when it names the active key already.
fn reseal_value(
    deps: &AppDeps,
    active: &str,
    key_of: KeyIdOf<'_>,
    stored: &[u8],
    aad: &SealAad,
) -> Result<Option<Vec<u8>>, PortError> {
    let value = Sealed::from_bytes(stored.to_vec());
    match key_of(&value) {
        Some(kid) if kid == active => return Ok(None),
        Some(_) => {}
        None => return Err(PortError::invalid("the stored value is not a sealed value")),
    }
    let plaintext = deps.sealer.open(&value, aad)?;
    Ok(Some(deps.sealer.seal(plaintext.expose_secret(), aad)?.into_bytes()))
}

/// The signing secrets of webhook subscriptions (the current and the previous one of a rotated secret).
#[derive(Debug, Clone)]
pub struct WebhookSecrets {
    core: AppCore,
}

impl WebhookSecrets {
    /// What the resealer declares.
    pub const COVERAGE: Coverage = Coverage {
        name: "webhook_secrets",
        tables: &["webhook_subscriptions"],
        awaiting: &[],
    };

    /// Creates the resealer on the shared application core.
    pub const fn new(core: AppCore) -> Self {
        Self { core }
    }
}

#[async_trait]
impl Resealer for WebhookSecrets {
    fn coverage(&self) -> &'static Coverage {
        &Self::COVERAGE
    }

    async fn reseal_tenant(&self, tenant: TenantId, active: &str, key_of: KeyIdOf<'_>) -> Result<Counts, StoreError> {
        let deps = self.core.deps();
        let mut counts = Counts::default();
        let mut updated_rows = 0_u64;
        let mut tx = deps.database.begin(tenant, TxMode::ReadWrite).await?;
        let mut request = PageReq::first(100);
        loop {
            let page = tx.webhooks().list(request).await?;
            for mut subscription in page.items {
                let aad = SealAad::webhook_secret(tenant, subscription.id);
                // What this row contributes, added to the totals only when its update is known.
                let mut row = Counts::default();
                let mut changed = false;
                match reseal_value(deps, active, key_of, &subscription.sealed_secret, &aad) {
                    Ok(Some(bytes)) => {
                        subscription.sealed_secret = bytes;
                        changed = true;
                        row.resealed += 1;
                    }
                    Ok(None) => row.current += 1,
                    Err(error) => {
                        row.failed += 1;
                        tracing::error!(%error, webhook = %subscription.id, "cannot reseal a webhook secret");
                    }
                }
                if let Some(previous) = subscription.sealed_secret_previous.as_deref() {
                    match reseal_value(deps, active, key_of, previous, &aad) {
                        Ok(Some(bytes)) => {
                            subscription.sealed_secret_previous = Some(bytes);
                            changed = true;
                            row.resealed += 1;
                        }
                        Ok(None) => row.current += 1,
                        Err(error) => {
                            row.failed += 1;
                            tracing::error!(
                                %error,
                                webhook = %subscription.id,
                                "cannot reseal the previous webhook secret"
                            );
                        }
                    }
                }
                if !changed {
                    counts.add(row);
                    continue;
                }
                let version = subscription.version;
                match tx.webhooks().update(subscription, version).await {
                    Ok(_) => {
                        updated_rows += 1;
                        counts.add(row);
                    }
                    Err(StoreError::PreconditionFailed) => {
                        // The subscription changed meanwhile: its secrets were not sealed again, and the next run
                        // sees the new state.
                        tracing::warn!(%tenant, "a webhook subscription changed during the rotation; run it again");
                        row.failed += row.resealed;
                        row.resealed = 0;
                        counts.add(row);
                    }
                    Err(error) => return Err(error),
                }
            }
            match page.next {
                Some(cursor) => request = request.after(cursor),
                None => break,
            }
        }
        // Only a transaction that changed a row is audited.
        if updated_rows > 0 {
            tx.audit()
                .append(NewAudit {
                    id: deps.ids.new_id(),
                    actor: AuditActor::system(),
                    event: AuditEvent::KeysRotated(KeyRotationAudit {
                        active_kid: active.to_owned(),
                    }),
                })
                .await?;
        }
        tx.commit().await?;
        Ok(counts)
    }
}

/// The OAuth tokens of external provider accounts (`external_accounts.sealed_tokens`): one sealed document per account, bound to
/// the tenant and to the account row.
#[derive(Debug, Clone)]
pub struct ExternalAccountTokens {
    core: AppCore,
}

impl ExternalAccountTokens {
    /// What the resealer declares.
    pub const COVERAGE: Coverage = Coverage {
        name: "external_account_tokens",
        tables: &["external_accounts"],
        awaiting: &[],
    };

    /// Creates the resealer on the shared application core.
    pub const fn new(core: AppCore) -> Self {
        Self { core }
    }
}

#[async_trait]
impl Resealer for ExternalAccountTokens {
    fn coverage(&self) -> &'static Coverage {
        &Self::COVERAGE
    }

    async fn reseal_tenant(&self, tenant: TenantId, active: &str, key_of: KeyIdOf<'_>) -> Result<Counts, StoreError> {
        let deps = self.core.deps();
        let mut counts = Counts::default();
        let mut updated_rows = 0_u64;
        let mut tx = deps.database.begin(tenant, TxMode::ReadWrite).await?;
        let mut request = PageReq::first(100);
        loop {
            let page = tx
                .external_accounts()
                .list(&ExternalAccountFilter::default(), request)
                .await?;
            for mut account in page.items {
                let aad = SealAad::external_account_tokens(tenant, account.id);
                match reseal_value(deps, active, key_of, &account.sealed_tokens, &aad) {
                    Ok(None) => counts.current += 1,
                    Ok(Some(bytes)) => {
                        let (id, version) = (account.id, account.version);
                        account.sealed_tokens = bytes;
                        match tx.external_accounts().update(account, version).await {
                            Ok(_) => {
                                updated_rows += 1;
                                counts.resealed += 1;
                            }
                            Err(StoreError::PreconditionFailed) => {
                                // The sync engine or a reconnection changed the account meanwhile: its tokens were not sealed
                                // again, and the next run sees the new state.
                                tracing::warn!(
                                    %tenant, account = %id,
                                    "an external account changed during the rotation; run it again"
                                );
                                counts.failed += 1;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    Err(error) => {
                        counts.failed += 1;
                        tracing::error!(
                            %error, account = %account.id,
                            "cannot reseal the tokens of an external account"
                        );
                    }
                }
            }
            match page.next {
                Some(cursor) => request = request.after(cursor),
                None => break,
            }
        }
        // Only a transaction that changed a row is audited.
        if updated_rows > 0 {
            tx.audit()
                .append(NewAudit {
                    id: deps.ids.new_id(),
                    actor: AuditActor::system(),
                    event: AuditEvent::KeysRotated(KeyRotationAudit {
                        active_kid: active.to_owned(),
                    }),
                })
                .await?;
        }
        tx.commit().await?;
        Ok(counts)
    }
}

/// Seals every stored secret of every tenant under the active key of the key ring, so that a retired key can be removed
/// from `security.keys`. See the module documentation.
///
/// `key_of` tells which key a sealed value names (the format belongs to the sealer; the server passes the function of
/// the production sealer).
///
/// # Errors
///
/// [`MaintenanceError::Store`] when the tenants cannot be listed. A tenant whose resealing fails is counted in
/// [`Counts::failed`] and logged, and the other tenants are still visited.
pub async fn reseal_all(core: &AppCore, key_of: KeyIdOf<'_>) -> Result<RotationReport, MaintenanceError> {
    let deps = core.deps();
    let active = deps.keyring.active_kid(KeyPurpose::CredentialPepper);
    let resealers = resealers(core);
    let declared: Vec<&'static Coverage> = resealers.iter().map(|resealer| resealer.coverage()).collect();
    if declared.len() != COVERAGE.len() || declared.iter().zip(COVERAGE).any(|(found, listed)| *found != listed) {
        return Err(MaintenanceError::Invalid(
            "the resealers and the declarations of davhaven_app::maintenance::keys::COVERAGE differ".to_owned(),
        ));
    }
    let mut tenants = Vec::new();
    {
        let mut tx = deps.database.begin_system().await?;
        let mut request = PageReq::first(200);
        loop {
            let page = tx.tenants().list(request).await?;
            tenants.extend(page.items.into_iter().map(|tenant| tenant.id));
            match page.next {
                Some(cursor) => request = request.after(cursor),
                None => break,
            }
        }
        tx.commit().await?;
    }
    let mut report = RotationReport {
        active_key: active.clone(),
        total: Counts::default(),
        by_resealer: Vec::new(),
    };
    for coverage in &declared {
        // A resealer without tenants still appears in the report.
        report.add(coverage.name, Counts::default());
    }
    for tenant in tenants {
        for resealer in &resealers {
            let name = resealer.coverage().name;
            match resealer.reseal_tenant(tenant, &active, key_of).await {
                Ok(counts) => report.add(name, counts),
                Err(error) => {
                    tracing::error!(%error, %tenant, resealer = name, "cannot reseal the values of a tenant");
                    report.fail(name);
                }
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// The text of the call that starts at `start`, up to its matching closing parenthesis.
    fn call_at(source: &str, start: usize) -> &str {
        let mut depth = 0_u32;
        for (offset, character) in source.get(start..).unwrap_or_default().char_indices() {
            match character {
                '(' => depth += 1,
                ')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return source.get(start..start + offset).unwrap_or_default();
                    }
                }
                _ => {}
            }
        }
        ""
    }

    /// The tables named by the `SealAad` constructors of `davhaven-ports`, read from its source: every `Self::new(...)`
    /// call that names a table and a purpose as string literals.
    fn sealed_tables() -> BTreeSet<String> {
        let source = include_str!("../../../ports/src/crypto.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or_default();
        let mut tables = BTreeSet::new();
        for (start, _) in production.match_indices("Self::new(") {
            let call = call_at(production, start);
            // `Self::new(tenant, "table", row, "purpose")`: the literals are the odd members of the split at quotes.
            let literals: Vec<&str> = call.split('"').skip(1).step_by(2).collect();
            if let [table, _purpose] = literals.as_slice() {
                tables.insert((*table).to_owned());
            }
        }
        tables
    }

    #[test]
    fn the_scan_finds_the_sealed_tables_of_the_ports() {
        let tables = sealed_tables();
        for table in ["webhook_subscriptions", "external_accounts", "oauth_states"] {
            assert!(tables.contains(table), "{table}: {tables:?}");
        }
    }

    #[test]
    fn a_short_lived_table_is_sealed_and_has_no_resealer() {
        let sealed = sealed_tables();
        let covered: BTreeSet<&str> = COVERAGE
            .iter()
            .flat_map(|coverage| coverage.tables.iter().copied())
            .collect();
        for table in SHORT_LIVED_TABLES {
            assert!(
                sealed.contains(*table),
                "`{table}` is listed as short lived but nothing seals it any more"
            );
            assert!(
                !covered.contains(table),
                "`{table}` has a resealer: it is not short lived any more"
            );
        }
    }

    #[test]
    fn every_sealed_table_has_a_resealer_or_a_guard_that_is_still_needed() {
        let covered: BTreeSet<&str> = COVERAGE
            .iter()
            .flat_map(|coverage| coverage.tables.iter().copied())
            .collect();
        let guarded: BTreeSet<&str> = COVERAGE
            .iter()
            .flat_map(|coverage| coverage.awaiting.iter().copied())
            .collect();
        for table in sealed_tables() {
            assert!(
                covered.contains(table.as_str())
                    || guarded.contains(table.as_str())
                    || SHORT_LIVED_TABLES.contains(&table.as_str()),
                "`SealAad` seals a column of `{table}`, but no resealer of davhaven_app::maintenance::keys covers it: \
                 add one (or, until the owner of the table has written it, a guard that fails while rows exist; or, for \
                 values that live for minutes, an entry of SHORT_LIVED_TABLES), or `admin rotate-keys` would report \
                 success and leave values sealed under the retired key"
            );
        }
        for table in &guarded {
            assert!(
                !covered.contains(table),
                "`{table}` has a resealer now: remove the guard that waits for it"
            );
        }
    }

    #[test]
    fn coverage_names_are_distinct() {
        let names: BTreeSet<&str> = COVERAGE.iter().map(|coverage| coverage.name).collect();
        assert_eq!(names.len(), COVERAGE.len());
    }

    #[test]
    fn the_call_scanner_matches_parentheses() {
        let source = r#"Self::new(tenant, "t", row.as_uuid(), "p"); other"#;
        assert_eq!(call_at(source, 0), r#"Self::new(tenant, "t", row.as_uuid(), "p""#);
    }

    #[test]
    fn counts_add_up() {
        let mut total = Counts::default();
        total.add(Counts {
            resealed: 2,
            current: 1,
            failed: 0,
        });
        total.add(Counts {
            resealed: 0,
            current: 1,
            failed: 3,
        });
        assert_eq!(
            total,
            Counts {
                resealed: 2,
                current: 2,
                failed: 3
            }
        );
    }

    #[test]
    fn a_report_keeps_one_line_per_resealer() {
        let mut report = RotationReport {
            active_key: "k2".to_owned(),
            total: Counts::default(),
            by_resealer: Vec::new(),
        };
        report.add(
            "a",
            Counts {
                resealed: 1,
                current: 0,
                failed: 0,
            },
        );
        report.add(
            "a",
            Counts {
                resealed: 1,
                current: 1,
                failed: 0,
            },
        );
        report.fail("b");
        assert_eq!(report.by_resealer.len(), 2);
        assert_eq!(
            report.total,
            Counts {
                resealed: 2,
                current: 1,
                failed: 1
            }
        );
    }
}
