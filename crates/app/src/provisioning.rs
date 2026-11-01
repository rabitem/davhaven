//! Tenant provisioning and declarative create-or-replace semantics.
//!
//! Tenants are managed with system tokens (`system:tenants`) and addressed by their immutable slug. `PUT` creates or
//! replaces: the same body twice changes nothing (no new version, no audit record), which is what makes
//! reconciliation by a deployment safe. A tenant token with `principals:read` may read its own tenant.
//!
//! Tenant operations cross tenants and run in **system transactions**. The audit records `tenant.created` and
//! `tenant.settings_changed` are appended **in that transaction** (`SystemTenantRepo::append_audit`: the schema admits
//! these two events from system scope and no other), so a tenant change that commits always has its record and one
//! that rolls back leaves none, like every other audited change (`crate::audit`). `tenant.settings_changed` names
//! every field that changed: the settings (`scheduling.external`, ...) and `display_name`, `login_domain` and
//! `status`, so a suspension is recorded. `tenant.deleted` has no log to go to: the audit log of the tenant is deleted
//! with it, and the deletion is logged instead, with the actor.

use async_trait::async_trait;
use davhaven_domain::{
    Actor, AdminOperation, DomainName, ErrorKind, Locale, RequestContext, Tenant, TenantId, TenantSettings, TenantSlug,
    TenantStatus, audit::TenantSettingsAudit,
};
use davhaven_ports::{PageReq, StoreError, SystemTx, TenantAudit};
use davhaven_wire::{Page, TenantView, TenantWrite};

use crate::audit::Journal;
use crate::authz::{admin, clean_name, retrying};
use crate::error::{AppError, AppResult, SafeMessage};
use crate::paging;
use crate::services::{Conditions, MergePatch, PageRequest, TenantService, TenantSpec, Upserted};
use crate::wiring::AppCore;

/// The listing name that binds cursors to the tenant list.
const LISTING: &str = "tenants";

/// The longest display name of a tenant.
const MAX_DISPLAY_NAME: usize = 200;

/// The [`TenantService`] of the application.
#[derive(Debug, Clone)]
pub struct TenantServiceImpl {
    core: AppCore,
}

impl TenantServiceImpl {
    /// Creates the service on the shared application core.
    pub fn new(core: AppCore) -> Self {
        Self { core }
    }

    /// The shared application core: ports, configuration and limits.
    pub fn core(&self) -> &AppCore {
        &self.core
    }
}

fn view(tenant: &Tenant) -> TenantView {
    TenantView {
        id: tenant.id,
        slug: tenant.slug.clone(),
        display_name: tenant.display_name.clone(),
        login_domain: tenant.login_domain.clone(),
        status: tenant.status,
        settings: tenant.settings.clone(),
        created_at: tenant.created_at,
        updated_at: tenant.updated_at,
        version: tenant.version,
    }
}

/// The writable form of a tenant, for merge patches.
fn writable(tenant: &Tenant) -> TenantWrite {
    TenantWrite {
        display_name: tenant.display_name.clone(),
        login_domain: tenant.login_domain.clone(),
        status: Some(tenant.status),
        settings: Some(tenant.settings.clone()),
    }
}

/// The dotted names of the settings that differ, for the audit record (`scheduling.external`, `theme`, ...).
fn changed_settings(before: &TenantSettings, after: &TenantSettings) -> Vec<String> {
    fn walk(prefix: &str, before: &serde_json::Value, after: &serde_json::Value, out: &mut Vec<String>) {
        match (before, after) {
            (serde_json::Value::Object(before), serde_json::Value::Object(after)) => {
                let mut keys: Vec<&String> = before.keys().chain(after.keys()).collect();
                keys.sort();
                keys.dedup();
                for key in keys {
                    let name = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    let null = serde_json::Value::Null;
                    walk(
                        &name,
                        before.get(key).unwrap_or(&null),
                        after.get(key).unwrap_or(&null),
                        out,
                    );
                }
            }
            _ if before != after => out.push(prefix.to_owned()),
            _ => {}
        }
    }
    let (Ok(before), Ok(after)) = (serde_json::to_value(before), serde_json::to_value(after)) else {
        return Vec::new();
    };
    let mut fields = Vec::new();
    walk("", &before, &after, &mut fields);
    fields.retain(|field| field != "schema_version");
    fields
}

/// The pointer of the busy texts per language in a tenant body (`TenantSettings::busy_text_by_locale`).
const BUSY_TEXTS_POINTER: &str = "/settings/busy_text_by_locale";

/// A refusal of the busy texts of a patch, at the member that holds them.
fn busy_texts_refused(code: &'static str, message: &str) -> AppError {
    let message = SafeMessage::sanitized(message);
    AppError::invalid(message.clone()).with_field_error(BUSY_TEXTS_POINTER, code, message)
}

/// Writes the language tags of `settings.busy_text_by_locale` in a merge patch in their canonical case (`de_de` is `de-DE`).
///
/// A merge patch is merged into the stored document by its keys, and the tags of the stored document are canonical, so a
/// patch that spells a tag differently (`de_DE: null`, `DE: "Neu"`) would otherwise name another member: the removal and the
/// change would be ignored without an error, and the document would read the later of two keys that mean one tag. A tag that
/// is none, and one that the patch spells twice, are refused at the member (422) whatever their value is, `null` included.
fn canonical_busy_text_tags(patch: &MergePatch) -> AppResult<MergePatch> {
    let mut document = patch.document().clone();
    if let Some(texts) = document
        .pointer_mut("/settings/busy_text_by_locale")
        .and_then(serde_json::Value::as_object_mut)
    {
        let mut canonical = serde_json::Map::new();
        for (tag, text) in std::mem::take(texts) {
            let locale = Locale::parse(&tag).map_err(|error| {
                busy_texts_refused(
                    "invalid",
                    &format!("a language tag of busy_text_by_locale is not valid: {error}"),
                )
            })?;
            if canonical.insert(locale.to_string(), text).is_some() {
                return Err(busy_texts_refused(
                    "duplicate-tag",
                    &format!("the language tag `{locale}` is written twice in busy_text_by_locale"),
                ));
            }
        }
        *texts = canonical;
    }
    MergePatch::new(document)
}

/// The body of a write after validation.
struct Checked {
    display_name: String,
    login_domain: Option<DomainName>,
    status: Option<TenantStatus>,
    settings: Option<TenantSettings>,
}

impl Checked {
    /// Checks and normalizes the body of a write.
    fn of(body: &TenantWrite) -> AppResult<Self> {
        let display_name = clean_name("/display_name", &body.display_name, MAX_DISPLAY_NAME)?;
        let settings = body
            .settings
            .clone()
            .map(TenantSettings::normalized)
            .transpose()
            .map_err(|error| {
                let message = SafeMessage::sanitized(&format!("{}: {}", error.field(), error.reason()));
                // The pointer names the setting (`/settings/busy_text`), so that a client can show the error at its field.
                AppError::invalid(message.clone()).with_field_error(error.pointer(), "invalid", message)
            })?;
        Ok(Self {
            display_name,
            login_domain: body.login_domain.clone(),
            status: body.status,
            settings,
        })
    }
}

impl TenantServiceImpl {
    /// One attempt of a create-or-replace in a system transaction, which also holds the audit record of the change.
    async fn write_once(
        &self,
        ctx: &RequestContext,
        slug: &TenantSlug,
        body: &TenantWrite,
        conditions: Conditions,
        must_exist: bool,
    ) -> AppResult<(Tenant, bool)> {
        let deps = self.core.deps();
        let Checked {
            display_name,
            login_domain,
            status,
            settings,
        } = Checked::of(body)?;
        let journal = Journal::new(&self.core, ctx);
        let mut tx = deps.database.begin_system().await?;
        let existing = tx.tenants().find_by_slug(slug).await?;
        if must_exist && existing.is_none() {
            return Err(AppError::not_found());
        }
        conditions.check(existing.as_ref().map(|tenant| tenant.version))?;
        let (stored, created) = match existing {
            None => {
                let now = deps.clock.now();
                let tenant = Tenant {
                    id: TenantId::from_uuid(deps.ids.new_id()),
                    slug: slug.clone(),
                    display_name,
                    login_domain,
                    status: status.unwrap_or(TenantStatus::Active),
                    settings: settings.unwrap_or_default(),
                    created_at: now,
                    updated_at: now,
                    version: 1,
                };
                let stored = tx.tenants().create(tenant).await?;
                journal
                    .audit_system(tx.as_mut(), stored.id, TenantAudit::Created)
                    .await?;
                (stored, true)
            }
            Some(current) => {
                // What the body leaves out of the settings and the status stays as it is: a reconciler that does not
                // mention `status` must not reactivate a tenant that was suspended.
                let updated = Tenant {
                    display_name,
                    login_domain,
                    status: status.unwrap_or(current.status),
                    settings: settings.unwrap_or_else(|| current.settings.clone()),
                    ..current.clone()
                };
                let unchanged = updated.display_name == current.display_name
                    && updated.login_domain == current.login_domain
                    && updated.status == current.status
                    && updated.settings == current.settings;
                if unchanged {
                    (current, false)
                } else {
                    let mut fields = Vec::new();
                    if updated.display_name != current.display_name {
                        fields.push("display_name".to_owned());
                    }
                    if updated.login_domain != current.login_domain {
                        fields.push("login_domain".to_owned());
                    }
                    if updated.status != current.status {
                        fields.push("status".to_owned());
                    }
                    fields.extend(changed_settings(&current.settings, &updated.settings));
                    let stored = tx.tenants().update(updated, current.version).await?;
                    if !fields.is_empty() {
                        let event = TenantAudit::SettingsChanged(TenantSettingsAudit { fields });
                        journal.audit_system(tx.as_mut(), stored.id, event).await?;
                    }
                    (stored, false)
                }
            }
        };
        tx.commit().await?;
        Ok((stored, created))
    }

    async fn write(
        &self,
        ctx: &RequestContext,
        slug: &TenantSlug,
        body: TenantWrite,
        conditions: Conditions,
        must_exist: bool,
    ) -> AppResult<Upserted<TenantView>> {
        let retry_stale = conditions == Conditions::none();
        let (stored, created) = retrying(retry_stale, || {
            self.write_once(ctx, slug, &body, conditions, must_exist)
        })
        .await?;
        self.core.tenants().forget(stored.id).await;
        let view = view(&stored);
        Ok(if created {
            Upserted::created(view)
        } else {
            Upserted::replaced(view)
        })
    }
}

async fn find(tx: &mut dyn SystemTx, slug: &TenantSlug) -> AppResult<Tenant> {
    tx.tenants().find_by_slug(slug).await?.ok_or_else(AppError::not_found)
}

#[async_trait]
impl TenantService for TenantServiceImpl {
    async fn list(&self, ctx: &RequestContext, page: PageRequest) -> AppResult<Page<TenantView>> {
        admin(ctx, AdminOperation::ListTenants)?;
        let request: PageReq = paging::page_request(&self.core, ctx, LISTING, &page)?;
        let mut tx = self.core.deps().database.begin_system().await?;
        let rows = tx.tenants().list(request).await?;
        tx.commit().await?;
        let next = paging::next_cursor(&self.core, ctx, LISTING, rows.next)?;
        Ok(Page::new(rows.items.iter().map(view).collect(), next))
    }

    async fn get(&self, ctx: &RequestContext, slug: &TenantSlug) -> AppResult<TenantView> {
        admin(ctx, AdminOperation::GetTenant)?;
        let mut tx = self.core.deps().database.begin_system().await?;
        let tenant = find(tx.as_mut(), slug).await?;
        tx.commit().await?;
        // A tenant token sees its own tenant only; everything else is as good as unknown.
        if matches!(ctx.actor, Actor::TenantToken(_)) && tenant.id != ctx.tenant {
            return Err(AppError::not_found());
        }
        Ok(view(&tenant))
    }

    async fn upsert(
        &self,
        ctx: &RequestContext,
        spec: TenantSpec,
        conditions: Conditions,
    ) -> AppResult<Upserted<TenantView>> {
        admin(ctx, AdminOperation::PutTenant)?;
        self.write(ctx, &spec.slug, spec.body, conditions, false).await
    }

    async fn patch(
        &self,
        ctx: &RequestContext,
        slug: &TenantSlug,
        patch: MergePatch,
        conditions: Conditions,
    ) -> AppResult<TenantView> {
        admin(ctx, AdminOperation::PatchTenant)?;
        let patch = canonical_busy_text_tags(&patch)?;
        let (stored, _) = retrying(conditions == Conditions::none(), || async {
            let current = {
                let mut tx = self.core.deps().database.begin_system().await?;
                let current = find(tx.as_mut(), slug).await?;
                tx.commit().await?;
                current
            };
            conditions.check(Some(current.version))?;
            let mut document = serde_json::to_value(writable(&current)).map_err(AppError::internal)?;
            patch.apply(&mut document);
            let body: TenantWrite = serde_json::from_value(document)
                .map_err(|_| AppError::invalid(SafeMessage::from_static("The patched tenant is not valid.")))?;
            // The write applies to the version the patch was computed from. When another change got in between,
            // that is a lost race of this request (it is computed again), not a failed header of the client.
            self.write_once(ctx, slug, &body, Conditions::if_match(current.version), true)
                .await
                .map_err(|error| {
                    if error.kind() == ErrorKind::PreconditionFailed {
                        AppError::from(StoreError::PreconditionFailed)
                    } else {
                        error
                    }
                })
        })
        .await?;
        self.core.tenants().forget(stored.id).await;
        Ok(view(&stored))
    }

    async fn delete(&self, ctx: &RequestContext, slug: &TenantSlug, conditions: Conditions) -> AppResult<()> {
        admin(ctx, AdminOperation::DeleteTenant)?;
        let expected = conditions.require_if_match()?;
        let mut tx = self.core.deps().database.begin_system().await?;
        let tenant = find(tx.as_mut(), slug).await?;
        if tenant.version != expected {
            return Err(AppError::precondition_failed());
        }
        tx.tenants().delete(tenant.id).await?;
        tx.commit().await?;
        self.core.tenants().forget(tenant.id).await;
        // The audit log of the tenant went with it; this log line is the record of who did it.
        tracing::info!(
            tenant = %tenant.id,
            actor = ?davhaven_domain::AuditActor::from_context(ctx, None, None),
            "a tenant was deleted with everything in it"
        );
        Ok(())
    }
}
