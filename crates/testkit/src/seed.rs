//! Seeding a [`FixtureWorld`] into the real application.
//!
//! Everything the application can create is created **through its services**, the way the management API and DAV
//! clients create it: tenants and principals, memberships, calendars, events, grants and the invitation flow of
//! CalendarServer sharing (a pending and a declined sharee need the real flow: the management API only makes
//! accepted grants). Two things have no service and go through the store: the credentials (the constant secrets of
//! the world are hashed with the hasher of the application and stored as the credential service would store them; the
//! tokens that open MCP are among them, because the management API issues those to service principals only and a user gets
//! one from the operator, which an in-process world has no command for) and the
//! mirror calendar (a calendar of the `mirror` kind is made by the sync engine of a provider, and the harness writes
//! the row and the binding of its owner itself).
//!
//! Events are written with a batch (one entry per event, addressed by the external key of the fixture), so that the
//! management API can read them by key and DAV by resource name: the application names objects it creates after
//! their `UID`.

use std::collections::BTreeMap;

use chrono::Duration;
use davhaven_app::AppDeps;
use davhaven_app::AppServices;
use davhaven_app::services::SecretString;
use davhaven_app::services::{
    CalendarRef, CalendarSpec, Conditions, GrantSpec, InviteReply, PrincipalSpec, ShareRequest, ShareeSet, TenantSpec,
};
use davhaven_domain::{
    Actor, ApiToken, AppPassword, AppPasswordText, Binding, BindingId, Calendar, CalendarId, CalendarKind, Channel,
    CredentialId, CredentialKind, DomainName, FeedMode, FeedToken, GrantStatus, PrincipalId, PrincipalKind,
    PrincipalName, PrincipalStatus, RequestContext, RequestId, ResourcePath, Scope, ScopeSet, TenantId, TenantSettings,
    TenantSlug, TokenId, TokenKind, TokenText,
};
use davhaven_fixtures::{
    CalendarRef as FixtureCalendarRef, FixtureCredential, FixtureGrant, FixturePrincipal, FixtureWorld,
};
use davhaven_ports::{IdGenerator as _, TxMode};
use davhaven_wire::{BatchItem, BatchRequest, CalendarWrite, GrantWrite, PrincipalWrite, TenantWrite};
use uuid::Uuid;

use crate::app::TestAppError;

/// The domain the tenants of a test application send mail from.
pub const SENDER_DOMAIN: &str = "mail.example.org";

/// The ids of what was seeded.
#[derive(Debug, Clone, Default)]
pub struct SeedIndex {
    /// The tenants by slug.
    pub tenants: BTreeMap<String, TenantId>,
    /// The principals by (tenant slug, name).
    pub principals: BTreeMap<(String, String), PrincipalId>,
    /// The calendars by their natural key.
    pub calendars: BTreeMap<FixtureCalendarRef, CalendarId>,
}

impl SeedIndex {
    /// The id of a tenant.
    pub fn tenant(&self, slug: &str) -> Option<TenantId> {
        self.tenants.get(slug).copied()
    }

    /// The id of a principal.
    pub fn principal(&self, tenant: &str, name: &str) -> Option<PrincipalId> {
        self.principals.get(&(tenant.to_owned(), name.to_owned())).copied()
    }
}

fn seed_error(what: &str, error: &impl core::fmt::Debug) -> TestAppError {
    TestAppError::Seed(format!("{what}: {error:?}"))
}

fn tenant_id_of(index: &SeedIndex, slug: &TenantSlug) -> Result<TenantId, TestAppError> {
    index
        .tenant(slug.as_str())
        .ok_or_else(|| TestAppError::Seed(format!("the tenant `{slug}` was not created")))
}

fn principal_id_of(index: &SeedIndex, tenant: &TenantSlug, name: &PrincipalName) -> Result<PrincipalId, TestAppError> {
    index
        .principal(tenant.as_str(), name.as_str())
        .ok_or_else(|| TestAppError::Seed(format!("the principal `{name}` of `{tenant}` was not created")))
}

/// Builds request contexts for the seeding.
struct Contexts<'a> {
    deps: &'a AppDeps,
}

impl Contexts<'_> {
    fn request_id(&self) -> RequestId {
        RequestId::from_uuid(self.deps.ids.new_id())
    }

    /// A system token (tenant provisioning).
    fn system(&self) -> RequestContext {
        RequestContext {
            tenant: TenantId::from_uuid(Uuid::nil()),
            actor: Actor::SystemToken(TokenId::from_uuid(self.deps.ids.new_id())),
            scopes: ScopeSet::of(&[Scope::SystemTenants]),
            channel: Channel::Api,
            credential: None,
            request_id: self.request_id(),
            locale: None,
            client_ip: None,
        }
    }

    /// The trusted internal channel of a tenant.
    fn admin(&self, tenant: TenantId) -> RequestContext {
        RequestContext::internal(tenant, self.request_id())
    }

    /// A principal in a CalDAV client.
    fn dav(&self, tenant: TenantId, principal: PrincipalId) -> RequestContext {
        RequestContext {
            tenant,
            actor: Actor::Principal(principal),
            scopes: ScopeSet::empty(),
            channel: Channel::Dav,
            credential: None,
            request_id: self.request_id(),
            locale: None,
            client_ip: None,
        }
    }
}

/// What the steps of the seeding share.
struct Seeding<'a> {
    deps: &'a AppDeps,
    services: &'a AppServices,
    world: &'a FixtureWorld,
    contexts: Contexts<'a>,
}

/// Seeds the world: tenants, principals, memberships, calendars, events, grants, bindings and credentials.
///
/// `settings` replaces the settings of the tenants it names before anything else is created.
///
/// # Errors
///
/// [`TestAppError::Seed`] naming the step that failed.
pub async fn seed_world(
    deps: &AppDeps,
    services: &AppServices,
    world: &FixtureWorld,
    settings: &[(String, TenantSettings)],
) -> Result<SeedIndex, TestAppError> {
    let seeding = Seeding {
        deps,
        services,
        world,
        contexts: Contexts { deps },
    };
    let mut index = SeedIndex::default();
    seeding.tenants(&mut index, settings).await?;
    seeding.principals(&mut index).await?;
    seeding.memberships(&index).await?;
    seeding.calendars_and_events(&index).await?;
    seeding.grants(&index).await?;
    seeding.bindings(&index).await?;
    index.calendars = seeding.calendar_ids(&index).await?;
    seed_credentials(deps, world, &index).await?;
    // The suspended principals are suspended last: nothing above could act for them otherwise.
    seeding.suspensions(&index).await?;
    Ok(index)
}

/// The body of an upsert of a principal of the world.
fn principal_body(principal: &FixturePrincipal, status: Option<PrincipalStatus>) -> PrincipalWrite {
    PrincipalWrite {
        kind: principal.kind,
        display_name: principal.display_name.clone(),
        email: principal.email.clone(),
        addresses: Vec::new(),
        locale: None,
        timezone: None,
        external_ref: None,
        status,
    }
}

impl Seeding<'_> {
    /// Creates the tenants; `settings` replaces the settings of the tenants it names.
    async fn tenants(&self, index: &mut SeedIndex, settings: &[(String, TenantSettings)]) -> Result<(), TestAppError> {
        for tenant in &self.world.tenants {
            let mut tenant_settings = TenantSettings::default();
            tenant_settings.sender.domain = Some(
                DomainName::parse(SENDER_DOMAIN)
                    .map_err(|error| seed_error("the sender domain of the tenants", &error))?,
            );
            // MCP is opt-in per tenant (`tenant.settings.mcp_enabled`); the matrices exercise it.
            tenant_settings.mcp_enabled = true;
            if let Some((_, custom)) = settings.iter().find(|(slug, _)| slug == tenant.slug.as_str()) {
                tenant_settings = custom.clone();
            }
            let created = self
                .services
                .tenants
                .upsert(
                    &self.contexts.system(),
                    TenantSpec {
                        slug: tenant.slug.clone(),
                        body: TenantWrite {
                            display_name: tenant.display_name.clone(),
                            login_domain: Some(tenant.login_domain.clone()),
                            status: None,
                            settings: Some(tenant_settings),
                        },
                    },
                    Conditions::none(),
                )
                .await
                .map_err(|error| seed_error(&format!("the tenant `{}`", tenant.slug), &error))?;
            index.tenants.insert(tenant.slug.to_string(), created.value.id);
        }
        if let Some((slug, _)) = settings.iter().find(|(slug, _)| !index.tenants.contains_key(slug)) {
            return Err(TestAppError::Seed(format!(
                "the settings name the unknown tenant `{slug}`"
            )));
        }
        Ok(())
    }

    /// Creates the principals.
    async fn principals(&self, index: &mut SeedIndex) -> Result<(), TestAppError> {
        for principal in &self.world.principals {
            let tenant = tenant_id_of(index, &principal.tenant)?;
            let created = self
                .services
                .principals
                .upsert(
                    &self.contexts.admin(tenant),
                    PrincipalSpec {
                        name: principal.name.clone(),
                        body: principal_body(principal, None),
                    },
                    Conditions::none(),
                )
                .await
                .map_err(|error| seed_error(&format!("the principal `{}`", principal.name), &error))?;
            index.principals.insert(
                (principal.tenant.to_string(), principal.name.to_string()),
                created.value.id,
            );
        }
        Ok(())
    }

    /// Fills the groups.
    async fn memberships(&self, index: &SeedIndex) -> Result<(), TestAppError> {
        for group in self.world.principals.iter().filter(|p| p.kind == PrincipalKind::Group) {
            let members: Vec<PrincipalName> = self
                .world
                .memberships
                .iter()
                .filter(|m| m.tenant == group.tenant && m.group == group.name)
                .map(|m| m.member.clone())
                .collect();
            self.services
                .principals
                .set_members(
                    &self.contexts.admin(tenant_id_of(index, &group.tenant)?),
                    &group.name,
                    members,
                )
                .await
                .map_err(|error| seed_error(&format!("the members of `{}`", group.name), &error))?;
        }
        Ok(())
    }

    /// Creates the calendars (the personal ones exist with their users) and the events in them.
    async fn calendars_and_events(&self, index: &SeedIndex) -> Result<(), TestAppError> {
        for calendar in &self.world.calendars {
            let tenant = tenant_id_of(index, &calendar.key.tenant)?;
            let admin = self.contexts.admin(tenant);
            if calendar.kind == CalendarKind::Mirror {
                // A mirror is made by the sync engine of a provider, and no service creates one.
                create_mirror(self.deps, index, &calendar.key, &calendar.display_name).await?;
            } else if !calendar.implicit {
                self.services
                    .calendars
                    .upsert(
                        &admin,
                        CalendarSpec {
                            owner: calendar.key.owner.clone(),
                            slug: calendar.key.slug.clone(),
                            body: CalendarWrite {
                                kind: Some(calendar.kind),
                                display_name: calendar.display_name.clone(),
                                description: None,
                                color: None,
                                sort_order: None,
                                components: None,
                            },
                        },
                        Conditions::none(),
                    )
                    .await
                    .map_err(|error| seed_error(&format!("the calendar `{}`", calendar.key.slug), &error))?;
            }
            let events: Vec<BatchItem> = self
                .world
                .events
                .iter()
                .filter(|event| event.calendar == calendar.key)
                .map(|event| BatchItem {
                    external_key: event.external_key.clone(),
                    event: None,
                    ical: Some(event.ics.clone()),
                })
                .collect();
            if events.is_empty() {
                continue;
            }
            let result = self
                .services
                .objects
                .batch(
                    &admin,
                    &CalendarRef::Key {
                        owner: calendar.key.owner.clone(),
                        slug: calendar.key.slug.clone(),
                    },
                    BatchRequest {
                        items: events,
                        ..BatchRequest::default()
                    },
                )
                .await
                .map_err(|error| seed_error(&format!("the events of `{}`", calendar.key.slug), &error))?;
            if result.has_failures() {
                return Err(seed_error(
                    &format!("the events of `{}` were refused", calendar.key.slug),
                    &result.results,
                ));
            }
        }
        Ok(())
    }

    /// Creates the grants: accepted ones through the management API, the others through the invitation flow.
    async fn grants(&self, index: &SeedIndex) -> Result<(), TestAppError> {
        for grant in &self.world.grants {
            let tenant = tenant_id_of(index, &grant.calendar.tenant)?;
            let grantee = self
                .world
                .principal_named(grant.calendar.tenant.as_str(), grant.grantee.as_str())
                .map_err(|error| seed_error("a grantee of the world", &error))?;
            if grant.status == GrantStatus::Accepted || grantee.kind == PrincipalKind::Group {
                self.services
                    .sharing
                    .put_grant(
                        &self.contexts.admin(tenant),
                        GrantSpec {
                            calendar: CalendarRef::Key {
                                owner: grant.calendar.owner.clone(),
                                slug: grant.calendar.slug.clone(),
                            },
                            grantee: grant.grantee.clone(),
                            body: GrantWrite {
                                access: grant.access,
                                required: grant.required,
                            },
                        },
                        Conditions::none(),
                    )
                    .await
                    .map_err(|error| seed_error(&format!("the grant to `{}`", grant.grantee), &error))?;
            } else {
                self.invite(index, tenant, grant, grantee).await?;
            }
        }
        Ok(())
    }

    /// Invites a sharee the way a CalDAV client does and, for a declined grant, has the sharee decline.
    async fn invite(
        &self,
        index: &SeedIndex,
        tenant: TenantId,
        grant: &FixtureGrant,
        grantee: &FixturePrincipal,
    ) -> Result<(), TestAppError> {
        let owner = principal_id_of(index, &grant.calendar.tenant, &grant.calendar.owner)?;
        let collection = ResourcePath::Collection {
            tenant: grant.calendar.tenant.clone(),
            principal: grant.calendar.owner.clone(),
            binding: grant.calendar.slug.clone(),
        };
        let address = grantee
            .address()
            .ok_or_else(|| TestAppError::Seed(format!("the sharee `{}` has no address", grant.grantee)))?;
        let results = self
            .services
            .sharing
            .share(
                &self.contexts.dav(tenant, owner),
                &collection,
                ShareRequest {
                    set: vec![ShareeSet {
                        address,
                        common_name: Some(grantee.display_name.clone()),
                        summary: None,
                        access: grant.access,
                    }],
                    remove: Vec::new(),
                },
            )
            .await
            .map_err(|error| seed_error(&format!("the invitation of `{}`", grant.grantee), &error))?;
        if let Some(failed) = results.iter().find(|result| result.error.is_some()) {
            return Err(seed_error(
                &format!("the invitation of `{}`", grant.grantee),
                &failed.error,
            ));
        }
        if grant.status != GrantStatus::Declined {
            return Ok(());
        }
        let sharee = principal_id_of(index, &grant.calendar.tenant, &grant.grantee)?;
        let sharee_ctx = self.contexts.dav(tenant, sharee);
        let notifications = self
            .services
            .sharing
            .list_notifications(&sharee_ctx, &grant.grantee)
            .await
            .map_err(|error| seed_error(&format!("the notifications of `{}`", grant.grantee), &error))?;
        let invitation = notifications
            .first()
            .ok_or_else(|| TestAppError::Seed(format!("`{}` received no invitation", grant.grantee)))?;
        self.services
            .sharing
            .reply_invite(
                &sharee_ctx,
                &ResourcePath::Home {
                    tenant: grant.calendar.tenant.clone(),
                    principal: grant.grantee.clone(),
                },
                InviteReply {
                    in_reply_to: invitation.uid.clone(),
                    accepted: false,
                    host_url: Some(collection),
                    summary: None,
                },
            )
            .await
            .map_err(|error| seed_error(&format!("the answer of `{}`", grant.grantee), &error))?;
        Ok(())
    }

    /// Makes the bindings that are created when a home is listed for the first time.
    async fn bindings(&self, index: &SeedIndex) -> Result<(), TestAppError> {
        for calendar in &self.world.calendars {
            let tenant = tenant_id_of(index, &calendar.key.tenant)?;
            for bound in &calendar.bound {
                let principal = principal_id_of(index, &calendar.key.tenant, bound)?;
                self.services
                    .calendars
                    .list_home(&self.contexts.dav(tenant, principal), bound)
                    .await
                    .map_err(|error| seed_error(&format!("the home of `{bound}`"), &error))?;
            }
        }
        Ok(())
    }

    /// The ids of the calendars of the world, read back from the store.
    async fn calendar_ids(&self, index: &SeedIndex) -> Result<BTreeMap<FixtureCalendarRef, CalendarId>, TestAppError> {
        let mut calendar_ids = BTreeMap::new();
        for calendar in &self.world.calendars {
            let tenant = tenant_id_of(index, &calendar.key.tenant)?;
            let owner = principal_id_of(index, &calendar.key.tenant, &calendar.key.owner)?;
            let mut tx = self
                .deps
                .database
                .begin(tenant, TxMode::ReadOnly)
                .await
                .map_err(|error| seed_error("a read transaction", &error))?;
            let stored = tx
                .calendars()
                .get_by_slug(owner, &calendar.key.slug)
                .await
                .map_err(|error| seed_error(&format!("the calendar `{}` is missing", calendar.key.slug), &error))?;
            tx.commit()
                .await
                .map_err(|error| seed_error("the commit of a read transaction", &error))?;
            calendar_ids.insert(calendar.key.clone(), stored.id);
        }
        Ok(calendar_ids)
    }

    /// Suspends the principals of the world that are not active.
    async fn suspensions(&self, index: &SeedIndex) -> Result<(), TestAppError> {
        for principal in self
            .world
            .principals
            .iter()
            .filter(|p| p.status != PrincipalStatus::Active)
        {
            let tenant = tenant_id_of(index, &principal.tenant)?;
            self.services
                .principals
                .upsert(
                    &self.contexts.admin(tenant),
                    PrincipalSpec {
                        name: principal.name.clone(),
                        body: principal_body(principal, Some(principal.status)),
                    },
                    Conditions::none(),
                )
                .await
                .map_err(|error| seed_error(&format!("the status of `{}`", principal.name), &error))?;
        }
        Ok(())
    }
}

/// Creates a calendar of the `mirror` kind with the binding of its owner, the way the application creates every
/// calendar (a row and the owner's binding in one transaction).
async fn create_mirror(
    deps: &AppDeps,
    index: &SeedIndex,
    key: &FixtureCalendarRef,
    display_name: &str,
) -> Result<(), TestAppError> {
    let tenant = tenant_id_of(index, &key.tenant)?;
    let owner = principal_id_of(index, &key.tenant, &key.owner)?;
    let now = deps.clock.now();
    let mut tx = deps
        .database
        .begin(tenant, TxMode::ReadWrite)
        .await
        .map_err(|error| seed_error("a write transaction", &error))?;
    let calendar = tx
        .calendars()
        .create(Calendar {
            id: CalendarId::from_uuid(deps.ids.new_id()),
            tenant_id: tenant,
            owner_id: owner,
            slug: key.slug.clone(),
            kind: CalendarKind::Mirror,
            display_name: display_name.to_owned(),
            description: None,
            color: None,
            sort_order: 0,
            components: TenantSettings::default().allowed_components,
            timezone_ics: None,
            sync_seq: 0,
            sync_min_seq: 0,
            sync_epoch: deps.ids.new_id(),
            deleted_at: None,
            created_at: now,
            updated_at: now,
            version: 1,
        })
        .await
        .map_err(|error| seed_error("the mirror calendar", &error))?;
    tx.bindings()
        .create(Binding {
            id: BindingId::from_uuid(deps.ids.new_id()),
            tenant_id: tenant,
            principal_id: owner,
            calendar_id: calendar.id,
            slug: key.slug.clone(),
            display_name: None,
            color: None,
            sort_order: None,
            schedule_transp: None,
            hidden: false,
            created_at: now,
            updated_at: now,
            version: 1,
        })
        .await
        .map_err(|error| seed_error("the binding of the mirror calendar", &error))?;
    tx.commit()
        .await
        .map_err(|error| seed_error("the commit of the mirror calendar", &error))?;
    Ok(())
}

/// Stores the credentials of the world as the credential service stores what it issues: only the keyed hash.
async fn seed_credentials(deps: &AppDeps, world: &FixtureWorld, index: &SeedIndex) -> Result<(), TestAppError> {
    for credential in &world.credentials {
        match credential.kind {
            CredentialKind::AppPassword => seed_app_password(deps, index, credential).await?,
            CredentialKind::ApiToken => seed_api_token(deps, index, credential).await?,
            CredentialKind::FeedToken | CredentialKind::RsvpToken => {
                return Err(TestAppError::Seed(format!(
                    "the credential `{}` is a feed or RSVP token, which tests create when they need one",
                    credential.label
                )));
            }
        }
    }
    Ok(())
}

/// Stores the hash of an app password.
async fn seed_app_password(
    deps: &AppDeps,
    index: &SeedIndex,
    credential: &FixtureCredential,
) -> Result<(), TestAppError> {
    let now = deps.clock.now();
    let FixtureCredential {
        label,
        tenant,
        principal,
        secret,
        ..
    } = credential;
    let (Some(tenant), Some(principal)) = (tenant, principal) else {
        return Err(TestAppError::Seed(format!(
            "the app password `{label}` has no principal"
        )));
    };
    let parsed = AppPasswordText::parse(secret)
        .ok_or_else(|| TestAppError::Seed(format!("the app password `{label}` is malformed")))?;
    let hashed = deps.hasher.hash(
        CredentialKind::AppPassword,
        &SecretString::from(parsed.expose().to_owned()),
    );
    let tenant_id = index
        .tenant(tenant.as_str())
        .ok_or_else(|| TestAppError::Seed(format!("the tenant of `{label}` is unknown")))?;
    let principal_id = index
        .principal(tenant.as_str(), principal.as_str())
        .ok_or_else(|| TestAppError::Seed(format!("the principal of `{label}` is unknown")))?;
    let mut tx = deps
        .database
        .begin(tenant_id, TxMode::ReadWrite)
        .await
        .map_err(|error| seed_error("a write transaction", &error))?;
    tx.credentials()
        .create_app_password(AppPassword {
            id: CredentialId::from_uuid(deps.ids.new_id()),
            tenant_id,
            principal_id,
            label: label.clone(),
            prefix: parsed.prefix().to_owned(),
            hash: hashed.hash,
            pepper_kid: hashed.pepper_kid,
            last_used_at: None,
            revoked_at: None,
            created_at: now,
            updated_at: now,
            version: 1,
        })
        .await
        .map_err(|error| seed_error(&format!("the app password `{label}`"), &error))?;
    tx.commit()
        .await
        .map_err(|error| seed_error("the commit of an app password", &error))?;
    Ok(())
}

/// Stores the hash of an API token: a system token through a system transaction, the others in their tenant.
async fn seed_api_token(deps: &AppDeps, index: &SeedIndex, credential: &FixtureCredential) -> Result<(), TestAppError> {
    let now = deps.clock.now();
    let FixtureCredential {
        label,
        tenant,
        token_kind,
        principal,
        scopes,
        expires_in_days,
        secret,
        ..
    } = credential;
    let token_kind = token_kind.ok_or_else(|| TestAppError::Seed(format!("the API token `{label}` has no kind")))?;
    let token = TokenText::parse(CredentialKind::ApiToken, secret)
        .ok_or_else(|| TestAppError::Seed(format!("the API token `{label}` is malformed")))?;
    let hashed = deps
        .hasher
        .hash(CredentialKind::ApiToken, &SecretString::from(token.secret().to_owned()));
    let tenant_id = tenant
        .as_ref()
        .map(|slug| {
            index
                .tenant(slug.as_str())
                .ok_or_else(|| TestAppError::Seed(format!("the tenant of `{label}` is unknown")))
        })
        .transpose()?;
    let principal_id = match (tenant, principal) {
        (Some(tenant), Some(principal)) => Some(
            index
                .principal(tenant.as_str(), principal.as_str())
                .ok_or_else(|| TestAppError::Seed(format!("the principal of `{label}` is unknown")))?,
        ),
        _ => None,
    };
    let row = ApiToken {
        id: TokenId::from_uuid(deps.ids.new_id()),
        tenant_id,
        kind: token_kind,
        principal_id,
        label: label.clone(),
        scopes: *scopes,
        prefix: token.prefix().to_owned(),
        hash: hashed.hash,
        pepper_kid: hashed.pepper_kid,
        expires_at: expires_in_days.map(|days| now + Duration::days(i64::from(days))),
        created_by: None,
        allowed_origins: Vec::new(),
        last_used_at: None,
        revoked_at: None,
        created_at: now,
        updated_at: now,
        version: 1,
    };
    match (token_kind, tenant_id) {
        (TokenKind::System, _) | (_, None) => {
            let mut tx = deps
                .database
                .begin_system()
                .await
                .map_err(|error| seed_error("a system transaction", &error))?;
            tx.credential_lookup()
                .create_system_token(row)
                .await
                .map_err(|error| seed_error(&format!("the system token `{label}`"), &error))?;
            tx.commit()
                .await
                .map_err(|error| seed_error("the commit of a system token", &error))?;
        }
        (_, Some(tenant_id)) => {
            let mut tx = deps
                .database
                .begin(tenant_id, TxMode::ReadWrite)
                .await
                .map_err(|error| seed_error("a write transaction", &error))?;
            tx.credentials()
                .create_api_token(row)
                .await
                .map_err(|error| seed_error(&format!("the API token `{label}`"), &error))?;
            tx.commit()
                .await
                .map_err(|error| seed_error("the commit of an API token", &error))?;
        }
    }
    Ok(())
}

/// Stores a feed token that renders `calendars` for `principal`, with the constant secret `secret` (a text in the format
/// of feed tokens). The token is made even when the principal cannot read the calendars: access is checked again on
/// every request, which is what the permission matrix looks at.
///
/// # Errors
///
/// [`TestAppError::Seed`] when the secret is malformed or the store refuses the token.
pub async fn mint_feed_token(
    deps: &AppDeps,
    tenant: TenantId,
    principal: PrincipalId,
    calendars: Vec<CalendarId>,
    secret: &str,
) -> Result<(), TestAppError> {
    let token = TokenText::parse(CredentialKind::FeedToken, secret)
        .ok_or_else(|| TestAppError::Seed("the feed token is malformed".to_owned()))?;
    let hashed = deps.hasher.hash(
        CredentialKind::FeedToken,
        &SecretString::from(token.secret().to_owned()),
    );
    let now = deps.clock.now();
    let mut tx = deps
        .database
        .begin(tenant, TxMode::ReadWrite)
        .await
        .map_err(|error| seed_error("a write transaction", &error))?;
    tx.credentials()
        .create_feed_token(FeedToken {
            id: TokenId::from_uuid(deps.ids.new_id()),
            tenant_id: tenant,
            principal_id: principal,
            mode: FeedMode::Full,
            calendar_ids: calendars,
            prefix: token.prefix().to_owned(),
            hash: hashed.hash,
            pepper_kid: hashed.pepper_kid,
            revoked_at: None,
            created_at: now,
            updated_at: now,
            version: 1,
        })
        .await
        .map_err(TestAppError::Store)?;
    tx.commit()
        .await
        .map_err(|error| seed_error("the commit of a feed token", &error))?;
    Ok(())
}
