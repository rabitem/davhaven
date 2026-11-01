//! The credentials of the roles of a fixture world on every surface.
//!
//! A [`CredentialBook`] answers "how does this role present itself on that surface". The in-process application seeds
//! the constant secrets of the fixture world into its store, so its book is [`CredentialBook::from_world`]; a deployed
//! instance issues its own secrets (they cannot be chosen through the management API), so the staging runner fills a
//! book with what the instance returned. Everything above (the matrices, the scenario runner) asks the book.
//!
//! Principals present their app password on DAV and their principal token on the API and MCP surfaces; the roles
//! without an app password (the service principal) present their token on DAV too, which a server must refuse. Tenant
//! and system tokens present themselves as bearer tokens everywhere. Feed and RSVP pages identify by the token in the
//! URL, so no role has a credential header there.
//!
//! The book holds live secrets (on a deployed instance the operator's own tokens among them), so it never prints them:
//! `Debug` lists what the book holds, not what it holds it as.

use core::fmt;
use std::collections::BTreeMap;

use davhaven_fixtures::{ActorRole, FixtureWorld, PRINCIPAL_TOKEN_SCOPE_LABEL, TENANT_TOKEN_SCOPE_LABEL};

use crate::handles::Actor;
use crate::matrix::Surface;

/// How the roles of a world present themselves.
#[derive(Clone, Default)]
pub struct CredentialBook {
    /// DAV logins and app passwords by role.
    app_passwords: BTreeMap<ActorRole, (String, String)>,
    /// Principal tokens by role, each with whether it carries the scopes of MCP (`mcp:read`, `mcp:write`).
    principal_tokens: BTreeMap<ActorRole, (String, bool)>,
    /// Principal tokens that carry exactly one scope, by role and scope.
    scoped_principal_tokens: BTreeMap<(ActorRole, String), String>,
    /// Tenant tokens of the main tenant by the one scope they carry; `None` is the token with every tenant scope.
    tenant_tokens: BTreeMap<Option<String>, String>,
    /// The tenant token with every scope of the other tenant.
    other_tenant_admin: Option<String>,
    /// The system token.
    system_token: Option<String>,
}

impl fmt::Debug for CredentialBook {
    /// The roles and scopes the book holds credentials for; never a secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialBook")
            .field("app_passwords", &self.app_passwords.keys().collect::<Vec<_>>())
            .field("principal_tokens", &self.principal_tokens.keys().collect::<Vec<_>>())
            .field(
                "scoped_principal_tokens",
                &self
                    .scoped_principal_tokens
                    .keys()
                    .map(|(role, scope)| format!("{role}[{scope}]"))
                    .collect::<Vec<_>>(),
            )
            .field(
                "tenant_tokens",
                &self
                    .tenant_tokens
                    .keys()
                    .map(|scope| scope.as_deref().unwrap_or("every scope").to_owned())
                    .collect::<Vec<_>>(),
            )
            .field(
                "other_tenant_admin",
                &self.other_tenant_admin.as_ref().map(|_| "<redacted>"),
            )
            .field("system_token", &self.system_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl CredentialBook {
    /// An empty book.
    pub fn new() -> Self {
        Self::default()
    }

    /// The book of the constant secrets of `world`: what the in-process application seeds into its store.
    pub fn from_world(world: &FixtureWorld) -> Self {
        let mut book = Self::new();
        for role in ActorRole::ALL {
            if let (Ok(login), Ok(password)) = (world.login(*role), world.app_password(*role)) {
                book.set_app_password(*role, &login, &password.secret);
            }
            if let Ok(token) = world.principal_token(*role) {
                // The tokens of the world carry every scope a principal token may have, the scopes of MCP among them.
                book.set_principal_token(*role, &token.secret, true);
            }
        }
        if let Ok(token) = world.admin_token() {
            book.set_tenant_token(None, &token.secret);
        }
        for credential in &world.credentials {
            if let Some(scope) = credential.label.strip_prefix(TENANT_TOKEN_SCOPE_LABEL) {
                book.set_tenant_token(Some(scope), &credential.secret);
            }
            if let Some(rest) = credential.label.strip_prefix(PRINCIPAL_TOKEN_SCOPE_LABEL) {
                // `{tenant}:{name}:{scope}`: the scope itself contains a colon, so only the first two colons split.
                let mut parts = rest.splitn(3, ':');
                if let (Some(_tenant), Some(name), Some(scope)) = (parts.next(), parts.next(), parts.next())
                    && let Some(role) = ActorRole::ALL.iter().find(|role| role.principal_name() == Some(name))
                {
                    book.set_scoped_principal_token(*role, scope, &credential.secret);
                }
            }
        }
        if let Ok(token) = world.other_tenant_admin_token() {
            book.set_other_tenant_admin(&token.secret);
        }
        if let Ok(token) = world.system_token() {
            book.set_system_token(&token.secret);
        }
        book
    }

    /// Records the DAV login and app password of a role.
    pub fn set_app_password(&mut self, role: ActorRole, login: &str, password: &str) {
        self.app_passwords.insert(role, (login.to_owned(), password.to_owned()));
    }

    /// Records the principal token of a role, and whether it carries the scopes of MCP. The in-process application stores tokens
    /// that do. A deployed instance issues them to service principals through the management API and to everybody else only
    /// through `davhaven admin principal-token create` (a token mints tokens with a subset of its own scopes, and no tenant
    /// token can carry the scopes of MCP), so the book of a deployed world says for each token which kind it is.
    pub fn set_principal_token(&mut self, role: ActorRole, secret: &str, carries_mcp_scopes: bool) {
        self.principal_tokens
            .insert(role, (secret.to_owned(), carries_mcp_scopes));
    }

    /// Records the principal token of a role that carries exactly `scope`.
    pub fn set_scoped_principal_token(&mut self, role: ActorRole, scope: &str, secret: &str) {
        self.scoped_principal_tokens
            .insert((role, scope.to_owned()), secret.to_owned());
    }

    /// Records a tenant token: with `scope` the token that carries exactly that scope, without the one with every
    /// tenant scope.
    pub fn set_tenant_token(&mut self, scope: Option<&str>, secret: &str) {
        self.tenant_tokens.insert(scope.map(str::to_owned), secret.to_owned());
    }

    /// Records the tenant token with every scope of the other tenant.
    pub fn set_other_tenant_admin(&mut self, secret: &str) {
        self.other_tenant_admin = Some(secret.to_owned());
    }

    /// Records the system token.
    pub fn set_system_token(&mut self, secret: &str) {
        self.system_token = Some(secret.to_owned());
    }

    /// The DAV login and app password of a role.
    pub fn app_password(&self, role: ActorRole) -> Option<(&str, &str)> {
        self.app_passwords
            .get(&role)
            .map(|(login, password)| (login.as_str(), password.as_str()))
    }

    /// The principal token of a role.
    pub fn principal_token(&self, role: ActorRole) -> Option<&str> {
        self.principal_tokens.get(&role).map(|(secret, _)| secret.as_str())
    }

    /// The principal token of a role that carries exactly `scope`.
    pub fn scoped_principal_token(&self, role: ActorRole, scope: &str) -> Option<&str> {
        self.scoped_principal_tokens
            .get(&(role, scope.to_owned()))
            .map(String::as_str)
    }

    /// Whether a case of `role` on MCP lacks the token that only the management API or the operator can issue. A principal role
    /// needs its principal token with the scopes of MCP; with `scope`, the token of the role that carries exactly that scope (which
    /// need not be a scope of MCP: the matrix presents the tokens of the other scopes to MCP too, and MCP refuses them). The roles
    /// that are only a credential (tenant and system tokens, anonymous) never lack one: they present what they have, MCP answers
    /// that too (a token that acts as nobody is offered no tools), and when they have nothing [`CredentialBook::actor`] says so.
    pub fn lacks_mcp_token(&self, role: ActorRole, scope: Option<&str>) -> bool {
        if role.principal_name().is_none() {
            return false;
        }
        match scope {
            Some(scope) => self.scoped_principal_token(role, scope).is_none(),
            None => !self
                .principal_tokens
                .get(&role)
                .is_some_and(|(_, carries_mcp_scopes)| *carries_mcp_scopes),
        }
    }

    /// The tenant token with every scope.
    pub fn admin_token(&self) -> Option<&str> {
        self.tenant_tokens.get(&None).map(String::as_str)
    }

    /// The tenant token that carries exactly `scope`.
    pub fn tenant_token(&self, scope: &str) -> Option<&str> {
        self.tenant_tokens.get(&Some(scope.to_owned())).map(String::as_str)
    }

    /// The tenant token with every scope of the other tenant.
    pub fn other_tenant_admin(&self) -> Option<&str> {
        self.other_tenant_admin.as_deref()
    }

    /// The system token.
    pub fn system_token(&self) -> Option<&str> {
        self.system_token.as_deref()
    }

    /// The credentials a role presents on a surface; `scope` selects the token that carries only that scope (tenant
    /// tokens, and the principal tokens of the roles that hold such tokens on the API and MCP). `None` when the role has no
    /// credential there (feed and RSVP pages are addressed by a token in the URL, and a role may lack a token).
    pub fn actor(&self, role: ActorRole, surface: Surface, scope: Option<&str>) -> Option<Actor> {
        if role == ActorRole::Anonymous {
            return Some(Actor::Anonymous);
        }
        match surface {
            Surface::Feed | Surface::Rsvp => None,
            Surface::Dav | Surface::Api | Surface::Mcp => match role {
                ActorRole::TenantToken => match scope {
                    Some(scope) => self.tenant_token(scope),
                    None => self.admin_token(),
                }
                .map(Actor::bearer),
                ActorRole::OtherTenantToken => self.other_tenant_admin().map(Actor::bearer),
                ActorRole::SystemToken => self.system_token().map(Actor::bearer),
                _ => {
                    if let Some(scope) = scope
                        && surface != Surface::Dav
                    {
                        return self.scoped_principal_token(role, scope).map(Actor::bearer);
                    }
                    let on_dav = (surface == Surface::Dav)
                        .then(|| self.app_password(role))
                        .flatten()
                        .map(|(login, password)| Actor::basic(login, password));
                    on_dav.or_else(|| self.principal_token(role).map(Actor::bearer))
                }
            },
        }
    }
}

/// The credentials a role presents on a surface in the constant world: a shorthand for
/// `CredentialBook::from_world(world).actor(role, surface, None)`.
pub fn credentials_of(world: &FixtureWorld, role: ActorRole, surface: Surface) -> Option<Actor> {
    CredentialBook::from_world(world).actor(role, surface, None)
}

#[cfg(test)]
mod tests {
    use davhaven_domain::Scope;

    use super::*;

    #[test]
    fn the_book_of_the_world_resolves_every_role() {
        let world = FixtureWorld::standard();
        let book = CredentialBook::from_world(&world);
        assert!(
            matches!(book.actor(ActorRole::Owner, Surface::Dav, None), Some(Actor::Basic { ref login, .. }) if login == "olivia@acme.example")
        );
        assert!(matches!(
            book.actor(ActorRole::Owner, Surface::Api, None),
            Some(Actor::Bearer(_))
        ));
        assert!(
            matches!(
                book.actor(ActorRole::ServicePrincipal, Surface::Dav, None),
                Some(Actor::Bearer(_))
            ),
            "no app password: the token is presented on DAV too"
        );
        assert_eq!(
            book.actor(ActorRole::Anonymous, Surface::Mcp, None),
            Some(Actor::Anonymous)
        );
        assert!(book.actor(ActorRole::Owner, Surface::Feed, None).is_none());
        assert!(book.system_token().is_some() && book.other_tenant_admin().is_some());
        let scoped = book.actor(ActorRole::TenantToken, Surface::Api, Some(Scope::EventsRead.as_str()));
        let all = book.actor(ActorRole::TenantToken, Surface::Api, None);
        assert!(scoped.is_some() && all.is_some() && scoped != all);
        assert!(
            book.actor(ActorRole::TenantToken, Surface::Api, Some("mcp:read"))
                .is_none(),
            "tenant tokens carry no mcp scopes"
        );
        for role in ActorRole::ALL.iter().filter(|role| role.principal_name().is_some()) {
            assert!(book.principal_token(*role).is_some(), "{role}");
            assert!(
                !book.lacks_mcp_token(*role, None),
                "{role}: the tokens of the world carry the scopes of MCP"
            );
        }
        for role in [
            ActorRole::TenantToken,
            ActorRole::OtherTenantToken,
            ActorRole::SystemToken,
            ActorRole::Anonymous,
        ] {
            assert!(
                !book.lacks_mcp_token(role, None),
                "{role}: the credential alone is what MCP answers"
            );
        }
        assert_eq!(
            credentials_of(&world, ActorRole::Owner, Surface::Dav),
            book.actor(ActorRole::Owner, Surface::Dav, None)
        );
    }

    #[test]
    fn the_owner_holds_a_token_for_each_scope_a_principal_token_may_carry() {
        let world = FixtureWorld::standard();
        let book = CredentialBook::from_world(&world);
        for scope in Scope::ALL
            .iter()
            .filter(|scope| scope.allowed_for(davhaven_domain::TokenKind::Principal))
        {
            let token = book.actor(ActorRole::Owner, Surface::Mcp, Some(scope.as_str()));
            assert!(matches!(token, Some(Actor::Bearer(_))), "{scope}");
            assert_ne!(token, book.actor(ActorRole::Owner, Surface::Mcp, None), "{scope}");
            assert_eq!(
                book.actor(ActorRole::Owner, Surface::Api, Some(scope.as_str())),
                token,
                "one token per scope on both token surfaces"
            );
        }
        assert!(
            book.actor(ActorRole::Owner, Surface::Api, Some("system:tenants"))
                .is_none(),
            "no principal token carries a scope that principals cannot have"
        );
        assert!(
            book.actor(ActorRole::ShareeRead, Surface::Api, Some("events:read"))
                .is_none(),
            "only the owner holds single-scope tokens"
        );
        assert_eq!(
            book.actor(ActorRole::Owner, Surface::Dav, Some("events:read")),
            book.actor(ActorRole::Owner, Surface::Dav, None),
            "DAV takes app passwords, which have no scopes"
        );
    }

    #[test]
    fn a_book_holds_what_it_is_given() {
        let mut book = CredentialBook::new();
        assert!(book.actor(ActorRole::Owner, Surface::Dav, None).is_none());
        book.set_app_password(ActorRole::Owner, "olivia@x.example", "pw");
        book.set_principal_token(ActorRole::Owner, "tok", false);
        assert_eq!(
            book.actor(ActorRole::Owner, Surface::Dav, None),
            Some(Actor::basic("olivia@x.example", "pw"))
        );
        assert_eq!(
            book.actor(ActorRole::Owner, Surface::Api, None),
            Some(Actor::bearer("tok"))
        );
    }

    #[test]
    fn a_role_is_asked_on_mcp_only_with_a_token_that_carries_its_scopes() {
        let mut book = CredentialBook::new();
        book.set_principal_token(ActorRole::Owner, "api-only", false);
        assert!(
            book.lacks_mcp_token(ActorRole::Owner, None),
            "a principal token that was issued through the management API has no scope of MCP"
        );
        assert!(book.lacks_mcp_token(ActorRole::Owner, Some("mcp:read")));
        book.set_principal_token(ActorRole::Owner, "operators", true);
        assert!(!book.lacks_mcp_token(ActorRole::Owner, None));
        assert!(
            book.lacks_mcp_token(ActorRole::ShareeRead, None),
            "a role without a token has nothing to present"
        );
        book.set_scoped_principal_token(ActorRole::Owner, "mcp:read", "scoped");
        assert!(!book.lacks_mcp_token(ActorRole::Owner, Some("mcp:read")));
        assert!(book.lacks_mcp_token(ActorRole::Owner, Some("mcp:write")));
        // The roles that are only a credential never lack a token: what they have is presented, and without it `actor` says so, which
        // is a better reason than a missing token of an operator.
        assert!(!book.lacks_mcp_token(ActorRole::TenantToken, None));
        assert!(!book.lacks_mcp_token(ActorRole::TenantToken, Some("mcp:read")));
        assert!(!book.lacks_mcp_token(ActorRole::SystemToken, None));
        assert!(book.actor(ActorRole::SystemToken, Surface::Mcp, None).is_none());
        assert!(!book.lacks_mcp_token(ActorRole::Anonymous, None));
    }

    #[test]
    fn a_book_never_prints_a_secret() {
        let world = FixtureWorld::standard();
        let book = CredentialBook::from_world(&world);
        let shown = format!("{book:?}");
        for credential in &world.credentials {
            assert!(!shown.contains(&credential.secret), "{}", credential.label);
        }
        assert!(shown.contains("Owner") || shown.contains("owner"), "{shown}");
        let mut with_system = book;
        with_system.set_system_token("dvh_pat_supersecret");
        assert!(!format!("{with_system:?}").contains("supersecret"));
        for credential in &world.credentials {
            assert!(
                !format!("{credential:?}").contains(&credential.secret),
                "{}",
                credential.label
            );
        }
    }
}
