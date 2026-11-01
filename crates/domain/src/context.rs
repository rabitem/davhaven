//! The per-request context: tenant, actor, channel, scopes, credential reference and request id.
//!
//! Authentication produces a [`RequestContext`]; every application service takes it as its first argument. The
//! context says who acts ([`Actor`]), through which surface ([`Channel`]) and with which token scopes; the
//! authorization functions in [`crate::authz`] decide from it.

use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::authz::Subject;
use crate::ids::{CredentialId, ObjectId, PrincipalId, RequestId, TenantId, TokenId};
use crate::keys::{CalendarUserAddress, Locale};
use crate::scope::ScopeSet;

text_enum!(
    /// The surface a request arrived on. Credentials are bound to their surface: app passwords work on `dav`
    /// only, API tokens on `api` and `mcp`, feed and RSVP tokens on their pages.
    Channel [] {
        /// WebDAV and CalDAV.
        Dav => "dav",
        /// The management API.
        Api => "api",
        /// The MCP server.
        Mcp => "mcp",
        /// Subscription feeds.
        Feed => "feed",
        /// RSVP pages.
        Rsvp => "rsvp",
        /// Server-originated work (workers, the sync engine, internal delivery). Never produced by
        /// authentication.
        Internal => "internal",
    }
);

text_enum!(
    /// The kind of a presented credential.
    CredentialKind [] {
        /// A per-device DAV app password.
        AppPassword => "app_password",
        /// A management API or MCP token.
        ApiToken => "api_token",
        /// A subscription feed token.
        FeedToken => "feed_token",
        /// An RSVP link token.
        RsvpToken => "rsvp_token",
    }
);

/// A reference to the credential a request was authenticated with (never the secret).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CredentialRef {
    /// What kind of credential it is.
    pub kind: CredentialKind,
    /// The credential's id: a [`CredentialId`] for app passwords, a [`TokenId`] for the token kinds.
    pub id: Uuid,
}

impl CredentialRef {
    /// Reference to an app password.
    pub const fn app_password(id: CredentialId) -> Self {
        Self {
            kind: CredentialKind::AppPassword,
            id: id.as_uuid(),
        }
    }

    /// Reference to an API token.
    pub const fn api_token(id: TokenId) -> Self {
        Self {
            kind: CredentialKind::ApiToken,
            id: id.as_uuid(),
        }
    }

    /// Reference to a feed token.
    pub const fn feed_token(id: TokenId) -> Self {
        Self {
            kind: CredentialKind::FeedToken,
            id: id.as_uuid(),
        }
    }

    /// Reference to an RSVP token.
    pub const fn rsvp_token(id: TokenId) -> Self {
        Self {
            kind: CredentialKind::RsvpToken,
            id: id.as_uuid(),
        }
    }
}

/// Who performs a request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Actor {
    /// A principal authenticated with an app password (DAV).
    Principal(PrincipalId),
    /// A principal acting through a principal API token (API, MCP).
    PrincipalToken {
        /// The principal the token acts as.
        principal: PrincipalId,
        /// The token.
        token: TokenId,
    },
    /// A tenant administrator token.
    TenantToken(TokenId),
    /// A system token (tenant management only).
    SystemToken(TokenId),
    /// A subscription feed reader.
    FeedReader {
        /// The principal whose access the feed is rendered with.
        principal: PrincipalId,
        /// The feed token.
        token: TokenId,
    },
    /// An attendee answering through an RSVP link.
    RsvpAttendee {
        /// The invitation the link belongs to.
        object: ObjectId,
        /// The attendee the link was issued to.
        address: CalendarUserAddress,
    },
    /// No authentication (discovery requests, internal work).
    Anonymous,
}

impl Actor {
    /// The principal the actor acts as, for the kinds that act as one.
    pub const fn principal(&self) -> Option<PrincipalId> {
        match self {
            Self::Principal(principal)
            | Self::PrincipalToken { principal, .. }
            | Self::FeedReader { principal, .. } => Some(*principal),
            Self::TenantToken(_) | Self::SystemToken(_) | Self::RsvpAttendee { .. } | Self::Anonymous => None,
        }
    }

    /// Whether the actor presented a credential.
    pub const fn is_authenticated(&self) -> bool {
        !matches!(self, Self::Anonymous)
    }

    /// A stable lowercase name for logs and audit records.
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Principal(_) => "principal",
            Self::PrincipalToken { .. } => "principal_token",
            Self::TenantToken(_) => "tenant_token",
            Self::SystemToken(_) => "system_token",
            Self::FeedReader { .. } => "feed_reader",
            Self::RsvpAttendee { .. } => "rsvp_attendee",
            Self::Anonymous => "anonymous",
        }
    }

    /// The id of the token the actor authenticated with, for the token-based kinds.
    pub const fn token(&self) -> Option<TokenId> {
        match self {
            Self::PrincipalToken { token, .. }
            | Self::FeedReader { token, .. }
            | Self::TenantToken(token)
            | Self::SystemToken(token) => Some(*token),
            Self::Principal(_) | Self::RsvpAttendee { .. } | Self::Anonymous => None,
        }
    }
}

/// Everything the application layer needs to know about the caller of one request.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestContext {
    /// The tenant the request operates in (resolved from the path, the login domain or the token).
    pub tenant: TenantId,
    /// Who acts.
    pub actor: Actor,
    /// The scopes of the credential (checked on the API and MCP surfaces).
    pub scopes: ScopeSet,
    /// The surface the request arrived on.
    pub channel: Channel,
    /// The credential the request was authenticated with.
    pub credential: Option<CredentialRef>,
    /// The request id, echoed to the client and carried through logs.
    pub request_id: RequestId,
    /// The locale from the request (for example `Accept-Language`), if any.
    pub locale: Option<Locale>,
    /// The client IP after trusted-proxy processing.
    pub client_ip: Option<IpAddr>,
}

impl RequestContext {
    /// The context of server-originated work in `tenant`: no actor, no scopes, the internal channel.
    pub const fn internal(tenant: TenantId, request_id: RequestId) -> Self {
        Self {
            tenant,
            actor: Actor::Anonymous,
            scopes: ScopeSet::empty(),
            channel: Channel::Internal,
            credential: None,
            request_id,
            locale: None,
            client_ip: None,
        }
    }

    /// The principal the request acts as, if any.
    pub const fn principal(&self) -> Option<PrincipalId> {
        self.actor.principal()
    }

    /// The caller as seen by the authorization functions.
    pub fn subject(&self) -> Subject {
        Subject::from(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Case = (Actor, Option<PrincipalId>, Option<TokenId>, &'static str, bool);

    fn principal(n: u128) -> PrincipalId {
        PrincipalId::from_uuid(Uuid::from_u128(n))
    }

    fn token(n: u128) -> TokenId {
        TokenId::from_uuid(Uuid::from_u128(n))
    }

    #[test]
    fn actors_expose_their_principal_and_token() {
        let p = principal(1);
        let t = token(2);
        let attendee = Actor::RsvpAttendee {
            object: ObjectId::from_uuid(Uuid::from_u128(3)),
            address: CalendarUserAddress::parse("mailto:guest@example.org").unwrap(),
        };
        let cases: Vec<Case> = vec![
            (Actor::Principal(p), Some(p), None, "principal", true),
            (
                Actor::PrincipalToken { principal: p, token: t },
                Some(p),
                Some(t),
                "principal_token",
                true,
            ),
            (Actor::TenantToken(t), None, Some(t), "tenant_token", true),
            (Actor::SystemToken(t), None, Some(t), "system_token", true),
            (
                Actor::FeedReader { principal: p, token: t },
                Some(p),
                Some(t),
                "feed_reader",
                true,
            ),
            (attendee, None, None, "rsvp_attendee", true),
            (Actor::Anonymous, None, None, "anonymous", false),
        ];
        for (actor, expected_principal, expected_token, name, authenticated) in cases {
            assert_eq!(actor.principal(), expected_principal, "{name}");
            assert_eq!(actor.token(), expected_token, "{name}");
            assert_eq!(actor.kind_name(), name);
            assert_eq!(actor.is_authenticated(), authenticated, "{name}");
        }
    }

    #[test]
    fn internal_contexts_have_no_actor_and_no_scopes() {
        let ctx = RequestContext::internal(
            TenantId::from_uuid(Uuid::from_u128(1)),
            RequestId::from_uuid(Uuid::from_u128(2)),
        );
        assert_eq!(ctx.channel, Channel::Internal);
        assert_eq!(ctx.actor, Actor::Anonymous);
        assert!(ctx.scopes.is_empty());
        assert_eq!(ctx.principal(), None);
        assert_eq!(ctx.credential, None);
        assert_eq!(ctx.subject().actor, Actor::Anonymous);
    }

    #[test]
    fn credential_refs_carry_kind_and_id() {
        let c = CredentialId::from_uuid(Uuid::from_u128(7));
        let t = token(8);
        assert_eq!(CredentialRef::app_password(c).kind, CredentialKind::AppPassword);
        assert_eq!(CredentialRef::app_password(c).id, Uuid::from_u128(7));
        assert_eq!(CredentialRef::api_token(t).kind, CredentialKind::ApiToken);
        assert_eq!(CredentialRef::feed_token(t).kind, CredentialKind::FeedToken);
        assert_eq!(CredentialRef::rsvp_token(t).kind, CredentialKind::RsvpToken);
        assert_eq!(CredentialRef::api_token(t).id, Uuid::from_u128(8));
    }

    #[test]
    fn channels_and_credential_kinds_have_stable_names() {
        let channels: Vec<&str> = Channel::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(channels, vec!["dav", "api", "mcp", "feed", "rsvp", "internal"]);
        let kinds: Vec<&str> = CredentialKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(kinds, vec!["app_password", "api_token", "feed_token", "rsvp_token"]);
        assert_eq!(serde_json::to_string(&Channel::Mcp).unwrap(), "\"mcp\"");
        assert_eq!("rsvp".parse::<Channel>().unwrap(), Channel::Rsvp);
        assert!("smtp".parse::<Channel>().is_err());
    }
}
