//! Signed cursors for every paged listing of the application (the management API lists principals, calendars, grants,
//! credentials, events, tenants, audit records, the outbox and the webhooks with them). The module belongs to no
//! feature: the listings call it, it calls nothing of theirs.
//!
//! A cursor is `v1.{kid}.{id}.{mac}`: the id of the last item of the page and an HMAC over tenant, listing and id
//! made with the key ring (purpose `Cursor`). A client cannot forge a position, and a cursor of one listing or one
//! tenant is useless for another. The key id comes first so that a cursor made before a key rotation still verifies.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use davhaven_domain::RequestContext;
use davhaven_ports::{KeyPurpose, PageReq, Signature};
use davhaven_wire::Cursor;
use uuid::Uuid;

use crate::error::{AppError, AppResult, SafeMessage};
use crate::services::PageRequest;
use crate::wiring::AppCore;

const VERSION: &str = "v1";

fn invalid() -> AppError {
    AppError::invalid(SafeMessage::from_static("The cursor is not valid."))
}

/// What the signature covers.
fn payload(ctx: &RequestContext, listing: &str, id: Uuid) -> Vec<u8> {
    format!("davhaven/cursor/{VERSION}/{}/{listing}/{id}", ctx.tenant).into_bytes()
}

/// The store request of a listing: the page size clamped to the API limits and the position of a verified cursor.
///
/// # Errors
///
/// `Invalid` for a cursor that is not genuine, belongs to another listing or tenant, or is damaged.
pub(crate) fn page_request(
    core: &AppCore,
    ctx: &RequestContext,
    listing: &str,
    request: &PageRequest,
) -> AppResult<PageReq> {
    let limit = core.deps().limits.api.page_size(request.limit);
    let after = request
        .cursor
        .as_ref()
        .map(|cursor| open(core, ctx, listing, cursor.as_str()))
        .transpose()?;
    Ok(PageReq { limit, after })
}

fn open(core: &AppCore, ctx: &RequestContext, listing: &str, text: &str) -> AppResult<Uuid> {
    // The key id may contain dots, so the text is read from the right: mac, id, then `v1.{kid}`.
    let mut parts = text.rsplitn(3, '.');
    let (Some(mac), Some(id), Some(head)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(invalid());
    };
    let (VERSION, kid) = head.split_once('.').ok_or_else(invalid)? else {
        return Err(invalid());
    };
    let id = Uuid::parse_str(id).map_err(|_| invalid())?;
    let mac = URL_SAFE_NO_PAD.decode(mac).map_err(|_| invalid())?;
    let signature = Signature::new(kid, mac);
    if core
        .deps()
        .keyring
        .verify(KeyPurpose::Cursor, &payload(ctx, listing, id), &signature)
    {
        Ok(id)
    } else {
        Err(invalid())
    }
}

/// The cursor of the page after the item `next`, if there is one.
///
/// # Errors
///
/// `Internal` when the cursor text is not representable (a key id with characters outside printable ASCII).
pub(crate) fn next_cursor(
    core: &AppCore,
    ctx: &RequestContext,
    listing: &str,
    next: Option<Uuid>,
) -> AppResult<Option<Cursor>> {
    let Some(id) = next else {
        return Ok(None);
    };
    let signature = core.deps().keyring.sign(KeyPurpose::Cursor, &payload(ctx, listing, id));
    let text = format!(
        "{VERSION}.{}.{}.{}",
        signature.kid,
        id.simple(),
        URL_SAFE_NO_PAD.encode(&signature.mac)
    );
    Cursor::parse(&text).map(Some).map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use davhaven_domain::{ErrorKind, RequestId, TenantId};
    use uuid::Uuid;

    use super::*;
    use crate::outbox::fixture::Fixture;

    fn ctx(tenant: u128) -> RequestContext {
        RequestContext::internal(
            TenantId::from_uuid(Uuid::from_u128(tenant)),
            RequestId::from_uuid(Uuid::from_u128(9)),
        )
    }

    #[test]
    fn a_cursor_round_trips_for_its_listing_and_tenant() {
        let core = Fixture::new().core;
        let id = Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_0042);
        let cursor = next_cursor(&core, &ctx(1), "outbox", Some(id)).unwrap().unwrap();
        assert!(cursor.as_str().starts_with("v1.test."), "{cursor}");
        let request = PageRequest::with_limit(500).after(cursor);
        let page = page_request(&core, &ctx(1), "outbox", &request).unwrap();
        assert_eq!(page.after, Some(id));
        assert_eq!(page.limit, 200, "the limit is clamped to the maximum page size");
        assert_eq!(
            page_request(&core, &ctx(1), "outbox", &PageRequest::first())
                .unwrap()
                .limit,
            50
        );
        assert_eq!(next_cursor(&core, &ctx(1), "outbox", None).unwrap(), None);
    }

    #[test]
    fn foreign_forged_and_damaged_cursors_are_invalid() {
        let core = Fixture::new().core;
        let id = Uuid::from_u128(7);
        let cursor = next_cursor(&core, &ctx(1), "outbox", Some(id)).unwrap().unwrap();
        let text = cursor.as_str().to_owned();
        let other_listing = page_request(&core, &ctx(1), "webhooks", &PageRequest::first().after(cursor.clone()));
        let other_tenant = page_request(&core, &ctx(2), "outbox", &PageRequest::first().after(cursor));
        assert_eq!(other_listing.unwrap_err().kind(), ErrorKind::Invalid);
        assert_eq!(other_tenant.unwrap_err().kind(), ErrorKind::Invalid);
        let tampered = text.replace(&id.simple().to_string(), &Uuid::from_u128(8).simple().to_string());
        for bad in [
            tampered.as_str(),
            "v1.test.not-a-uuid.AAAA",
            "v2.test.00000000000000000000000000000007.AAAA",
            "v1.other.00000000000000000000000000000007.AAAA",
            "v1.test.00000000000000000000000000000007.!!!!",
            "v1.test.00000000000000000000000000000007",
            "garbage",
            "v1..",
        ] {
            let request = PageRequest::first().after(Cursor::parse(bad).unwrap());
            let error = page_request(&core, &ctx(1), "outbox", &request).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Invalid, "{bad}");
        }
    }
}
