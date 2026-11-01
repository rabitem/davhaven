//! Cases of principals, their addresses, group memberships, search and purge.

use davhaven_domain::{
    CalendarUserAddress, CollectionKey, CollectionKind, GrantStatus, InboxItem, Locale, Notification, NotificationKind,
    ObjectUri, PrincipalKind, PrincipalStatus, SearchCriterion, SearchField, TextMatch, TimeZoneName,
};
use davhaven_ports::{
    Expected, InboxScope, MembershipDiff, PageReq, PrincipalFilter, PrincipalQuery, StoreError, Tx, UniqueKey,
};

use super::Outcome;
use super::world::{
    Db, StoreChecks, address, app_password, at, begin, binding, epoch, feed_token, grant, id, key, principal,
    scheduling, seed, version,
};
use crate::suite::Checks;
use davhaven_domain::{ETag, InboxItemId, NotificationId, Uid};

/// Creating, reading and updating principals.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn principals_crud(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let mut ann = principal(0x110, "ann", PrincipalKind::User)?;
    ann.external_ref = Some("crm-1".to_owned());
    ann.locale = Some(key(Locale::parse("de"))?);
    ann.timezone = Some(key(TimeZoneName::parse("Europe/Berlin"))?);
    ann.credential_generation = 0;
    let created = tx.principals().create(ann.clone()).await?;
    checks.equal(
        &created.tenant_id,
        &world.a,
        "the store binds the principal to the transaction's tenant",
    );
    checks.equal(&created.version, &1, "a new principal has version 1");
    checks.equal(
        &created.created_at,
        &created.updated_at,
        "creation stamps both times alike",
    );
    checks.that(created.created_at != epoch(), "the store stamps created_at itself");
    checks.equal(
        &created.external_ref,
        &ann.external_ref,
        "the external reference is stored",
    );
    checks.equal(&created.locale, &ann.locale, "the locale is stored");
    checks.equal(&created.timezone, &ann.timezone, "the time zone is stored");
    checks.equal(
        &tx.principals().get(created.id).await?,
        &created,
        "get returns what create returned",
    );
    checks.equal(
        &tx.principals().get_by_name(&created.name).await?,
        &created,
        "get by name",
    );
    checks.equal(
        &tx.principals().find_by_external_ref("crm-1").await?,
        &Some(created.clone()),
        "find by external reference",
    );
    checks.equal(
        &tx.principals().find_by_external_ref("nope").await?,
        &None,
        "an unknown external reference",
    );
    checks.not_found(tx.principals().get(id(0x999)).await, "an unknown principal");
    checks.not_found(
        tx.principals()
            .get_by_name(&key(davhaven_domain::PrincipalName::parse("nobody"))?)
            .await,
        "an unknown name",
    );

    let mut changed = principal(0x110, "renamed", PrincipalKind::Group)?;
    changed.display_name = "Ann B.".into();
    changed.email = None;
    changed.locale = None;
    changed.timezone = None;
    changed.external_ref = Some("crm-2".to_owned());
    changed.status = PrincipalStatus::Suspended;
    changed.credential_generation = 5;
    let updated = tx.principals().update(changed.clone(), created.version).await?;
    checks.equal(&updated.version, &2, "an update bumps the version");
    checks.equal(&updated.name, &created.name, "the name is immutable");
    checks.equal(&updated.kind, &created.kind, "the kind is immutable");
    checks.equal(
        &updated.credential_generation,
        &0,
        "the credential generation changes only through its own method",
    );
    checks.equal(&updated.display_name.as_str(), &"Ann B.", "the display name changes");
    checks.equal(&updated.email, &None, "the e-mail address changes");
    checks.equal(&updated.status, &PrincipalStatus::Suspended, "the status changes");
    checks.equal(
        &updated.external_ref.as_deref(),
        &Some("crm-2"),
        "the external reference changes",
    );
    checks.equal(&updated.created_at, &created.created_at, "creation time stays");
    checks.precondition_failed(
        tx.principals().update(changed.clone(), created.version).await,
        "a stale version",
    );
    checks.not_found(
        tx.principals()
            .update(principal(0x998, "ghost", PrincipalKind::User)?, 1)
            .await,
        "an unknown principal",
    );

    let mut deleted = updated.clone();
    deleted.status = PrincipalStatus::Deleted;
    deleted.deleted_at = Some(at(9));
    let hidden = tx.principals().update(deleted, updated.version).await?;
    checks.equal(&hidden.deleted_at, &Some(at(9)), "the deletion time is stored");
    checks.equal(
        &tx.principals().get(created.id).await?.status,
        &PrincipalStatus::Deleted,
        "get returns principals of every status",
    );
    tx.commit().await?;
    Ok(())
}

/// Listing principals with filters and pages.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn principals_filters_and_pages(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let mut ann = principal(0x111, "ann", PrincipalKind::User)?;
    ann.external_ref = Some("ext-ann".to_owned());
    tx.principals().create(ann).await?;
    tx.principals()
        .create(principal(0x112, "bob", PrincipalKind::User)?)
        .await?;
    tx.principals()
        .create(principal(0x113, "svc", PrincipalKind::Service)?)
        .await?;
    let dan = tx
        .principals()
        .create(principal(0x114, "dan", PrincipalKind::User)?)
        .await?;
    let mut deleted = dan.clone();
    deleted.status = PrincipalStatus::Deleted;
    deleted.deleted_at = Some(at(8));
    tx.principals().update(deleted, dan.version).await?;

    let names = |page: &davhaven_ports::StorePage<davhaven_domain::Principal>| -> Vec<String> {
        page.items.iter().map(|principal| principal.name.to_string()).collect()
    };
    let all = tx
        .principals()
        .list(&PrincipalFilter::default(), PageReq::default())
        .await?;
    checks.equal(
        &names(&all),
        &["olivia", "mia", "team", "ann", "bob", "svc"]
            .map(str::to_owned)
            .to_vec(),
        "deleted principals are excluded by default, the rest is in id order",
    );
    let with_deleted = tx
        .principals()
        .list(
            &PrincipalFilter {
                include_deleted: true,
                ..PrincipalFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(
        &with_deleted.items.len(),
        &7,
        "include_deleted adds the deleted principal",
    );
    let only_deleted = tx
        .principals()
        .list(
            &PrincipalFilter {
                status: Some(PrincipalStatus::Deleted),
                ..PrincipalFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(
        &names(&only_deleted),
        &vec!["dan".to_owned()],
        "an explicit status filter wins",
    );
    let services = tx
        .principals()
        .list(
            &PrincipalFilter {
                kind: Some(PrincipalKind::Service),
                ..PrincipalFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(&names(&services), &vec!["svc".to_owned()], "the kind filter");
    let external = tx
        .principals()
        .list(
            &PrincipalFilter {
                external_ref: Some("ext-ann".to_owned()),
                ..PrincipalFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(
        &names(&external),
        &vec!["ann".to_owned()],
        "the external reference filter",
    );

    let first = tx
        .principals()
        .list(&PrincipalFilter::default(), PageReq::first(4))
        .await?;
    checks.equal(&first.items.len(), &4, "the first page is full");
    let cursor = first.next;
    checks.that(cursor.is_some(), "and names a cursor");
    if let Some(cursor) = cursor {
        let second = tx
            .principals()
            .list(&PrincipalFilter::default(), PageReq::first(4).after(cursor))
            .await?;
        checks.equal(
            &names(&second),
            &vec!["bob".to_owned(), "svc".to_owned()],
            "the second page continues",
        );
        checks.equal(&second.next, &None, "and is the last");
    }
    Ok(())
}

/// Names and external references are unique; violations are typed and leave the transaction usable.
pub(super) async fn principals_unique_keys(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    checks.unique(
        tx.principals()
            .create(principal(0x120, "olivia", PrincipalKind::User)?)
            .await,
        UniqueKey::PrincipalName,
        "a duplicate name",
    );
    let mut first = principal(0x121, "first", PrincipalKind::User)?;
    first.external_ref = Some("same".to_owned());
    let first = tx.principals().create(first).await?;
    let mut second = principal(0x122, "second", PrincipalKind::User)?;
    second.external_ref = Some("same".to_owned());
    checks.unique(
        tx.principals().create(second.clone()).await,
        UniqueKey::ExternalRef,
        "a duplicate external reference",
    );
    second.external_ref = Some("other".to_owned());
    let second = tx.principals().create(second).await?;
    let mut clash = second.clone();
    clash.external_ref = Some("same".to_owned());
    checks.unique(
        tx.principals().update(clash, second.version).await,
        UniqueKey::ExternalRef,
        "updating to a taken external reference",
    );
    checks.equal(
        &tx.principals().get(second.id).await?.external_ref.as_deref(),
        &Some("other"),
        "a failed update changes nothing",
    );
    checks.equal(
        &first.name.as_str(),
        &"first",
        "the transaction is usable after violations",
    );
    // A deleted principal is hidden but keeps its name and external reference reserved until the purge, and both still
    // resolve to it, so that a caller can tell a value that is taken by a hidden principal from a free one (the
    // application answers `external-ref-reserved` and the 412 of `If-None-Match: *` for them).
    let mut hidden = first.clone();
    hidden.status = PrincipalStatus::Deleted;
    hidden.deleted_at = Some(at(7));
    tx.principals().update(hidden, first.version).await?;
    let mut third = principal(0x124, "third", PrincipalKind::User)?;
    third.external_ref = Some("same".to_owned());
    checks.unique(
        tx.principals().create(third.clone()).await,
        UniqueKey::ExternalRef,
        "the external reference of a deleted principal stays reserved",
    );
    checks.equal(
        &tx.principals()
            .find_by_external_ref("same")
            .await?
            .map(|found| (found.id, found.status)),
        &Some((first.id, PrincipalStatus::Deleted)),
        "and still resolves to it",
    );
    checks.equal(
        &tx.principals().get_by_name(&first.name).await?.status,
        &PrincipalStatus::Deleted,
        "the name of a deleted principal resolves too",
    );
    let mut renamed = third;
    renamed.name = first.name.clone();
    renamed.external_ref = None;
    checks.unique(
        tx.principals().create(renamed).await,
        UniqueKey::PrincipalName,
        "and the name stays reserved as well",
    );
    let others = tx
        .principals()
        .list(
            &PrincipalFilter {
                external_ref: Some("same".to_owned()),
                ..PrincipalFilter::default()
            },
            PageReq::first(10),
        )
        .await?;
    checks.equal(
        &others.items.len(),
        &0,
        "the listing by external reference does not show the deleted principal",
    );
    tx.commit().await?;
    // The same name and external reference are free in another tenant.
    let mut tx = begin(db, world.b).await?;
    let mut twin = principal(0x123, "first", PrincipalKind::User)?;
    twin.external_ref = Some("same".to_owned());
    tx.principals().create(twin).await?;
    tx.commit().await?;
    Ok(())
}

/// Addresses: ordering, case-insensitive uniqueness, replacement and reservation.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn principals_addresses(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let lower = "https://example.org/principals/olivia/";
    let mixed = "https://example.org/PRINCIPALS/olivia/";
    tx.principals()
        .set_addresses(
            world.olivia,
            vec![
                address(world.olivia, "urn:uuid:018f3c1e-7b2a-7c3d-9e4f-0123456789ab", false)?,
                address(world.olivia, lower, false)?,
                address(world.olivia, "mailto:olivia@example.org", true)?,
            ],
        )
        .await?;
    let stored = tx.principals().addresses(world.olivia).await?;
    let texts: Vec<&str> = stored.iter().map(|stored| stored.address.as_str()).collect();
    checks.equal(
        &texts,
        &vec![
            "mailto:olivia@example.org",
            lower,
            "urn:uuid:018f3c1e-7b2a-7c3d-9e4f-0123456789ab",
        ],
        "the primary address comes first, then the others in address order",
    );
    checks.equal(
        &stored.iter().filter(|stored| stored.primary).count(),
        &1,
        "one primary address",
    );
    let by_address = tx
        .principals()
        .find_by_address(&key(CalendarUserAddress::parse(mixed))?)
        .await?;
    checks.equal(
        &by_address.map(|found| found.id),
        &Some(world.olivia),
        "addresses match case-insensitively",
    );
    checks.equal(
        &tx.principals()
            .find_by_address(&key(CalendarUserAddress::parse("mailto:nobody@example.org"))?)
            .await?,
        &None,
        "an unknown address",
    );
    checks.unique(
        tx.principals()
            .set_addresses(world.mia, vec![address(world.mia, mixed, false)?])
            .await,
        UniqueKey::Address,
        "an address another principal owns, in another case",
    );
    checks.equal(
        &tx.principals().addresses(world.mia).await?.len(),
        &0,
        "a failed replacement changes nothing",
    );
    checks.unique(
        tx.principals()
            .set_addresses(
                world.mia,
                vec![
                    address(world.mia, "mailto:twin@example.org", false)?,
                    address(world.mia, "MAILTO:Twin@example.org", false)?,
                ],
            )
            .await,
        UniqueKey::Address,
        "the same address twice in one list",
    );
    checks.internal(
        tx.principals()
            .set_addresses(world.mia, vec![address(world.olivia, "mailto:x@example.org", false)?])
            .await,
        "an address that names another principal",
    );
    checks.internal(
        tx.principals()
            .set_addresses(
                world.mia,
                vec![
                    address(world.mia, "mailto:a@example.org", true)?,
                    address(world.mia, "mailto:b@example.org", true)?,
                ],
            )
            .await,
        "two primary addresses",
    );
    checks.not_found(
        tx.principals().set_addresses(id(0x999), Vec::new()).await,
        "an unknown principal",
    );
    checks.not_found(
        tx.principals().addresses(id(0x999)).await,
        "the addresses of an unknown principal",
    );

    tx.principals()
        .set_addresses(
            world.olivia,
            vec![address(world.olivia, "mailto:olivia@example.org", true)?],
        )
        .await?;
    tx.principals()
        .set_addresses(world.mia, vec![address(world.mia, lower, false)?])
        .await?;
    checks.equal(
        &tx.principals().addresses(world.mia).await?.len(),
        &1,
        "a replaced address is free for others",
    );

    let olivia = tx.principals().get(world.olivia).await?;
    let mut deleted = olivia.clone();
    deleted.status = PrincipalStatus::Deleted;
    deleted.deleted_at = Some(at(9));
    tx.principals().update(deleted, olivia.version).await?;
    checks.unique(
        tx.principals()
            .set_addresses(
                world.team,
                vec![address(world.team, "mailto:olivia@example.org", false)?],
            )
            .await,
        UniqueKey::Address,
        "the address of a deleted principal stays reserved",
    );
    checks.equal(
        &tx.principals()
            .find_by_address(&key(CalendarUserAddress::parse("mailto:olivia@example.org"))?)
            .await?
            .map(|found| found.status),
        &Some(PrincipalStatus::Deleted),
        "and still resolves, so callers can tell taken from free",
    );
    tx.commit().await?;
    Ok(())
}

/// Searching principals by name, display name and address.
pub(super) async fn principals_search(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let mut anna = principal(0x130, "anna.schmidt", PrincipalKind::User)?;
    anna.display_name = "Anna Schmidt".into();
    tx.principals().create(anna).await?;
    let mut anton = principal(0x131, "room-anton", PrincipalKind::Resource)?;
    anton.display_name = "Anton Room".into();
    tx.principals().create(anton).await?;
    let mut bernd = principal(0x132, "bernd", PrincipalKind::Service)?;
    bernd.display_name = "Bernd Anders".into();
    tx.principals().create(bernd).await?;
    let mut carl = principal(0x133, "carl", PrincipalKind::User)?;
    carl.display_name = "Carl Anselm".into();
    let carl = tx.principals().create(carl).await?;
    tx.principals()
        .set_addresses(carl.id, vec![address(carl.id, "mailto:findme@corp.example", true)?])
        .await?;
    let mut dora = principal(0x134, "dora", PrincipalKind::User)?;
    dora.display_name = "Dora An".into();
    let dora = tx.principals().create(dora).await?;
    let mut suspended = dora.clone();
    suspended.status = PrincipalStatus::Suspended;
    tx.principals().update(suspended, dora.version).await?;

    let found = tx
        .principals()
        .search(&PrincipalQuery {
            text: "AN".to_owned(),
            kinds: Vec::new(),
            limit: 10,
            ..PrincipalQuery::default()
        })
        .await?;
    let names: Vec<String> = found.iter().map(|hit| hit.principal.name.to_string()).collect();
    checks.equal(
        &names,
        &["anna.schmidt", "room-anton", "carl"].map(str::to_owned).to_vec(),
        "case-insensitive substring over names and display names, active users, groups and resources, by display name",
    );
    let by_address = tx
        .principals()
        .search(&PrincipalQuery {
            text: "Corp.Example".to_owned(),
            kinds: Vec::new(),
            limit: 10,
            ..PrincipalQuery::default()
        })
        .await?;
    checks.equal(&by_address.len(), &1, "the search covers addresses");
    checks.equal(
        &by_address.first().map(|hit| hit.addresses.len()),
        &Some(1),
        "and returns the addresses of the hit",
    );
    let services = tx
        .principals()
        .search(&PrincipalQuery {
            text: "bernd".to_owned(),
            kinds: vec![PrincipalKind::Service],
            limit: 10,
            ..PrincipalQuery::default()
        })
        .await?;
    checks.equal(&services.len(), &1, "service principals are found when asked for");
    let limited = tx
        .principals()
        .search(&PrincipalQuery {
            text: "an".to_owned(),
            kinds: Vec::new(),
            limit: 1,
            ..PrincipalQuery::default()
        })
        .await?;
    checks.equal(&limited.len(), &1, "the limit caps the hits");
    Ok(())
}

/// The names of the principals a search finds, in the order of the result.
async fn found_names(tx: &mut dyn Tx, query: PrincipalQuery) -> Result<Vec<String>, StoreError> {
    Ok(tx
        .principals()
        .search(&query)
        .await?
        .iter()
        .map(|hit| hit.principal.name.to_string())
        .collect())
}

/// Search criteria: the properties they look into, how they compare, all of them or any of them, together with the
/// plain text and the kinds, and all of it before the limit cuts the result.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn principals_search_criteria(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    // Sixty people whose display name starts with "Anna A", so that the first fifty by display name all contain "anna".
    for number in 0..60_u128 {
        let mut person = principal(0x400 + number, &format!("rosa{number:02}"), PrincipalKind::User)?;
        person.display_name = format!("Anna Aaron Rosa {number:02}");
        tx.principals().create(person).await?;
    }
    let mut bauer = principal(0x500, "abauer", PrincipalKind::User)?;
    bauer.display_name = "Anna Bauer".into();
    let bauer = tx.principals().create(bauer).await?;
    tx.principals()
        .set_addresses(
            bauer.id,
            vec![
                address(bauer.id, "mailto:anna.bauer@corp.example", true)?,
                address(bauer.id, "urn:uuid:00000000-0000-0000-0000-00000000abab", false)?,
            ],
        )
        .await?;
    let mut ben = principal(0x501, "ben", PrincipalKind::User)?;
    ben.display_name = "Ben Baker".into();
    let ben = tx.principals().create(ben).await?;
    tx.principals()
        .set_addresses(ben.id, vec![address(ben.id, "mailto:Ben@Acme.Example", true)?])
        .await?;
    let mut room = principal(0x502, "room1", PrincipalKind::Resource)?;
    room.display_name = "Meeting Room 1".into();
    tx.principals().create(room).await?;

    let criterion =
        |text: &str, fields: &[SearchField], matching: TextMatch| SearchCriterion::new(text, fields.to_vec(), matching);
    let search = |text: &str, criteria: Vec<SearchCriterion>, any_of: bool, limit: u32| PrincipalQuery {
        text: text.to_owned(),
        limit,
        criteria,
        any_of,
        ..PrincipalQuery::default()
    };
    let strings = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect::<Vec<String>>();

    // Every condition is applied before the limit: more than fifty people contain "anna", yet the one whose display
    // name also contains "bau" is found, and the plain text alone is cut at the limit without her.
    let crowded = found_names(tx.as_mut(), search("anna", Vec::new(), false, 50)).await?;
    checks.equal(&crowded.len(), &50, "the limit cuts the people that contain the text");
    checks.that(
        !crowded.contains(&"abauer".to_owned()),
        "Anna Bauer is behind the first fifty by display name",
    );
    for second in ["b", "bau", "baue", "bauer"] {
        let criteria = vec![SearchCriterion::contains("anna"), SearchCriterion::contains(second)];
        checks.equal(
            &found_names(tx.as_mut(), search("", criteria, false, 50)).await?,
            &strings(&["abauer"]),
            &format!("all of [anna, {second}] are applied before the limit"),
        );
    }
    checks.equal(
        &found_names(
            tx.as_mut(),
            search("anna", vec![SearchCriterion::contains("bau")], false, 50),
        )
        .await?,
        &strings(&["abauer"]),
        "the plain text and the criteria are all required",
    );

    // The properties a criterion looks into.
    let cases: Vec<(SearchCriterion, Vec<&str>, &str)> = vec![
        (
            criterion("ANNA BAUER", &[SearchField::DisplayName], TextMatch::Equals),
            vec!["abauer"],
            "the display name equals the text, ignoring case",
        ),
        (
            criterion("bauer", &[SearchField::DisplayName], TextMatch::StartsWith),
            vec![],
            "no display name starts with it",
        ),
        (
            criterion("anna b", &[SearchField::DisplayName], TextMatch::StartsWith),
            vec!["abauer"],
            "a display name starts with it",
        ),
        (
            criterion("ABAUER", &[SearchField::Name], TextMatch::Equals),
            vec!["abauer"],
            "the name",
        ),
        (
            criterion("abauer", &[SearchField::DisplayName], TextMatch::Contains),
            vec![],
            "the name is not the display name",
        ),
        (
            criterion("mailto:anna.", &[SearchField::Address], TextMatch::StartsWith),
            vec!["abauer"],
            "the address with its scheme",
        ),
        (
            criterion("mailto:anna.", &[SearchField::Email], TextMatch::StartsWith),
            vec![],
            "the e-mail part has no scheme",
        ),
        (
            criterion("anna.bauer@", &[SearchField::Email], TextMatch::StartsWith),
            vec!["abauer"],
            "the e-mail part without it",
        ),
        (
            criterion("BEN@acme.example", &[SearchField::Email], TextMatch::Equals),
            vec!["ben"],
            "an address that was written in mixed case",
        ),
        (
            criterion("urn:uuid:", &[SearchField::Email], TextMatch::Contains),
            vec![],
            "a stored address that is no mail address has no e-mail part",
        ),
        (
            criterion(
                "00000000-0000-0000-0000-00000000abab",
                &[SearchField::Address],
                TextMatch::Contains,
            ),
            vec!["abauer"],
            "a stored address that is no mail address is an address",
        ),
        (
            criterion(
                "ben",
                &[SearchField::DisplayName, SearchField::Email],
                TextMatch::StartsWith,
            ),
            vec!["ben"],
            "one of several properties is enough",
        ),
        (
            criterion("meeting", &[], TextMatch::Contains),
            vec!["room1"],
            "no property means the name, the display name and the addresses",
        ),
    ];
    for (criterion, expected, message) in cases {
        let found = found_names(tx.as_mut(), search("", vec![criterion], false, 100)).await?;
        checks.equal(&found, &strings(&expected), message);
    }

    // One of the criteria is enough with `any_of`; the result stays ordered by display name.
    let either = vec![
        criterion("Meeting Room 1", &[SearchField::DisplayName], TextMatch::Equals),
        criterion("ben@acme.example", &[SearchField::Email], TextMatch::Equals),
    ];
    checks.equal(
        &found_names(tx.as_mut(), search("", either.clone(), true, 10)).await?,
        &strings(&["ben", "room1"]),
        "one of two criteria",
    );
    checks.equal(
        &found_names(tx.as_mut(), search("", either, false, 10)).await?,
        &strings(&[]),
        "all of two criteria that nobody satisfies together",
    );
    checks.equal(
        &found_names(tx.as_mut(), search("", Vec::new(), true, 3)).await?.len(),
        &3,
        "no criteria are satisfied by everybody, whatever any_of says",
    );
    checks.equal(
        &found_names(
            tx.as_mut(),
            search("room", vec![criterion("ben", &[], TextMatch::Contains)], true, 10),
        )
        .await?,
        &strings(&[]),
        "the plain text is required next to the criteria",
    );

    // The kinds narrow the search before the limit as well.
    let mut rooms = search("", vec![SearchCriterion::contains("e")], false, 1);
    rooms.kinds = vec![PrincipalKind::Resource];
    checks.equal(
        &found_names(tx.as_mut(), rooms).await?,
        &strings(&["room1"]),
        "a room is found although the first by display name is a person that matches too",
    );
    let mut services = search("", vec![SearchCriterion::contains("e")], false, 1);
    services.kinds = vec![PrincipalKind::Service];
    checks.equal(
        &found_names(tx.as_mut(), services).await?,
        &strings(&[]),
        "no service of that name",
    );
    Ok(())
}

/// The credential generation counts up without touching the version.
pub(super) async fn principals_credential_generation(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let before = tx.principals().get(world.olivia).await?;
    checks.equal(
        &tx.principals().bump_credential_generation(world.olivia).await?,
        &1,
        "the first bump",
    );
    checks.equal(
        &tx.principals().bump_credential_generation(world.olivia).await?,
        &2,
        "the second bump",
    );
    let after = tx.principals().get(world.olivia).await?;
    checks.equal(&after.credential_generation, &2, "the generation is stored");
    checks.equal(&after.version, &before.version, "the version does not change");
    checks.not_found(
        tx.principals().bump_credential_generation(id(0x999)).await,
        "an unknown principal",
    );
    Ok(())
}

/// Group memberships.
pub(super) async fn memberships(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    checks.equal(
        &tx.memberships().members(world.team).await?,
        &vec![world.mia],
        "members of the group",
    );
    checks.equal(
        &tx.memberships().groups_of(world.mia).await?,
        &vec![world.team],
        "groups of the member",
    );
    checks.equal(
        &tx.memberships().groups_of(world.olivia).await?,
        &Vec::new(),
        "no groups",
    );
    checks.equal(
        &tx.memberships().add_member(world.team, world.olivia).await?,
        &true,
        "adding a new member",
    );
    checks.equal(
        &tx.memberships().add_member(world.team, world.olivia).await?,
        &false,
        "adding a member twice",
    );
    checks.not_found(
        tx.memberships().add_member(world.team, id(0x999)).await,
        "an unknown member",
    );
    checks.not_found(
        tx.memberships().add_member(id(0x999), world.mia).await,
        "an unknown group",
    );
    checks.equal(
        &tx.memberships().remove_member(world.team, world.olivia).await?,
        &true,
        "removing a member",
    );
    checks.equal(
        &tx.memberships().remove_member(world.team, world.olivia).await?,
        &false,
        "removing a non-member",
    );
    checks.not_found(
        tx.memberships().remove_member(id(0x999), world.mia).await,
        "removing from an unknown group",
    );
    checks.not_found(
        tx.memberships().members(id(0x999)).await,
        "the members of an unknown group",
    );

    let diff = tx
        .memberships()
        .set_members(world.team, &[world.olivia, world.olivia])
        .await?;
    checks.equal(
        &diff,
        &MembershipDiff {
            added: vec![world.olivia],
            removed: vec![world.mia],
        },
        "setting the members reports what was added and removed, duplicates counted once",
    );
    checks.equal(
        &tx.memberships().members(world.team).await?,
        &vec![world.olivia],
        "the set replaced the members",
    );
    checks.not_found(
        tx.memberships().set_members(world.team, &[world.mia, id(0x999)]).await,
        "a set that names an unknown member",
    );
    checks.equal(
        &tx.memberships().members(world.team).await?,
        &vec![world.olivia],
        "a failed set changes nothing",
    );
    checks.not_found(
        tx.memberships().set_members(id(0x999), &[]).await,
        "a set for an unknown group",
    );
    let empty = tx.memberships().set_members(world.team, &[]).await?;
    checks.that(
        empty.added.is_empty() && empty.removed == vec![world.olivia],
        "an empty set removes everybody",
    );
    checks.that(
        tx.memberships().set_members(world.team, &[]).await?.is_empty(),
        "setting the same members again changes nothing",
    );
    tx.commit().await?;
    Ok(())
}

/// Purging a principal removes everything that belongs to it and clears the references to it.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn principals_purge_removes_everything(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let event = scheduling(
        version(0x401, "meeting.ics", "meeting-1")?,
        "mailto:olivia@example.org",
        &[("mailto:mia@example.org", Some(world.mia))],
    )?;
    let written = tx.objects().put(world.personal, event, Expected::Absent).await?;
    tx.principals()
        .set_addresses(world.mia, vec![address(world.mia, "mailto:mia@example.org", true)?])
        .await?;
    tx.bindings()
        .create(binding(0x501, world.mia, world.shared, "projects")?)
        .await?;
    tx.grants()
        .create(grant(0x601, world.shared, world.mia, GrantStatus::Accepted))
        .await?;
    tx.credentials()
        .create_app_password(app_password(0x701, world.mia, "mia-pass"))
        .await?;
    // A grantee's feed token names calendars of other owners in an array the store cannot cascade through.
    tx.principals()
        .create(principal(0x104, "guest", PrincipalKind::User)?)
        .await?;
    tx.credentials()
        .create_feed_token(feed_token(
            0x702,
            id(0x104),
            vec![world.personal, world.shared, world.team_calendar],
            "guest-feed",
        ))
        .await?;
    let uri = key(ObjectUri::parse("invite.xml"))?;
    tx.notifications()
        .create(Notification {
            id: id::<NotificationId>(0x801),
            tenant_id: world.a,
            principal_id: world.mia,
            uri: uri.clone(),
            uid: key(Uid::parse("invite-1"))?,
            etag: ETag::from_bytes(b"x"),
            kind: NotificationKind::Invite,
            body_xml: "<x/>".to_owned(),
            created_at: epoch(),
            updated_at: epoch(),
            version: 1,
        })
        .await?;
    tx.inbox()
        .create(InboxItem {
            id: id::<InboxItemId>(0x901),
            tenant_id: world.a,
            principal_id: world.mia,
            uri,
            etag: ETag::from_bytes(b"y"),
            data: "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_owned(),
            quarantined: false,
            created_at: epoch(),
            updated_at: epoch(),
            version: 1,
        })
        .await?;
    tx.commit().await?;

    let mut tx = begin(db, world.a).await?;
    tx.principals().purge(world.mia).await?;
    checks.not_found(tx.principals().get(world.mia).await, "the purged principal");
    checks.equal(
        &tx.memberships().members(world.team).await?,
        &Vec::new(),
        "its memberships",
    );
    checks.equal(
        &tx.grants().for_calendar(world.shared).await?,
        &Vec::new(),
        "its grants",
    );
    checks.equal(&tx.bindings().list_for(world.mia).await?.len(), &0, "its bindings");
    checks.equal(
        &tx.credentials().list_app_passwords(world.mia).await?,
        &Vec::new(),
        "its credentials",
    );
    checks.equal(
        &tx.notifications().list(world.mia).await?,
        &Vec::new(),
        "its notifications",
    );
    checks.equal(
        &tx.inbox().list(world.mia, InboxScope::Delivered).await?,
        &Vec::new(),
        "its inbox",
    );
    checks.equal(
        &tx.principals()
            .find_by_address(&key(CalendarUserAddress::parse("mailto:mia@example.org"))?)
            .await?,
        &None,
        "its addresses are free again",
    );
    let attendees = tx.objects().attendees(written.object_id).await?;
    checks.equal(
        &attendees
            .iter()
            .map(|attendee| attendee.principal_id)
            .collect::<Vec<_>>(),
        &vec![None],
        "the reference from an attendee row is cleared, the row stays",
    );
    checks.not_found(
        tx.changes()
            .state(CollectionKey {
                kind: CollectionKind::Home,
                id: world.mia.as_uuid(),
            })
            .await,
        "its change logs",
    );
    tx.principals().purge(world.olivia).await?;
    let feeds = tx.credentials().list_feed_tokens(id(0x104)).await?;
    checks.equal(
        &feeds.iter().map(|token| token.calendar_ids.clone()).collect::<Vec<_>>(),
        &vec![vec![world.team_calendar]],
        "the calendars of a purged owner disappear from other principals' feed tokens (no dangling ids)",
    );
    checks.not_found(
        tx.calendars().get(world.personal).await,
        "the calendars of a purged owner",
    );
    checks.not_found(tx.objects().get_by_id(written.object_id).await, "and their objects");
    checks.not_found(
        tx.changes()
            .state(CollectionKey {
                kind: CollectionKind::Calendar,
                id: world.personal.as_uuid(),
            })
            .await,
        "and their change logs",
    );
    checks.not_found(tx.principals().purge(world.olivia).await, "purging twice");
    tx.commit().await?;
    Ok(())
}

/// German and other non-ASCII text round-trips verbatim, and case-insensitive matching treats non-ASCII letters
/// the same in every adapter (the PostgreSQL adapter needs a Unicode-aware `LC_CTYPE` for it).
pub(super) async fn principals_unicode_text(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let mut oezlem = principal(0x140, "oezlem", PrincipalKind::User)?;
    oezlem.display_name = "Özlem Öztürk-Großmann".into();
    let oezlem = tx.principals().create(oezlem).await?;
    let mut party = principal(0x141, "party", PrincipalKind::User)?;
    party.display_name = "Fête 🎉 Zoë 𝒜".into();
    let party = tx.principals().create(party).await?;
    checks.equal(
        &tx.principals().get(oezlem.id).await?.display_name.as_str(),
        &"Özlem Öztürk-Großmann",
        "umlauts and ß are stored verbatim",
    );
    checks.equal(
        &tx.principals().get(party.id).await?.display_name.as_str(),
        &"Fête 🎉 Zoë 𝒜",
        "so are accents and characters outside the Basic Multilingual Plane",
    );
    tx.principals()
        .set_addresses(
            oezlem.id,
            vec![address(oezlem.id, "mailto:oezlem@beispiel.example", true)?],
        )
        .await?;

    for (text, expected) in [
        ("ÖZLEM", "oezlem"),
        ("özlem", "oezlem"),
        ("öztürk-groß", "oezlem"),
        ("ZOË", "party"),
        ("🎉", "party"),
        ("BEISPIEL.EXAMPLE", "oezlem"),
    ] {
        let found = tx
            .principals()
            .search(&PrincipalQuery {
                text: text.to_owned(),
                kinds: Vec::new(),
                limit: 10,
                ..PrincipalQuery::default()
            })
            .await?;
        checks.equal(
            &found
                .iter()
                .map(|hit| hit.principal.name.to_string())
                .collect::<Vec<_>>(),
            &vec![expected.to_owned()],
            &format!("searching `{text}` matches case-insensitively beyond ASCII"),
        );
    }
    tx.commit().await?;
    Ok(())
}

/// The batch reads (`find_by_addresses`, `get_many`, `get_many_by_name`, `addresses_many`, `members_of_many`,
/// `groups_of_many`) answer exactly what the single reads answer, in the order the contract names.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn principals_batch_reads(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let ops = id::<davhaven_domain::PrincipalId>(0x104);
    tx.principals()
        .create(principal(0x104, "ops", PrincipalKind::Group)?)
        .await?;
    tx.principals()
        .set_addresses(
            world.olivia,
            vec![
                address(world.olivia, "mailto:olivia@example.org", true)?,
                address(world.olivia, "https://example.org/principals/olivia/", false)?,
            ],
        )
        .await?;
    tx.principals()
        .set_addresses(world.mia, vec![address(world.mia, "mailto:mia@example.org", true)?])
        .await?;
    let olivia_mail = key(CalendarUserAddress::parse("mailto:olivia@example.org"))?;
    let olivia_url = key(CalendarUserAddress::parse("https://example.org/PRINCIPALS/olivia/"))?;
    let mia_mail = key(CalendarUserAddress::parse("mailto:mia@example.org"))?;
    let nobody = key(CalendarUserAddress::parse("mailto:nobody@example.org"))?;

    // find_by_addresses: one entry per distinct address that has an owner, in the order asked, whatever the case.
    let found = tx
        .principals()
        .find_by_addresses(&[
            mia_mail.clone(),
            nobody.clone(),
            olivia_url.clone(),
            mia_mail.clone(),
            olivia_mail.clone(),
        ])
        .await?;
    let named: Vec<(&str, davhaven_domain::PrincipalId)> = found
        .iter()
        .map(|(address, principal)| (address.as_str(), principal.id))
        .collect();
    checks.equal(
        &named,
        &vec![
            (mia_mail.as_str(), world.mia),
            (olivia_url.as_str(), world.olivia),
            (olivia_mail.as_str(), world.olivia),
        ],
        "find_by_addresses answers once per distinct address with an owner, in the order asked, and one principal \
         may appear with several addresses",
    );
    for (address, principal) in &found {
        checks.equal(
            &tx.principals().find_by_address(address).await?,
            &Some(principal.clone()),
            "find_by_addresses agrees with find_by_address",
        );
    }
    checks.equal(
        &tx.principals().find_by_addresses(&[]).await?.len(),
        &0,
        "find_by_addresses without addresses",
    );
    checks.equal(
        &tx.principals().find_by_addresses(&[nobody]).await?.len(),
        &0,
        "find_by_addresses with an unknown address",
    );
    let olivia = tx.principals().get(world.olivia).await?;
    let mut hidden = olivia.clone();
    hidden.status = PrincipalStatus::Deleted;
    hidden.deleted_at = Some(at(9));
    tx.principals().update(hidden, olivia.version).await?;
    let reserved = tx.principals().find_by_addresses(&[olivia_mail]).await?;
    checks.equal(
        &reserved.into_iter().map(|(_, found)| found.status).collect::<Vec<_>>(),
        &vec![PrincipalStatus::Deleted],
        "find_by_addresses finds the reserved address of a deleted principal, as find_by_address does",
    );

    // get_many and get_many_by_name keep the order asked, skip the unknown and answer once for a repeated key.
    let team = tx.principals().get(world.team).await?;
    let mia = tx.principals().get(world.mia).await?;
    let olivia = tx.principals().get(world.olivia).await?;
    checks.equal(
        &tx.principals()
            .get_many(&[world.mia, id(0x999), world.olivia, world.mia, world.team])
            .await?,
        &vec![mia.clone(), olivia.clone(), team.clone()],
        "get_many: the order asked, deleted principals included, unknown ids skipped, a repeated id once",
    );
    checks.equal(&tx.principals().get_many(&[]).await?.len(), &0, "get_many without ids");
    checks.equal(
        &tx.principals()
            .get_many_by_name(&[
                team.name.clone(),
                key(davhaven_domain::PrincipalName::parse("nobody"))?,
                olivia.name.clone(),
                team.name.clone(),
            ])
            .await?,
        &vec![team.clone(), olivia.clone()],
        "get_many_by_name: the order asked, unknown names skipped, a repeated name once",
    );

    // addresses_many: grouped by principal in id order, each group in the order of `addresses`.
    let mut expected = Vec::new();
    for principal in [world.olivia, world.mia] {
        expected.extend(tx.principals().addresses(principal).await?);
    }
    checks.equal(
        &tx.principals()
            .addresses_many(&[world.mia, world.team, id(0x999), world.olivia, world.mia])
            .await?,
        &expected,
        "addresses_many: principals in id order, unknown ones and principals without addresses contribute nothing",
    );
    checks.equal(
        &tx.principals().addresses_many(&[]).await?.len(),
        &0,
        "addresses_many without ids",
    );

    // Memberships in both directions.
    tx.memberships()
        .set_members(world.team, &[world.mia, world.olivia])
        .await?;
    tx.memberships().set_members(ops, &[world.olivia]).await?;
    checks.equal(
        &tx.memberships()
            .members_of_many(&[ops, world.team, id(0x999), ops])
            .await?,
        &vec![(world.team, world.olivia), (world.team, world.mia), (ops, world.olivia)],
        "members_of_many: groups in id order, members in id order, unknown groups skipped, a repeated group once",
    );
    checks.equal(
        &tx.memberships()
            .groups_of_many(&[world.mia, world.olivia, id(0x999), world.team, world.mia])
            .await?,
        &vec![(world.olivia, world.team), (world.olivia, ops), (world.mia, world.team)],
        "groups_of_many: members in id order, groups in id order, principals without groups contribute nothing",
    );
    checks.equal(
        &(tx.memberships().members_of_many(&[]).await?.len() + tx.memberships().groups_of_many(&[]).await?.len()),
        &0,
        "memberships in batch without ids",
    );
    tx.commit().await?;
    Ok(())
}
