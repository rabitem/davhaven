//! `DAV:principal-property-search`, `DAV:principal-search-property-set` and `CS:calendarserver-principal-search`.
//!
//! Calendar clients look up people to invite: Apple Calendar sends `CS:calendarserver-principal-search` while the
//! user types an attendee, other clients send `DAV:principal-property-search` (RFC 3744 section 9.4). Both are
//! `REPORT`s to the principal collection, which is the entry point `/dav/` (`principal-collection-set` of every
//! resource); a principal URL takes them too (and advertises them), every other resource answers 403
//! `DAV:supported-report`.
//!
//! The rules of PLAN 2.9 apply to both and are the application's: this module reads the request, hands it over as
//! **one search** and renders what comes back.
//!
//! * a search sees the principals of **the caller's tenant** and no others;
//! * a search needs a text of at least **two characters**; a request that has none finds nothing (the answer is an
//!   empty `multistatus`, not an error, so a client that searches while the user types has nothing to handle), and a
//!   text longer than any address finds nothing either;
//! * a search returns at most **50 principals**, ordered by href; an answer the limit cut ends with a 507 entry for
//!   the request URI (`DAV:number-of-matches-within-limits`), as CalendarServer answers, so a client knows that
//!   there are more people than it was shown and can refine the search;
//! * a found principal shows its **display name and addresses only**: `displayname`, `calendar-user-address-set`,
//!   `CS:email-address-set`, `calendar-user-type`, `principal-URL` and `resourcetype`. The URLs of its home, inbox,
//!   outbox and notification collection, its groups and its members are not part of an answer to a search
//!   ([`crate::props::Subject::SearchHit`]); every other requested property is a 404 `propstat`.
//!
//! Service principals are not people to invite and are never found.
//!
//! # How a search is answered
//!
//! Every condition of the request is a field of the one [`PrincipalSearch`] this module builds, so that the
//! application applies all of them (the kinds of principal, the texts, the properties they are looked for in and how
//! they are compared) in its query, **before** its limit of 50: a person is found whatever else matches the first
//! text, and nothing is decided or checked again here (`PrincipalService::find_principals`).
//!
//! * `CS:calendarserver-principal-search`: every token has to be in the name, the display name or a stored address of
//!   the principal, whatever its length (`Anna B` finds `Anna Bauer`), as long as one of them has two characters; the
//!   kinds of principal come from `context` and `type`. A search that asks for no kind of principal does not ask the
//!   application at all.
//! * `DAV:principal-property-search` with `allof`: every `property-search` has to be satisfied by one of the
//!   properties it names (`displayname`, `calendar-user-address-set`, `CS:email-address-set`) with the match type it
//!   says. One that names none of them cannot be satisfied and ends the search before the application is asked.
//! * `anyof`: one satisfied `property-search` is enough; one that names no searchable property, or whose text is too
//!   short to be looked up, contributes nothing.
//!
//! Only what the application stores is searched: the principal URL and the `urn:uuid:` address of a principal are
//! part of `calendar-user-address-set` when it is shown, but no search finds a principal by them.
//!
//! # `DAV:principal-property-search`
//!
//! A request has one or more `property-search` elements, each naming properties and a text to look for in them:
//!
//! ```xml
//! <D:principal-property-search xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" test="anyof">
//!   <D:property-search><D:prop><D:displayname/></D:prop><D:match>ben</D:match></D:property-search>
//!   <D:property-search><D:prop><C:calendar-user-address-set/></D:prop><D:match>ben</D:match></D:property-search>
//!   <D:prop><D:displayname/><C:calendar-user-address-set/></D:prop>
//! </D:principal-property-search>
//! ```
//!
//! Searchable are `displayname`, `calendar-user-address-set` and `CS:email-address-set` (what
//! `principal-search-property-set` lists). `test` is `allof` (the default: a principal must satisfy every
//! `property-search`) or `anyof`. `match` finds a **case insensitive substring**; the attribute `match-type` may say
//! `starts-with` or `equals` instead. A name that contains the text does not satisfy a search of the addresses. The
//! `Depth` header is not evaluated (RFC 3744 defines the report for `Depth: 0` only; every value is answered as `0`),
//! and a search sent to a principal URL covers the whole tenant like one sent to the entry point, with or without
//! `DAV:apply-to-principal-collection-set`. A request names at most `limits.dav.max_search_terms` `property-search`
//! elements.
//!
//! # `CS:calendarserver-principal-search`
//!
//! ```xml
//! <CS:calendarserver-principal-search xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/" context="attendee">
//!   <CS:search-token>ben</CS:search-token>
//!   <CS:limit><CS:nresults>20</CS:nresults></CS:limit>
//!   <D:prop><D:displayname/><C:calendar-user-address-set/></D:prop>
//! </CS:calendarserver-principal-search>
//! ```
//!
//! Every token must match the principal (in its name, display name or stored addresses); `context` is `attendee`
//! (people, groups and resources: the default), `user`, `group`, `location` or `resource`, and the optional `type` is
//! a calendar user type (`INDIVIDUAL`, `GROUP`, `RESOURCE`, `ROOM`). A request names at most
//! `limits.dav.max_search_terms` tokens.

use axum::response::Response;
use davhaven_app::services::{
    MAX_SEARCH_HITS, MIN_SEARCH_CHARS, NS_CALDAV, NS_CALENDARSERVER, NS_DAV, PrincipalSearch, PrincipalSearchResult,
};
use davhaven_domain::{DavLimits, PrincipalKind, ResourcePath, SearchCriterion, SearchField, TextMatch};
use davhaven_http::problem::{EdgeProblem, ProblemCode};

use crate::discovery::current_principal;
use crate::methods::collaboration::{visible, xml_document, xml_response};
use crate::methods::{Call, minimal_requested, multistatus_response};
use crate::props::{Env, Subject, propstats};
use crate::reports::prefixes_for;
use crate::xml::Element;
use crate::xml::requests::{PropRequest, bad_request, prop_request};
use crate::xml::write::{Multistatus, escape_text};

/// The property of a principal that a DAV property names, if a search can look into it.
fn searchable(namespace: &str, local: &str) -> Option<SearchField> {
    match (namespace, local) {
        (NS_DAV, "displayname") => Some(SearchField::DisplayName),
        (NS_CALDAV, "calendar-user-address-set") => Some(SearchField::Address),
        (NS_CALENDARSERVER, "email-address-set") => Some(SearchField::Email),
        _ => None,
    }
}

/// A `DAV:principal-property-search` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertySearch {
    /// The `property-search` elements that name at least one searchable property, in document order.
    pub criteria: Vec<SearchCriterion>,
    /// How many `property-search` elements name none: no principal satisfies one of them.
    pub unsearchable: usize,
    /// `test="anyof"`: one satisfied criterion is enough; otherwise every one must be.
    pub any: bool,
    /// The properties to return.
    pub select: PropRequest,
}

/// A `CS:calendarserver-principal-search` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSearch {
    /// The search tokens: every one must match.
    pub tokens: Vec<String>,
    /// The kinds of principal to return, from `context` and `type`.
    pub kinds: Vec<PrincipalKind>,
    /// The most principals to return (`CS:nresults`, at most [`MAX_SEARCH_HITS`]).
    pub limit: u32,
    /// The properties to return.
    pub select: PropRequest,
}

/// The kinds of principal a search may find: people, groups and resources.
const FINDABLE: [PrincipalKind; 3] = [PrincipalKind::User, PrincipalKind::Group, PrincipalKind::Resource];

/// The kinds of principal `context` and `type` of a `CS:calendarserver-principal-search` ask for.
fn kinds_for(context: Option<&str>, cutype: Option<&str>) -> Vec<PrincipalKind> {
    let by_context: &[PrincipalKind] = match context.map(str::to_ascii_lowercase).as_deref() {
        None | Some("attendee") => &FINDABLE,
        Some("user") => &[PrincipalKind::User],
        Some("group") => &[PrincipalKind::Group],
        Some("location" | "resource") => &[PrincipalKind::Resource],
        Some(_) => &[],
    };
    let by_type = match cutype.map(str::to_ascii_uppercase).as_deref() {
        Some("INDIVIDUAL") => Some(PrincipalKind::User),
        Some("GROUP") => Some(PrincipalKind::Group),
        Some("RESOURCE" | "ROOM") => Some(PrincipalKind::Resource),
        _ => None,
    };
    by_context
        .iter()
        .copied()
        .filter(|kind| by_type.is_none_or(|wanted| wanted == *kind))
        .collect()
}

/// The most terms (`property-search` elements or tokens) a request may name.
fn most_terms(limits: &DavLimits) -> usize {
    usize::try_from(limits.max_search_terms).unwrap_or(usize::MAX)
}

/// Reads a `DAV:principal-property-search` document.
///
/// # Errors
///
/// 400 for a `test` other than `allof` and `anyof`, a `match-type` other than `contains`, `starts-with` and
/// `equals`, a `property-search` without `D:prop` or `D:match`, no `property-search` at all, more than
/// `max_search_terms` of them, and a malformed `D:prop` selection.
pub fn parse_property_search(root: &Element, limits: &DavLimits) -> Result<PropertySearch, EdgeProblem> {
    let any = match root.attribute("test") {
        None | Some("allof") => false,
        Some("anyof") => true,
        Some(_) => return Err(bad_request("The test of a principal search is allof or anyof.")),
    };
    let mut criteria = Vec::new();
    let mut unsearchable = 0;
    let mut terms = 0;
    for search in root.children_named(NS_DAV, "property-search") {
        terms += 1;
        if terms > most_terms(limits) {
            return Err(bad_request(
                "A principal search names too many property-search elements.",
            ));
        }
        let prop = search
            .child(NS_DAV, "prop")
            .ok_or_else(|| bad_request("A property-search names the properties to search in D:prop."))?;
        let needle = search
            .child(NS_DAV, "match")
            .ok_or_else(|| bad_request("A property-search names the text to look for in D:match."))?;
        let matching = match needle.attribute("match-type") {
            None | Some("contains") => TextMatch::Contains,
            Some("starts-with") => TextMatch::StartsWith,
            Some("equals") => TextMatch::Equals,
            Some(_) => return Err(bad_request("The match-type is contains, starts-with or equals.")),
        };
        let fields: Vec<SearchField> = prop
            .elements()
            .filter_map(|property| searchable(property.namespace.as_str(), &property.local))
            .collect();
        if fields.is_empty() {
            unsearchable += 1;
        } else {
            criteria.push(SearchCriterion::new(needle.text().trim(), fields, matching));
        }
    }
    if terms == 0 {
        return Err(bad_request("A principal search needs at least one property-search."));
    }
    Ok(PropertySearch {
        criteria,
        unsearchable,
        any,
        select: prop_request(root)?,
    })
}

/// Reads a `CS:calendarserver-principal-search` document.
///
/// # Errors
///
/// 400 for no search token, more than `max_search_terms`, a `CS:nresults` that is no number and a malformed `D:prop`
/// selection.
pub fn parse_token_search(root: &Element, limits: &DavLimits) -> Result<TokenSearch, EdgeProblem> {
    let tokens: Vec<String> = root
        .children_named(NS_CALENDARSERVER, "search-token")
        .map(|token| token.text().trim().to_owned())
        .filter(|token| !token.is_empty())
        .collect();
    if tokens.is_empty() {
        return Err(bad_request("A principal search needs at least one CS:search-token."));
    }
    if tokens.len() > most_terms(limits) {
        return Err(bad_request("A principal search names too many search tokens."));
    }
    let limit = match root
        .child(NS_CALENDARSERVER, "limit")
        .and_then(|limit| limit.child(NS_CALENDARSERVER, "nresults"))
    {
        Some(count) => count
            .text()
            .trim()
            .parse::<u32>()
            .map_err(|_| bad_request("CS:nresults is a number."))?
            .clamp(1, MAX_SEARCH_HITS),
        None => MAX_SEARCH_HITS,
    };
    Ok(TokenSearch {
        tokens,
        kinds: kinds_for(root.attribute("context"), root.attribute("type")),
        limit,
        select: prop_request(root)?,
    })
}

/// The search a `DAV:principal-property-search` comes to, or `None` when no principal can satisfy it.
fn property_query(request: &PropertySearch) -> Option<PrincipalSearch> {
    let mut criteria = request.criteria.clone();
    if request.any {
        // A `property-search` that cannot match adds nothing to a union: one that names no searchable property
        // (they are not in `criteria`) or whose text is too short to be looked up.
        criteria.retain(|criterion| criterion.text.trim().chars().count() >= MIN_SEARCH_CHARS);
        if criteria.is_empty() {
            return None;
        }
    } else if request.unsearchable > 0 {
        // Every element has to be satisfied, and one that names nothing searchable never is.
        return None;
    }
    Some(
        PrincipalSearch::default()
            .limited(MAX_SEARCH_HITS)
            .matching(criteria, request.any),
    )
}

/// The search a `CS:calendarserver-principal-search` comes to, or `None` when no principal can satisfy it.
fn token_query(request: &TokenSearch) -> Option<PrincipalSearch> {
    // Nobody is of no kind.
    if request.kinds.is_empty() {
        return None;
    }
    let criteria = request.tokens.iter().map(SearchCriterion::contains).collect();
    Some(
        PrincipalSearch::default()
            .limited(request.limit)
            .of_kinds(request.kinds.clone())
            .matching(criteria, false),
    )
}

/// The multistatus of the principals a search found, ordered by href; a search the limit cut ends with the 507 entry.
async fn answer(call: &Call<'_>, select: &PropRequest, found: PrincipalSearchResult) -> Result<Response, EdgeProblem> {
    let minimal = minimal_requested(call.headers());
    let current = current_principal(call, select).await?;
    let prefixes = prefixes_for(call, select);
    let env = Env {
        services: call.services(),
        current: current.as_ref(),
        prefixes: &prefixes,
    };
    let mut hits: Vec<(String, _)> = found.hits.into_iter().map(|hit| (hit.path.format(), hit)).collect();
    hits.sort_by(|a, b| a.0.cmp(&b.0));
    let mut multistatus = Multistatus::with_prefixes(&prefixes);
    for (href, hit) in hits {
        multistatus.response(&href, &propstats(&env, &Subject::SearchHit(hit), select, minimal));
    }
    if found.truncated {
        call.truncated(&mut multistatus);
    }
    Ok(multistatus_response(multistatus.finish(), minimal))
}

/// The properties a search can look into, with the descriptions a client may show (RFC 3744 section 9.5).
const SEARCHABLE: [(&str, &str, &str); 3] = [
    (NS_DAV, "displayname", "Display name"),
    (NS_CALDAV, "calendar-user-address-set", "Calendar user addresses"),
    (NS_CALENDARSERVER, "email-address-set", "E-mail addresses"),
];

/// The `DAV:principal-search-property-set` document: the properties `principal-property-search` can match.
pub fn search_property_set() -> String {
    xml_document(NS_DAV, "principal-search-property-set", |writer| {
        for (namespace, local, description) in SEARCHABLE {
            writer.start(NS_DAV, "principal-search-property");
            writer.start(NS_DAV, "prop");
            writer.empty(namespace, local);
            writer.end(NS_DAV, "prop");
            writer.raw(&format!(
                "<D:description xml:lang=\"en\">{}</D:description>",
                escape_text(description)
            ));
            writer.end(NS_DAV, "principal-search-property");
        }
    })
}

/// Serves the search reports (`root` is the request document).
pub(crate) async fn search(call: &Call<'_>, root: &Element) -> Result<Response, EdgeProblem> {
    if !matches!(call.resource, ResourcePath::Root | ResourcePath::Principal { .. }) {
        return Err(EdgeProblem::new(ProblemCode::UnsupportedReport));
    }
    // A principal URL must name a principal the caller can see, whatever the body says.
    visible(call).await?;
    if root.is(NS_DAV, "principal-search-property-set") {
        return Ok(xml_response(search_property_set()));
    }
    let limits = &call.limits().dav;
    let (select, query) = if root.is(NS_DAV, "principal-property-search") {
        let request = parse_property_search(root, limits)?;
        let query = property_query(&request);
        (request.select, query)
    } else {
        let request = parse_token_search(root, limits)?;
        let query = token_query(&request);
        (request.select, query)
    };
    // A search that cannot find anybody, or that the application would refuse as too short, is an empty answer.
    let found = match query {
        Some(query) if query.is_askable() => call.services().principals.find_principals(call.ctx, query).await?,
        _ => PrincipalSearchResult::default(),
    };
    answer(call, &select, found).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::fixture;
    use crate::xml::parse;

    fn read(xml: &str) -> Element {
        parse(xml.as_bytes(), &DavLimits::default()).unwrap()
    }

    const HEAD: &str =
        r#"xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CS="http://calendarserver.org/ns/""#;

    fn criterion(text: &str, fields: &[SearchField], matching: TextMatch) -> SearchCriterion {
        SearchCriterion::new(text, fields.to_vec(), matching)
    }

    #[test]
    fn a_property_search_reads_its_criteria_test_and_selection() {
        let search = parse_property_search(
            &read(&format!(
                r#"<D:principal-property-search {HEAD} test="anyof">
                 <D:property-search><D:prop><D:displayname/><CS:first-name/></D:prop><D:match> Ben </D:match></D:property-search>
                 <D:property-search>
                   <D:prop><C:calendar-user-address-set/><CS:email-address-set/></D:prop>
                   <D:match match-type="starts-with">ben@</D:match>
                 </D:property-search>
                 <D:property-search><D:prop><CS:first-name/></D:prop><D:match>ben</D:match></D:property-search>
                 <D:prop><D:displayname/></D:prop>
               </D:principal-property-search>"#
            )),
            &DavLimits::default(),
        )
        .unwrap();
        assert!(search.any);
        assert_eq!(
            search.criteria,
            vec![
                criterion("Ben", &[SearchField::DisplayName], TextMatch::Contains),
                criterion(
                    "ben@",
                    &[SearchField::Address, SearchField::Email],
                    TextMatch::StartsWith
                ),
            ]
        );
        assert_eq!(
            search.unsearchable, 1,
            "the one that names no searchable property is counted"
        );
        assert_eq!(search.select.names().len(), 1);
        let all = parse_property_search(
            &read(&format!(
                r#"<D:principal-property-search {HEAD}>
                 <D:property-search><D:prop><D:displayname/></D:prop><D:match match-type="equals">x</D:match></D:property-search>
               </D:principal-property-search>"#
            )),
            &DavLimits::default(),
        )
        .unwrap();
        assert!(!all.any, "allof is the default");
        assert_eq!(all.criteria[0].matching, TextMatch::Equals);
        assert!(
            matches!(all.select, PropRequest::AllProp(_)),
            "no selection asks for the default properties"
        );
    }

    #[test]
    fn property_searches_that_search_nothing_are_refused() {
        let wrap = |attributes: &str, inner: &str| {
            format!("<D:principal-property-search {HEAD}{attributes}>{inner}</D:principal-property-search>")
        };
        let one = |prop: &str, needle: &str| format!("<D:property-search>{prop}{needle}</D:property-search>");
        let limits = DavLimits::default();
        let most = usize::try_from(limits.max_search_terms).unwrap();
        let terms = |count: usize| {
            (0..count)
                .map(|n| {
                    one(
                        "<D:prop><D:displayname/></D:prop>",
                        &format!("<D:match>name{n}</D:match>"),
                    )
                })
                .collect::<String>()
        };
        let bad = [
            wrap("", ""),
            wrap(
                " test=\"sometimes\"",
                &one("<D:prop><D:displayname/></D:prop>", "<D:match>ben</D:match>"),
            ),
            wrap("", &one("", "<D:match>ben</D:match>")),
            wrap("", &one("<D:prop><D:displayname/></D:prop>", "")),
            wrap(
                "",
                &one(
                    "<D:prop><D:displayname/></D:prop>",
                    "<D:match match-type=\"regex\">b.n</D:match>",
                ),
            ),
            wrap("", &terms(most + 1)),
            r#"<D:principal-search-property-set xmlns:D="DAV:"/>"#.to_owned(),
        ];
        for xml in bad {
            assert!(parse_property_search(&read(&xml), &limits).is_err(), "{xml}");
        }
        assert!(parse_property_search(&read(&wrap("", &terms(most))), &limits).is_ok());
        // The limit is the one that is configured.
        let tight = DavLimits {
            max_search_terms: 2,
            ..DavLimits::default()
        };
        assert!(parse_property_search(&read(&wrap("", &terms(2))), &tight).is_ok());
        assert!(parse_property_search(&read(&wrap("", &terms(3))), &tight).is_err());
    }

    #[test]
    fn a_token_search_reads_tokens_limit_and_kinds() {
        let limits = DavLimits::default();
        let search = parse_token_search(
            &read(&format!(
                r#"<CS:calendarserver-principal-search {HEAD} context="attendee">
                 <CS:search-token> ben </CS:search-token><CS:search-token>baker</CS:search-token><CS:search-token> </CS:search-token>
                 <CS:limit><CS:nresults>20</CS:nresults></CS:limit>
                 <D:prop><D:displayname/><C:calendar-user-address-set/></D:prop>
               </CS:calendarserver-principal-search>"#
            )),
            &limits,
        )
        .unwrap();
        assert_eq!(search.tokens, ["ben", "baker"]);
        assert_eq!(search.limit, 20);
        assert_eq!(search.kinds, FINDABLE);
        assert_eq!(search.select.names().len(), 2);
        let capped = parse_token_search(
            &read(&format!(
                r"<CS:calendarserver-principal-search {HEAD}><CS:search-token>ben</CS:search-token>
                 <CS:limit><CS:nresults>5000</CS:nresults></CS:limit></CS:calendarserver-principal-search>"
            )),
            &limits,
        )
        .unwrap();
        assert_eq!(
            capped.limit, MAX_SEARCH_HITS,
            "a client cannot ask for more than the limit"
        );
        let bare = parse_token_search(
            &read(&format!(
                r"<CS:calendarserver-principal-search {HEAD}><CS:search-token>ben</CS:search-token></CS:calendarserver-principal-search>"
            )),
            &limits,
        )
        .unwrap();
        assert_eq!(bare.limit, MAX_SEARCH_HITS);
    }

    #[test]
    fn token_searches_that_search_nothing_are_refused() {
        let wrap = |inner: &str| {
            format!("<CS:calendarserver-principal-search {HEAD}>{inner}</CS:calendarserver-principal-search>")
        };
        let tokens = |count: usize| crate::xml::repeated(count, |n| format!("<CS:search-token>t{n}</CS:search-token>"));
        let limits = DavLimits::default();
        let most = usize::try_from(limits.max_search_terms).unwrap();
        for xml in [
            wrap(""),
            wrap("<CS:search-token>   </CS:search-token>"),
            wrap(&format!(
                "{}<CS:limit><CS:nresults>many</CS:nresults></CS:limit>",
                tokens(1)
            )),
            wrap(&format!(
                "{}<CS:limit><CS:nresults>-1</CS:nresults></CS:limit>",
                tokens(1)
            )),
            wrap(&tokens(most + 1)),
        ] {
            assert!(parse_token_search(&read(&xml), &limits).is_err(), "{xml}");
        }
        assert!(parse_token_search(&read(&wrap(&tokens(most))), &limits).is_ok());
        let tight = DavLimits {
            max_search_terms: 1,
            ..DavLimits::default()
        };
        assert!(parse_token_search(&read(&wrap(&tokens(2))), &tight).is_err());
    }

    #[test]
    fn context_and_type_choose_the_kinds_of_principal() {
        use PrincipalKind::{Group, Resource, User};
        let cases: [(Option<&str>, Option<&str>, Vec<PrincipalKind>); 11] = [
            (None, None, vec![User, Group, Resource]),
            (Some("attendee"), None, vec![User, Group, Resource]),
            (Some("ATTENDEE"), None, vec![User, Group, Resource]),
            (Some("user"), None, vec![User]),
            (Some("group"), None, vec![Group]),
            (Some("location"), None, vec![Resource]),
            (Some("resource"), None, vec![Resource]),
            (Some("nonsense"), None, vec![]),
            (None, Some("INDIVIDUAL"), vec![User]),
            (Some("attendee"), Some("room"), vec![Resource]),
            (Some("user"), Some("GROUP"), vec![]),
        ];
        for (context, cutype, expected) in cases {
            assert_eq!(kinds_for(context, cutype), expected, "{context:?} {cutype:?}");
        }
        assert_eq!(
            kinds_for(None, Some("UNKNOWN")),
            FINDABLE,
            "an unknown type does not narrow the search"
        );
    }

    #[test]
    fn a_token_search_is_one_search_with_every_token_as_a_condition() {
        let tokens = |texts: &[&str], context: Option<&str>, limit: u32| TokenSearch {
            tokens: texts.iter().map(|text| (*text).to_owned()).collect(),
            kinds: kinds_for(context, None),
            limit,
            select: PropRequest::PropName,
        };
        let query = token_query(&tokens(&["anna", "b"], None, 20)).unwrap();
        assert_eq!(
            query.criteria,
            vec![SearchCriterion::contains("anna"), SearchCriterion::contains("b")],
            "the short token is a condition of the same search, not a second one"
        );
        assert!(!query.any_of);
        assert_eq!(query.limit, Some(20));
        assert_eq!(query.kinds, FINDABLE);
        assert_eq!(query.query, "");
        assert!(query.is_askable());
        assert!(
            !token_query(&tokens(&["a", "b"], None, 20)).unwrap().is_askable(),
            "no token is long enough: the application would refuse it"
        );
        assert!(
            token_query(&tokens(&["anna"], Some("nonsense"), 20)).is_none(),
            "nobody is of no kind"
        );
        assert_eq!(
            token_query(&tokens(&["room"], Some("location"), 5)).unwrap().kinds,
            [PrincipalKind::Resource]
        );
    }

    #[test]
    fn a_property_search_is_one_search_with_the_test_it_names() {
        let anna = criterion("anna", &[SearchField::DisplayName], TextMatch::Contains);
        let short = criterion("b", &[SearchField::Address], TextMatch::StartsWith);
        let request = |criteria: Vec<SearchCriterion>, unsearchable: usize, any: bool| PropertySearch {
            criteria,
            unsearchable,
            any,
            select: PropRequest::PropName,
        };
        let all = property_query(&request(vec![anna.clone(), short.clone()], 0, false)).unwrap();
        assert_eq!(all.criteria, vec![anna.clone(), short.clone()]);
        assert!(!all.any_of);
        assert_eq!(all.limit, Some(MAX_SEARCH_HITS));
        assert!(
            all.is_askable(),
            "with every element required a short text is one more condition, next to a long one"
        );
        assert!(
            property_query(&request(vec![anna.clone()], 1, false)).is_none(),
            "an element that names nothing searchable is never satisfied"
        );
        let either = property_query(&request(vec![anna.clone(), short], 1, true)).unwrap();
        assert!(either.any_of);
        assert_eq!(
            either.criteria,
            vec![anna],
            "in a union what cannot match adds nothing: the short text and the element that names nothing"
        );
        assert!(either.is_askable());
        assert!(
            property_query(&request(
                vec![criterion("b", &[SearchField::Email], TextMatch::Equals)],
                0,
                true
            ))
            .is_none(),
            "nothing left to ask for"
        );
        assert!(property_query(&request(Vec::new(), 2, true)).is_none());
    }

    #[test]
    fn the_searchable_properties_are_listed_with_descriptions() {
        let document = search_property_set();
        let root = read(&document);
        assert!(root.is(NS_DAV, "principal-search-property-set"));
        let listed: Vec<(String, String, String)> = root
            .children_named(NS_DAV, "principal-search-property")
            .map(|entry| {
                let prop = entry.child(NS_DAV, "prop").unwrap().elements().next().unwrap();
                (
                    prop.namespace.to_string(),
                    prop.local.clone(),
                    entry.child(NS_DAV, "description").unwrap().text(),
                )
            })
            .collect();
        assert_eq!(listed.len(), SEARCHABLE.len());
        for ((namespace, local, description), (expected_namespace, expected_local, expected)) in
            listed.iter().zip(SEARCHABLE)
        {
            assert_eq!(
                (namespace.as_str(), local.as_str(), description.as_str()),
                (expected_namespace, expected_local, expected)
            );
            assert!(searchable(namespace, local).is_some(), "{local} is searchable");
        }
        assert!(document.contains("xml:lang=\"en\""));
    }

    #[test]
    fn the_attendee_search_of_apple_calendar_is_read() {
        let search =
            parse_token_search(&read(&fixture("principal-search-attendee.xml")), &DavLimits::default()).unwrap();
        assert_eq!(search.tokens, ["baker"]);
        assert_eq!(search.limit, 20);
        assert_eq!(search.kinds, FINDABLE);
        let names: Vec<&str> = search.select.names().iter().map(|name| name.local.as_str()).collect();
        assert_eq!(
            names,
            [
                "displayname",
                "calendar-user-address-set",
                "calendar-user-type",
                "email-address-set",
                "first-name",
                "last-name",
                "record-type",
                "calendar-home-set"
            ]
        );
    }

    #[test]
    fn the_property_search_of_other_clients_is_read() {
        let search = parse_property_search(
            &read(&fixture("principal-property-search-anyof.xml")),
            &DavLimits::default(),
        )
        .unwrap();
        assert!(search.any);
        assert_eq!(search.criteria.len(), 2);
        assert_eq!(search.criteria[0].fields, [SearchField::DisplayName]);
        assert_eq!(search.criteria[0].matching, TextMatch::Contains);
        assert_eq!(search.criteria[1].fields, [SearchField::Email]);
        assert_eq!(search.criteria[1].matching, TextMatch::StartsWith);
        assert_eq!(search.select.names().len(), 3);
        let property_set = read(&fixture("principal-search-property-set.xml"));
        assert!(property_set.is(NS_DAV, "principal-search-property-set"));
    }
}
