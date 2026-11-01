//! The permission matrix as a document.
//!
//! [`permission_matrix`] renders `docs/permission-matrix.md` from the expectations file: the status policy, the
//! actors, the calendars, the operations, the effective access of every actor on every calendar and, for every
//! surface and calendar, the expected answer of every operation for every actor. `cargo xtask matrix` writes the
//! document (through `davhaven-conformance matrix-report`) and `cargo xtask matrix --check` fails when the committed
//! file differs, so the document a reviewer reads is the oracle the harness runs, not a copy that can drift.
//!
//! The text is a pure function of the expectations file: no dates, no ordering that depends on a map, the same bytes
//! on every machine.

use core::fmt::{self, Write as _};

use davhaven_fixtures::{ActorRole, CalendarRole};

use crate::matrix::{
    Case, CredentialExpectation, CredentialState, CredentialType, Expectation, Expectations, Level, MatrixError,
    Operation, Source, Surface, Target, TokenClass,
};
use crate::permissions::admin;

/// The one-letter code of an expectation in the tables.
const fn code(expectation: Expectation) -> &'static str {
    match expectation {
        Expectation::Allow => "A",
        Expectation::Unauthenticated => "U",
        Expectation::Hidden => "H",
        Expectation::Forbidden => "F",
        Expectation::PreconditionFailed => "P",
    }
}

/// What an actor is, in a sentence.
const fn describe_actor(actor: ActorRole) -> &'static str {
    match actor {
        ActorRole::Owner => "Owns the personal, the shared and the mirror calendar.",
        ActorRole::GroupMember => {
            "Member of the group `team` (owner of the group calendar) and, through it, a reader of the managed calendar."
        }
        ActorRole::ShareeRead => "Accepted a read share of the shared calendar.",
        ActorRole::ShareeReadWrite => "Accepted a read-write share of the shared calendar.",
        ActorRole::GranteeViaGroup => "Reads the shared calendar through a grant to the group `viewers`.",
        ActorRole::PendingSharee => "Was invited to the shared calendar and has not answered.",
        ActorRole::DeclinedSharee => "Declined the invitation to the shared calendar.",
        ActorRole::OtherUser => "A user of the tenant without access to anything of the others.",
        ActorRole::OtherTenantUser => "A user of the other tenant.",
        ActorRole::SuspendedUser => "A suspended user: every login is refused.",
        ActorRole::ServicePrincipal => "A service principal; owns the managed calendar and has no password.",
        ActorRole::ServiceGrantee => {
            "A service principal that is granted the group calendar (read-write) and the managed calendar (read); works through the API and MCP."
        }
        ActorRole::ServiceWriter => {
            "A service principal that is granted the managed calendar for reading and writing: the API and MCP write where DAV is capped at read."
        }
        ActorRole::TenantToken => "An administrator token of the tenant with every tenant scope.",
        ActorRole::OtherTenantToken => "An administrator token of the other tenant.",
        ActorRole::SystemToken => "A system token (tenant administration of the installation).",
        ActorRole::Anonymous => "No credential at all.",
    }
}

/// What a calendar role is, in a sentence.
const fn describe_calendar(calendar: CalendarRole) -> &'static str {
    match calendar {
        CalendarRole::Personal => "The personal calendar of the owner.",
        CalendarRole::Group => "The calendar of the group `team`.",
        CalendarRole::Managed => "The managed calendar of the service principal, read-only for principals on DAV.",
        CalendarRole::Shared => "A user calendar of the owner that is shared with several sharees.",
        CalendarRole::Mirror => "A mirror of an external calendar, read-only on every principal surface.",
    }
}

/// What an operation is, in a sentence.
const fn describe_operation(operation: Operation) -> &'static str {
    match operation {
        Operation::ReadCollection => "Read the properties of a calendar.",
        Operation::ListObjects => "List or query the objects of a calendar, or its changes.",
        Operation::ReadObject => "Read one object.",
        Operation::FreeBusyQuery => "Ask for the busy time of a calendar.",
        Operation::CreateObject => "Create an object.",
        Operation::UpdateObject => "Replace or change an object.",
        Operation::DeleteObject => "Delete an object.",
        Operation::BatchUpsert => "Create or replace several objects with one request.",
        Operation::MoveObjectFrom => "MOVE: the source calendar.",
        Operation::MoveObjectTo => "MOVE: the target calendar.",
        Operation::CopyObjectFrom => "COPY: the source calendar.",
        Operation::CopyObjectTo => "COPY: the target calendar.",
        Operation::RespondToInvitation => "Answer an invitation on behalf of the caller.",
        Operation::PropPatchBinding => {
            "Change the properties that belong to the caller's own binding (colour, order, name)."
        }
        Operation::UpdateCalendar => "Change the settings that belong to the calendar for everyone.",
        Operation::RenameCalendar => "Rename the calendar itself.",
        Operation::CreateCalendar => "Create a calendar in the home of the owner.",
        Operation::DeleteCalendar => "Delete the calendar for everyone.",
        Operation::RemoveBinding => {
            "Delete a bound calendar without being its owner: the binding goes away, unless a required grant reaches the caller, which is refused."
        }
        Operation::ShareCalendar => "Share the calendar (CalendarServer sharing).",
        Operation::ReplyInvite => "Accept or decline a pending invitation to a shared calendar.",
        Operation::ListGrants => "List the grants of a calendar.",
        Operation::PutGrant => "Create or replace a grant.",
        Operation::DeleteGrant => "Remove a grant.",
        Operation::ReadInbox => "Read the scheduling inbox of the home.",
        Operation::DeleteInboxItem => "Delete an item of the scheduling inbox.",
        Operation::PostOutbox => "POST to the scheduling outbox (free-busy requests).",
        Operation::ReadNotifications => "Read the notification collection of the home.",
        Operation::DeleteNotification => "Delete a notification.",
        Operation::ReadHome => "List the home of the owner of a calendar: its bindings, and their synchronization.",
        Operation::ReadPrincipal => {
            "Read the principal resource of the owner of a calendar (addresses, URL of the home)."
        }
        Operation::ReadFeed => "Render the subscription feed of a calendar.",
        Operation::RsvpView => "Open an RSVP page.",
        Operation::RsvpAnswer => "Answer on an RSVP page.",
    }
}

const fn describe_surface(surface: Surface) -> &'static str {
    match surface {
        Surface::Dav => "WebDAV and CalDAV, HTTP Basic with an app password",
        Surface::Api => "management API under `/api/v1`, bearer tokens",
        Surface::Mcp => "MCP server, bearer tokens of principals",
        Surface::Feed => "subscription feeds, feed tokens in the URL",
        Surface::Rsvp => "RSVP pages, RSVP tokens in the URL",
    }
}

fn put(out: &mut String, args: fmt::Arguments<'_>) {
    let _ = out.write_fmt(args);
    out.push('\n');
}

fn names<T: fmt::Display>(items: &[T], all: usize) -> String {
    if items.len() == all {
        "all".to_owned()
    } else {
        items.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
    }
}

fn cell(expectations: &Expectations, case: &Case) -> Result<String, MatrixError> {
    let resolution = expectations.resolve(case)?;
    let mut text = code(resolution.expectation).to_owned();
    if matches!(resolution.source, Source::Exception(_)) {
        text.push('*');
    }
    Ok(text)
}

fn table_header(out: &mut String, first: &str, columns: &[String]) {
    put(out, format_args!("| {first} | {} |", columns.join(" | ")));
    put(
        out,
        format_args!(
            "| --- | {} |",
            columns.iter().map(|_| "---").collect::<Vec<_>>().join(" | ")
        ),
    );
}

fn status_section(out: &mut String, expectations: &Expectations) {
    put(out, format_args!("## Status policy"));
    put(out, format_args!(""));
    put(
        out,
        format_args!("| Code | Expectation | HTTP | Challenge | DAV precondition | Problem code | Meaning |"),
    );
    put(out, format_args!("| --- | --- | --- | --- | --- | --- | --- |"));
    for expectation in [
        Expectation::Allow,
        Expectation::Unauthenticated,
        Expectation::Hidden,
        Expectation::Forbidden,
        Expectation::PreconditionFailed,
    ] {
        if let Some(rule) = expectations.status().rule(expectation) {
            put(
                out,
                format_args!(
                    "| `{}` | {} | {} | {} | {} | {} | {} |",
                    code(expectation),
                    expectation,
                    rule.http,
                    if rule.challenge { "`WWW-Authenticate`" } else { "" },
                    rule.dav_precondition
                        .as_deref()
                        .map_or_else(String::new, |p| format!("`{p}`")),
                    rule.problem_code
                        .as_deref()
                        .map_or_else(String::new, |p| format!("`{p}`")),
                    rule.note.as_deref().unwrap_or(""),
                ),
            );
        }
    }
    put(out, format_args!(""));
    put(
        out,
        format_args!(
            "A `*` after a code marks a case that an exception row of the expectations file decides; the default rules \
             (effective access against what the operation needs) decide all the others."
        ),
    );
    put(out, format_args!(""));
}

fn actors_section(out: &mut String) {
    put(out, format_args!("## Actors"));
    put(out, format_args!(""));
    put(out, format_args!("| Actor | Tenant | Principal | What |"));
    put(out, format_args!("| --- | --- | --- | --- |"));
    for actor in ActorRole::ALL {
        put(
            out,
            format_args!(
                "| `{actor}` | {} | {} | {} |",
                actor.tenant().unwrap_or("-"),
                actor
                    .principal_name()
                    .map_or_else(|| "-".to_owned(), |name| format!("`{name}`")),
                describe_actor(*actor)
            ),
        );
    }
    put(out, format_args!(""));
}

fn calendars_section(out: &mut String) {
    put(out, format_args!("## Calendars"));
    put(out, format_args!(""));
    put(out, format_args!("| Calendar | Owner | Slug | Kind | What |"));
    put(out, format_args!("| --- | --- | --- | --- | --- |"));
    for calendar in CalendarRole::ALL {
        put(
            out,
            format_args!(
                "| `{calendar}` | `{}` | `{}` | {:?} | {} |",
                calendar.owner(),
                calendar.slug(),
                calendar.kind(),
                describe_calendar(*calendar)
            ),
        );
    }
    put(out, format_args!(""));
}

fn operations_section(out: &mut String, expectations: &Expectations) {
    put(out, format_args!("## Operations"));
    put(out, format_args!(""));
    put(
        out,
        format_args!(
            "`Needs` is the effective access that the default rules require (`none` means every authenticated principal \
             of the tenant); `Target` says whether the operation addresses a calendar or the home of its owner. The \
             surface columns list the scope that a token needs on the API and on MCP."
        ),
    );
    put(out, format_args!(""));
    put(
        out,
        format_args!("| Operation | Needs | Target | DAV | API | MCP | Feed | RSVP | What |"),
    );
    put(
        out,
        format_args!("| --- | --- | --- | --- | --- | --- | --- | --- | --- |"),
    );
    for operation in Operation::ALL {
        let (needs, target) = expectations
            .need_of(*operation)
            .unwrap_or((Level::Nothing, Target::Calendar));
        let mut surfaces = Vec::new();
        for surface in Surface::ALL {
            let available = expectations.operations_on(*surface).contains(operation);
            surfaces.push(if available {
                match expectations.scope_of(*surface, *operation) {
                    Some(scope) => format!("`{scope}`"),
                    None => "yes".to_owned(),
                }
            } else {
                String::new()
            });
        }
        put(
            out,
            format_args!(
                "| `{operation}` | {needs} | {target} | {} | {} |",
                surfaces.join(" | "),
                describe_operation(*operation)
            ),
        );
    }
    put(out, format_args!(""));
}

fn access_section(out: &mut String, expectations: &Expectations) {
    put(out, format_args!("## Effective access"));
    put(out, format_args!(""));
    put(
        out,
        format_args!(
            "What each actor may do with each calendar before an operation is looked at: the access of the \
             actor, lowered by the caps of the surface. `none` means the calendar is invisible."
        ),
    );
    put(out, format_args!(""));
    for surface in [Surface::Dav, Surface::Api, Surface::Mcp] {
        put(out, format_args!("### {surface}"));
        put(out, format_args!(""));
        let columns: Vec<String> = CalendarRole::ALL
            .iter()
            .map(|calendar| format!("`{calendar}`"))
            .collect();
        table_header(out, "Actor", &columns);
        for actor in ActorRole::ALL {
            let levels: Vec<String> = CalendarRole::ALL
                .iter()
                .map(|calendar| expectations.level_of(*actor, *calendar, surface).to_string())
                .collect();
            put(out, format_args!("| `{actor}` | {} |", levels.join(" | ")));
        }
        put(out, format_args!(""));
    }
}

fn results_section(out: &mut String, expectations: &Expectations) -> Result<(), MatrixError> {
    put(out, format_args!("## Results"));
    put(out, format_args!(""));
    put(
        out,
        format_args!(
            "For every surface and calendar: the answer of every operation of the surface to every actor. For the \
             operations that address a home (`create_calendar`, the inbox, the outbox and the notifications) the \
             calendar column names the calendar whose owner's home is meant."
        ),
    );
    put(out, format_args!(""));
    let columns: Vec<String> = ActorRole::ALL.iter().map(|actor| format!("`{actor}`")).collect();
    for surface in Surface::ALL {
        let operations = expectations.operations_on(*surface);
        put(out, format_args!("### {surface}"));
        put(out, format_args!(""));
        put(out, format_args!("{}.", describe_surface(*surface)));
        put(out, format_args!(""));
        for calendar in CalendarRole::ALL {
            put(out, format_args!("#### {surface} / {calendar}"));
            put(out, format_args!(""));
            table_header(out, "Operation", &columns);
            for operation in &operations {
                let mut cells = Vec::with_capacity(ActorRole::ALL.len());
                for actor in ActorRole::ALL {
                    cells.push(cell(expectations, &Case::new(*actor, *calendar, *surface, *operation))?);
                }
                put(out, format_args!("| `{operation}` | {} |", cells.join(" | ")));
            }
            put(out, format_args!(""));
        }
    }
    Ok(())
}

fn scopes_section(out: &mut String, expectations: &Expectations) -> Result<(), MatrixError> {
    put(out, format_args!("## Token scopes"));
    put(out, format_args!(""));
    put(
        out,
        format_args!(
            "A tenant token that carries one scope is refused (`F`) for every operation that needs another one, and \
             allowed (`A`) for the operations of its own scope on the calendars it reaches. The table shows, per \
             operation, the scope that is needed and the answer for a token that carries only that scope, on the \
             personal calendar and on the group calendar."
        ),
    );
    put(out, format_args!(""));
    put(
        out,
        format_args!("| Surface | Operation | Scope | Personal | Group | Other scope |"),
    );
    put(out, format_args!("| --- | --- | --- | --- | --- | --- |"));
    for surface in [Surface::Api, Surface::Mcp] {
        for operation in expectations.operations_on(surface) {
            let Some(scope) = expectations.scope_of(surface, operation) else {
                continue;
            };
            let own = |calendar| {
                cell(
                    expectations,
                    &Case::new(ActorRole::TenantToken, calendar, surface, operation).with_scope(scope),
                )
            };
            let other = cell(
                expectations,
                &Case::new(ActorRole::TenantToken, CalendarRole::Group, surface, operation).with_scope("none:none"),
            )?;
            put(
                out,
                format_args!(
                    "| {surface} | `{operation}` | `{scope}` | {} | {} | {other} |",
                    own(CalendarRole::Personal)?,
                    own(CalendarRole::Group)?
                ),
            );
        }
    }
    put(out, format_args!(""));
    Ok(())
}

fn administration_section(out: &mut String, expectations: &Expectations) -> Result<(), MatrixError> {
    put(out, format_args!("## Administration operations"));
    put(out, format_args!(""));
    put(
        out,
        format_args!(
            "The operations of the management API that are not about one calendar. A token needs one of the scopes of \
             the row; principals never administer anything (a principal token is refused whatever its scopes); a tenant token \
             administers its tenant within its scopes and sees nothing of another tenant (`H`); a system token is allowed where \
             `system:tenants` is listed and refused everywhere else. The table shows what each actor gets for a tenant token that \
             carries every tenant scope; the token that carries exactly one of the scopes of a row is allowed, and the tokens \
             that carry only other scopes are refused (`F`), for every one of the {} scopes a tenant token can carry. An operation \
             that names an id is also asked for by the administrator of another tenant in its own tenant with the ids of the first, \
             and answers `H`. A `+` after the operation marks one of the operations of a service that is not offered yet (see \
             \"Pending operations\").",
            admin::tenant_scopes(expectations).len()
        ),
    );
    put(out, format_args!(""));
    let mut columns: Vec<String> = vec!["Scopes".to_owned()];
    columns.extend(ActorRole::ALL.iter().map(|actor| format!("`{actor}`")));
    table_header(out, "Operation", &columns);
    for operation in admin::OPERATIONS {
        let scopes = expectations
            .admin_scopes(operation.id)
            .map_or_else(String::new, |scopes| {
                scopes
                    .iter()
                    .map(|scope| format!("`{scope}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            });
        let mut cells = Vec::with_capacity(ActorRole::ALL.len());
        for actor in ActorRole::ALL {
            let case = admin::AdminCase::new(operation.id, *actor);
            cells.push(code(admin::expected(expectations, &case)?).to_owned());
        }
        let pending = if expectations.pending(operation.id).is_some() {
            " +"
        } else {
            ""
        };
        put(
            out,
            format_args!(
                "| `{} {}` ({}){pending} | {scopes} | {} |",
                operation.method,
                operation.path,
                operation.id,
                cells.join(" | ")
            ),
        );
    }
    put(out, format_args!(""));
    Ok(())
}

fn admin_rules_section(out: &mut String, expectations: &Expectations) {
    put(out, format_args!("## Rules of the administration operations"));
    put(out, format_args!(""));
    put(
        out,
        format_args!(
            "How the actors are treated (`[[admin_actor]]`) and the scopes each kind of API token may carry (`[[token_scopes]]`). \
             A token is decided by its scopes: allowed with one of the scopes of the operation, refused without."
        ),
    );
    put(out, format_args!(""));
    put(out, format_args!("| Actor | Rule | Why |"));
    put(out, format_args!("| --- | --- | --- |"));
    for actor in ActorRole::ALL {
        if let Some((rule, note)) = expectations.admin_rule(*actor) {
            put(
                out,
                format_args!("| `{actor}` | `{rule}` | {} |", note.unwrap_or_default()),
            );
        }
    }
    put(out, format_args!(""));
    put(out, format_args!("| Token | Scopes it may carry |"));
    put(out, format_args!("| --- | --- |"));
    for class in TokenClass::ALL {
        let scopes: Vec<String> = expectations
            .token_scopes(*class)
            .iter()
            .map(|scope| format!("`{scope}`"))
            .collect();
        put(out, format_args!("| {class} | {} |", scopes.join(", ")));
    }
    put(out, format_args!(""));
}

fn pending_section(out: &mut String, expectations: &Expectations) {
    put(out, format_args!("## Pending operations"));
    put(out, format_args!(""));
    let pending = expectations.pending_operations();
    if pending.is_empty() {
        put(
            out,
            format_args!("None: every operation of the management API is offered."),
        );
    } else {
        put(
            out,
            format_args!(
                "Operations of a service that is not offered yet. A caller that reaches the service is answered 501, the others are \
                 judged by the rules above; the harness checks the rows against what the server does today, so an operation that \
                 stops answering 501 makes its row stale."
            ),
        );
        put(out, format_args!(""));
        put(out, format_args!("| Operation | Answers | Why |"));
        put(out, format_args!("| --- | --- | --- |"));
        for operation in pending {
            if let Some(row) = expectations.pending(operation) {
                put(out, format_args!("| `{operation}` | {} | {} |", row.state, row.reason));
            }
        }
    }
    put(out, format_args!(""));
}

fn credentials_section(out: &mut String, expectations: &Expectations) {
    put(out, format_args!("## Credentials"));
    put(out, format_args!(""));
    put(
        out,
        format_args!(
            "Which surface takes which kind of credential (a credential is bound to its surface), and what a state does \
             to a credential that its surface takes: `A` it authenticates, `R` it is refused at the door (401 on DAV, the API and \
             MCP, the 404 of an unknown token on the pages), `-` the state does not exist for the kind. A credential that its \
             surface does not take is refused whatever its state."
        ),
    );
    put(out, format_args!(""));
    put(out, format_args!("| Surface | Takes |"));
    put(out, format_args!("| --- | --- |"));
    for surface in Surface::ALL {
        let kinds: Vec<String> = expectations
            .credentials_taken_by(*surface)
            .iter()
            .map(|kind| format!("`{kind}`"))
            .collect();
        put(out, format_args!("| {surface} | {} |", kinds.join(", ")));
    }
    put(out, format_args!(""));
    let columns: Vec<String> = CredentialType::ALL.iter().map(|kind| format!("`{kind}`")).collect();
    table_header(out, "State", &columns);
    for state in CredentialState::ALL {
        let cells: Vec<&str> = CredentialType::ALL
            .iter()
            .map(|kind| match expectations.credential_state_rule(*kind, *state) {
                Some((CredentialExpectation::Accepted, _)) => "A",
                Some((CredentialExpectation::Refused, _)) => "R",
                Some((CredentialExpectation::NotApplicable, _)) | None => "-",
            })
            .collect();
        put(out, format_args!("| `{state}` | {} |", cells.join(" | ")));
    }
    put(out, format_args!(""));
    let mut notes: Vec<String> = Vec::new();
    for state in CredentialState::ALL {
        for kind in CredentialType::ALL {
            if let Some((_, Some(note))) = expectations.credential_state_rule(*kind, *state) {
                notes.push(format!("`{state}` / `{kind}`: {note}"));
            }
        }
    }
    if !notes.is_empty() {
        put(out, format_args!("Why, where the file says:"));
        put(out, format_args!(""));
        for note in notes {
            put(out, format_args!("* {note}"));
        }
        put(out, format_args!(""));
    }
}

fn exceptions_section(out: &mut String, expectations: &Expectations) {
    put(out, format_args!("## Exception rows"));
    put(out, format_args!(""));
    put(
        out,
        format_args!(
            "The rows that override the default rules, in the order in which they are consulted (the first row that \
             matches a case decides it). A row that no case reaches is rejected by the harness."
        ),
    );
    put(out, format_args!(""));
    put(
        out,
        format_args!("| # | Actors | Calendars | Surfaces | Operations | Expectation | Details waived because |"),
    );
    put(out, format_args!("| --- | --- | --- | --- | --- | --- | --- |"));
    for (index, row) in expectations.exceptions().iter().enumerate() {
        put(
            out,
            format_args!(
                "| {} | {} | {} | {} | {} | {} | {} |",
                index + 1,
                names(&row.actors, ActorRole::ALL.len()),
                names(&row.calendars, CalendarRole::ALL.len()),
                names(&row.surfaces, Surface::ALL.len()),
                names(&row.operations, Operation::ALL.len()),
                row.expect,
                row.waive_details.as_deref().unwrap_or("")
            ),
        );
    }
    put(out, format_args!(""));
}

fn known_issues_section(out: &mut String, expectations: &Expectations) {
    put(out, format_args!("## Known deviations"));
    put(out, format_args!(""));
    let issues = expectations.known_issues();
    if issues.is_empty() {
        put(
            out,
            format_args!("None: the server answers every case as the rows above say."),
        );
    } else {
        put(
            out,
            format_args!(
                "Cases in which the server answers differently from the rows above, and what it answers. The harness runs \
                 them against the answer that is listed and fails when the server stops deviating."
            ),
        );
        put(out, format_args!(""));
        put(
            out,
            format_args!("| Actors | Calendars | Surfaces | Operations | Server answers | Why |"),
        );
        put(out, format_args!("| --- | --- | --- | --- | --- | --- |"));
        for issue in issues {
            put(
                out,
                format_args!(
                    "| {} | {} | {} | {} | {} | {} |",
                    names(&issue.actors, ActorRole::ALL.len()),
                    names(&issue.calendars, CalendarRole::ALL.len()),
                    names(&issue.surfaces, Surface::ALL.len()),
                    names(&issue.operations, Operation::ALL.len()),
                    issue.observed,
                    issue.reason
                ),
            );
        }
    }
    put(out, format_args!(""));
}

fn summary_section(out: &mut String, expectations: &Expectations) -> Result<(), MatrixError> {
    put(out, format_args!("## Summary"));
    put(out, format_args!(""));
    let mut counts = std::collections::BTreeMap::<(Surface, Expectation), usize>::new();
    let mut total = 0_usize;
    for surface in Surface::ALL {
        for operation in expectations.operations_on(*surface) {
            for calendar in CalendarRole::ALL {
                for actor in ActorRole::ALL {
                    let expectation = expectations.expected(&Case::new(*actor, *calendar, *surface, operation))?;
                    *counts.entry((*surface, expectation)).or_default() += 1;
                    total += 1;
                }
            }
        }
    }
    put(out, format_args!("| Surface | Cases | `A` | `U` | `H` | `F` | `P` |"));
    put(out, format_args!("| --- | --- | --- | --- | --- | --- | --- |"));
    for surface in Surface::ALL {
        let count = |expectation| counts.get(&(*surface, expectation)).copied().unwrap_or(0);
        let all: usize = [
            Expectation::Allow,
            Expectation::Unauthenticated,
            Expectation::Hidden,
            Expectation::Forbidden,
            Expectation::PreconditionFailed,
        ]
        .iter()
        .map(|expectation| count(*expectation))
        .sum();
        put(
            out,
            format_args!(
                "| {surface} | {all} | {} | {} | {} | {} | {} |",
                count(Expectation::Allow),
                count(Expectation::Unauthenticated),
                count(Expectation::Hidden),
                count(Expectation::Forbidden),
                count(Expectation::PreconditionFailed)
            ),
        );
    }
    put(out, format_args!(""));
    put(
        out,
        format_args!(
            "{total} cases (actor x calendar x operation of the surface), without the per-scope cases of the tokens that carry one \
             scope, and {} cases of the administration operations (operation x actor, x scope for tenant tokens, and the \
             administrator of another tenant with the ids of the first).",
            admin::cases(expectations).len()
        ),
    );
    Ok(())
}

/// Renders the permission matrix document for an expectations file.
///
/// # Errors
///
/// [`MatrixError`] when a case does not resolve (cannot happen for a file that passed
/// [`Expectations::parse`]).
pub fn permission_matrix(expectations: &Expectations) -> Result<String, MatrixError> {
    let mut out = String::new();
    put(&mut out, format_args!("# Permission matrix"));
    put(&mut out, format_args!(""));
    put(
        &mut out,
        format_args!(
            "<!-- Generated by `cargo xtask matrix` from `crates/testkit/matrix/expectations.toml`. Do not edit by hand. -->"
        ),
    );
    put(&mut out, format_args!(""));
    put(
        &mut out,
        format_args!(
            "This is the permission oracle of Davhaven in readable form: what every actor gets when it \
             does every operation on every kind of calendar through every surface, and when it calls every \
             administration operation of the management API. The permission matrix of the test suite sends each of \
             these cases to the real application, in process on the memory and PostgreSQL stores, and fails when an \
             answer differs from the table; it also checks that a refusal changes nothing (no sequence bump, no \
             outbox item, no event) and that its body does not leak what the caller may not see. The cases that must \
             change nothing run against a deployed instance as well (`davhaven-conformance run`). The oracle is \
             written by hand and reviewed against the authorization rules in the management API and protocol documentation; it is never computed from the authorization code it \
             checks."
        ),
    );
    put(&mut out, format_args!(""));
    status_section(&mut out, expectations);
    actors_section(&mut out);
    calendars_section(&mut out);
    operations_section(&mut out, expectations);
    access_section(&mut out, expectations);
    results_section(&mut out, expectations)?;
    scopes_section(&mut out, expectations)?;
    administration_section(&mut out, expectations)?;
    admin_rules_section(&mut out, expectations);
    pending_section(&mut out, expectations);
    credentials_section(&mut out, expectations);
    exceptions_section(&mut out, expectations);
    known_issues_section(&mut out, expectations);
    summary_section(&mut out, expectations)?;
    while out.ends_with("\n\n") {
        out.pop();
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> String {
        permission_matrix(&Expectations::bundled().unwrap()).unwrap()
    }

    #[test]
    fn the_document_is_deterministic() {
        assert_eq!(document(), document());
    }

    #[test]
    fn it_names_every_actor_calendar_operation_and_surface() {
        let text = document();
        for actor in ActorRole::ALL {
            assert!(text.contains(&format!("`{actor}`")), "{actor}");
        }
        for calendar in CalendarRole::ALL {
            assert!(text.contains(&format!("`{calendar}`")), "{calendar}");
        }
        for operation in Operation::ALL {
            assert!(text.contains(&format!("`{operation}`")), "{operation}");
        }
        for surface in Surface::ALL {
            assert!(text.contains(&format!("#### {surface} / personal")), "{surface}");
        }
    }

    #[test]
    fn a_table_row_says_what_the_oracle_says() {
        let expectations = Expectations::bundled().unwrap();
        let text = document();
        // The owner of the personal calendar reads an object on DAV: the first allowed cell of the row.
        let section = text.split("#### dav / personal").nth(1).unwrap();
        let row = section
            .lines()
            .find(|line| line.starts_with("| `read_object` |"))
            .unwrap();
        let cells: Vec<&str> = row.trim_matches('|').split('|').map(str::trim).skip(1).collect();
        assert_eq!(cells.len(), ActorRole::ALL.len());
        for (actor, cell) in ActorRole::ALL.iter().zip(&cells) {
            let expected = expectations
                .expected(&Case::new(
                    *actor,
                    CalendarRole::Personal,
                    Surface::Dav,
                    Operation::ReadObject,
                ))
                .unwrap();
            assert!(cell.starts_with(code(expected)), "{actor}: {cell}");
        }
        assert!(cells[0].starts_with('A'), "the owner may read");
    }

    #[test]
    fn the_document_has_no_trailing_blank_line_and_ends_with_a_newline_free_summary() {
        let text = document();
        assert!(!text.ends_with("\n\n"));
        assert!(text.contains("## Summary"));
        assert!(text.starts_with("# Permission matrix\n"));
    }
}
