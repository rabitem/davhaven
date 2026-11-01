//! The tools of the MCP server.
//!
//! The tools and their schemas are defined in `davhaven-wire` (`wire::mcp`): ten tools with stable names, input and
//! output structs, annotations and the scope each needs (PLAN 2.12). Names never change and changes are additive; a
//! breaking change is a new tool name. This module is the catalog (the tool by name, the scope a token needs to call
//! it, the operations it performs) and the dispatch from a call to its implementation:
//!
//! | Tool | Scope | Operation(s) | Services |
//! | --- | --- | --- | --- |
//! | `list_calendars` | `mcp:read` | `ReadCollection` | `PrincipalService::current`, `CalendarService::list_home` |
//! | `list_events`, `search_events` | `mcp:read` | `ListObjects` | `ObjectService::search_events` |
//! | `get_event` | `mcp:read` | `ReadObject` | `ObjectService::get_event` |
//! | `free_busy`, `find_free_slots` | `mcp:read` | `FreeBusyQuery` | `SchedulingService::free_busy`, `find_free_slots` |
//! | `create_event` | `mcp:write` | `CreateObject` | `ObjectService::create_event` |
//! | `update_event` | `mcp:write` | `UpdateObject` | `ObjectService::put_event` |
//! | `delete_event` | `mcp:write` | `DeleteObject` | `ObjectService::delete_event_if_present` |
//! | `respond_to_invitation` | `mcp:write` | `RespondToInvitation` | `SchedulingService::respond` |
//!
//! Every tool acts as the principal of the token through the same services as DAV and the management API, so
//! permissions (`domain::authz::decide` per operation), scheduling rules, audit records (`mcp.write`), domain events,
//! the busy-only form of what is private to others and the budgets are the services' and not re-implemented here. The
//! scope a tool needs is the one the domain table gives its operation ([`ToolKind::required_scope`]); the catalog of
//! `davhaven-wire` repeats it for clients, and a test ties the two together. What this layer adds is the shape of a
//! call ([`crate::input`]) and the wire form of the answer ([`crate::render`]).

mod read;
mod schedule;
mod write;

use davhaven_app::AppError;
use davhaven_domain::{Channel, Operation, Scope, ScopeRule};
use davhaven_wire::mcp::{TOOLS, ToolInfo};
use rmcp::model::JsonObject;
use serde::Serialize;
use serde_json::Value;

use crate::caller::Caller;
use crate::config::McpConfig;
use crate::input;

/// Every tool of the server, in catalog order.
pub const fn catalog() -> &'static [ToolInfo] {
    &TOOLS
}

/// The tools, as a type the dispatch matches exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    /// `list_calendars`.
    ListCalendars,
    /// `list_events`.
    ListEvents,
    /// `get_event`.
    GetEvent,
    /// `search_events`.
    SearchEvents,
    /// `free_busy`.
    FreeBusy,
    /// `find_free_slots`.
    FindFreeSlots,
    /// `create_event`.
    CreateEvent,
    /// `update_event`.
    UpdateEvent,
    /// `delete_event`.
    DeleteEvent,
    /// `respond_to_invitation`.
    RespondToInvitation,
}

impl ToolKind {
    /// Every tool, in catalog order.
    pub const ALL: [Self; 10] = [
        Self::ListCalendars,
        Self::ListEvents,
        Self::GetEvent,
        Self::SearchEvents,
        Self::FreeBusy,
        Self::FindFreeSlots,
        Self::CreateEvent,
        Self::UpdateEvent,
        Self::DeleteEvent,
        Self::RespondToInvitation,
    ];

    /// The stable tool name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ListCalendars => "list_calendars",
            Self::ListEvents => "list_events",
            Self::GetEvent => "get_event",
            Self::SearchEvents => "search_events",
            Self::FreeBusy => "free_busy",
            Self::FindFreeSlots => "find_free_slots",
            Self::CreateEvent => "create_event",
            Self::UpdateEvent => "update_event",
            Self::DeleteEvent => "delete_event",
            Self::RespondToInvitation => "respond_to_invitation",
        }
    }

    /// The tool with this name.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.name() == name)
    }

    /// The catalog entry of the tool: its description, annotations and the scope the catalog announces.
    pub const fn info(self) -> &'static ToolInfo {
        match self {
            Self::ListCalendars => &TOOLS[0],
            Self::ListEvents => &TOOLS[1],
            Self::GetEvent => &TOOLS[2],
            Self::SearchEvents => &TOOLS[3],
            Self::FreeBusy => &TOOLS[4],
            Self::FindFreeSlots => &TOOLS[5],
            Self::CreateEvent => &TOOLS[6],
            Self::UpdateEvent => &TOOLS[7],
            Self::DeleteEvent => &TOOLS[8],
            Self::RespondToInvitation => &TOOLS[9],
        }
    }

    /// The operations of `davhaven_domain::authz` the tool performs, which the services decide on every call.
    pub const fn operations(self) -> &'static [Operation] {
        match self {
            Self::ListCalendars => &[Operation::ReadCollection],
            Self::ListEvents | Self::SearchEvents => &[Operation::ListObjects],
            Self::GetEvent => &[Operation::ReadObject],
            Self::FreeBusy | Self::FindFreeSlots => &[Operation::FreeBusyQuery],
            Self::CreateEvent => &[Operation::CreateObject],
            Self::UpdateEvent => &[Operation::UpdateObject],
            Self::DeleteEvent => &[Operation::DeleteObject],
            Self::RespondToInvitation => &[Operation::RespondToInvitation],
        }
    }

    /// The scope a token needs to call the tool, from the scope table of the domain for the MCP channel (the one the
    /// services enforce): `mcp:read` for reads, `mcp:write` for writes. `None` only if the domain table had no entry
    /// for the tool's operation, which a test rules out.
    pub fn required_scope(self) -> Option<Scope> {
        let operation = self.operations().first()?;
        match operation.scope_rule(Channel::Mcp) {
            ScopeRule::Required(scope) => Some(scope),
            ScopeRule::Unavailable | ScopeRule::Unscoped => None,
        }
    }

    /// Whether the tool only reads: its calls are charged to the read budget of the token.
    pub const fn reads(self) -> bool {
        self.info().read_only
    }
}

/// What a tool call needs besides the caller: the limits of the deployment.
pub struct Settings<'a> {
    /// The `[mcp]` configuration.
    pub config: &'a McpConfig,
}

/// Serializes the output of a tool.
fn encode<T: Serialize>(output: &T) -> Result<Value, AppError> {
    serde_json::to_value(output).map_err(AppError::internal)
}

/// Runs a tool call: reads the arguments, calls the services as the caller and returns the output as JSON, which the
/// protocol layer sends as `structuredContent`.
///
/// # Errors
///
/// The `AppError` of the call: `Invalid` for arguments that do not fit, the services' errors otherwise. The
/// protocol layer renders it as a failed tool result.
pub async fn run(
    caller: &Caller<'_>,
    settings: &Settings<'_>,
    tool: ToolKind,
    arguments: Option<JsonObject>,
) -> Result<Value, AppError> {
    match tool {
        ToolKind::ListCalendars => encode(&read::list_calendars(caller, input::parse(arguments)?).await?),
        ToolKind::ListEvents => encode(&read::list_events(caller, settings, input::parse(arguments)?).await?),
        ToolKind::GetEvent => encode(&read::get_event(caller, input::parse(arguments)?).await?),
        ToolKind::SearchEvents => encode(&read::search_events(caller, settings, input::parse(arguments)?).await?),
        ToolKind::FreeBusy => encode(&schedule::free_busy(caller, settings, input::parse(arguments)?).await?),
        ToolKind::FindFreeSlots => {
            encode(&schedule::find_free_slots(caller, settings, input::parse(arguments)?).await?)
        }
        ToolKind::CreateEvent => encode(&write::create_event(caller, input::parse(arguments)?).await?),
        ToolKind::UpdateEvent => encode(&write::update_event(caller, input::parse(arguments)?).await?),
        ToolKind::DeleteEvent => encode(&write::delete_event(caller, input::parse(arguments)?).await?),
        ToolKind::RespondToInvitation => encode(&write::respond_to_invitation(caller, input::parse(arguments)?).await?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalog_has_the_ten_tools_of_the_plan() {
        let names: Vec<&str> = catalog().iter().map(|tool| tool.name).collect();
        assert_eq!(
            names,
            vec![
                "list_calendars",
                "list_events",
                "get_event",
                "search_events",
                "free_busy",
                "find_free_slots",
                "create_event",
                "update_event",
                "delete_event",
                "respond_to_invitation",
            ]
        );
    }

    #[test]
    fn the_dispatch_knows_exactly_the_tools_of_the_catalog_in_the_same_order() {
        let dispatched: Vec<&str> = ToolKind::ALL.iter().map(|tool| tool.name()).collect();
        let cataloged: Vec<&str> = catalog().iter().map(|tool| tool.name).collect();
        assert_eq!(dispatched, cataloged);
        for tool in ToolKind::ALL {
            assert_eq!(ToolKind::from_name(tool.name()), Some(tool));
            assert_eq!(tool.info().name, tool.name(), "the entry of the tool is its own");
        }
        assert_eq!(ToolKind::from_name("drop_database"), None);
        assert_eq!(ToolKind::from_name("LIST_EVENTS"), None, "names are exact");
    }

    #[test]
    fn the_scope_of_every_tool_is_the_one_the_domain_gives_its_operations() {
        for tool in ToolKind::ALL {
            let announced = tool.info().scope;
            assert_eq!(tool.required_scope(), Some(announced), "{}", tool.name());
            assert!(!tool.operations().is_empty(), "{}", tool.name());
            for operation in tool.operations() {
                assert_eq!(
                    operation.scope_rule(Channel::Mcp),
                    ScopeRule::Required(announced),
                    "{}: {operation:?}",
                    tool.name()
                );
            }
        }
    }

    #[test]
    fn reads_need_the_read_scope_and_writes_the_write_scope() {
        for tool in ToolKind::ALL {
            let expected = if tool.reads() { Scope::McpRead } else { Scope::McpWrite };
            assert_eq!(tool.info().scope, expected, "{}", tool.name());
        }
        assert!(!ToolKind::CreateEvent.reads() && ToolKind::GetEvent.reads());
    }

    #[test]
    fn annotations_follow_the_plan() {
        let delete = ToolKind::DeleteEvent.info();
        assert!(delete.destructive && !delete.read_only);
        for tool in [ToolKind::UpdateEvent, ToolKind::RespondToInvitation] {
            assert!(tool.info().idempotent, "{}", tool.name());
        }
        for tool in catalog().iter().filter(|tool| tool.read_only) {
            assert!(!tool.destructive, "{}", tool.name);
            assert!(tool.idempotent, "{}", tool.name);
        }
    }
}
