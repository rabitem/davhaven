# Architecture decision records

Decisions that shape more than one crate are recorded here. A new ADR gets the next number and the status
`proposed`, and is accepted through a pull request; a superseded ADR stays and links to its successor.

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-technology-decisions.md) | Technology decisions | accepted |
| [0002](0002-plugin-registry.md) | Plugin registry | accepted |
| [0003](0003-consistency-contract.md) | Consistency contract | accepted |
| [0004](0004-shared-alarms.md) | Shared alarms; per-user alarm overlay deferred | accepted |
| [0005](0005-database-role-model-and-system-scope.md) | Database role model, system scope and the audit purge | accepted |
| [0006](0006-store-contract-amendments.md) | Store contract amendments | accepted |
| [0007](0007-derived-rsvp-tokens.md) | RSVP link tokens are derived from the key ring | accepted |
| [0008](0008-outbox-delivery-semantics.md) | Outbox delivery semantics | accepted |
| [0009](0009-webhook-delivery-and-egress.md) | Webhook delivery, details and the egress boundary | accepted |
| [0010](0010-theme-assets-through-the-application.md) | Theme assets reach the web surface through the application | accepted |
| [0011](0011-api-contract-in-components.md) | The API contract is built from components; additions of the HTTP edge | accepted |
| [0012](0012-authentication-failures-credential-format-and-fenced-idempotency.md) | Authentication failures, the credential format and fenced idempotency | accepted |
| [0013](0013-server-assembly-configuration-mapping-and-operations.md) | Server assembly, the mapping of configuration to adapters, and operations | accepted |
| [0014](0014-mcp-server-transport-judgement-and-budgets.md) | The MCP server: stateless JSON transport, judgement per call, and what the application does for it | accepted |
| [0015](0015-principal-tokens-for-service-principals-rehash-on-use-and-app-password-length.md) | Principal tokens for service principals, re-hash on use, and the secret length of app passwords | accepted |
| [0016](0016-calendar-providers-oauth-flow-mirror-calendars-and-pull-sync.md) | Calendar providers: the OAuth flow, mirror calendars and the pull sync engine | accepted |
