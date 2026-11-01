# Changelog

All notable changes to Davhaven are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from 1.0 on; before 1.0 a minor version may
change the configuration, the database schema or the wire formats.

## [Unreleased]

## [0.1.0] - 2026-11-01

The first public version: a multi-tenant CalDAV and scheduling server with a management REST API, an MCP endpoint and
pluggable adapters. See [README.md](README.md) for the feature set and [docs/ROADMAP.md](docs/ROADMAP.md) for what 1.0 still
lacks.

### Added

- CalDAV (RFC 4791, 4918, 6578) for standard clients: discovery, `PROPFIND`/`PROPPATCH`, `calendar-query`, multiget,
  `sync-collection`, extended `MKCOL`, free-busy, and VEVENT/VTODO/VJOURNAL storage that keeps the client's bytes.
- Multi-tenancy isolated by the database: composite keys and PostgreSQL row-level security.
- Personal, group, managed and user-created calendars, sharing from clients (CalendarServer sharing) and through the
  API, and mirror calendars that pull Google and Microsoft calendars over OAuth.
- Server-side scheduling (RFC 6638): direct delivery to internal attendees, iMIP mail from themeable German and English
  templates and an RSVP page for external attendees.
- Revocable credentials stored as keyed hashes: app passwords, scoped API tokens, feed tokens and RSVP tokens.
- Subscription feeds (iCalendar over HTTPS), full or busy-only.
- The management API (`/api/v1`, OpenAPI 3.1 in `docs/openapi.json`) for provisioning, managed calendars, grants,
  webhooks and integrations, with the problem catalog in `docs/problems.md`.
- An MCP endpoint with principal-bound, scoped tokens and per-token budgets.
- Plugins for storage (PostgreSQL, memory), authentication, mail (SMTP, memory), templates, outbound HTTP, providers,
  webhooks, content scanning and rate limiting.
- Operations: structured JSON logs, Prometheus metrics, optional OTLP traces, health endpoints, graceful shutdown and a
  container image.

[Unreleased]: https://github.com/rabitem/davhaven/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rabitem/davhaven/releases/tag/v0.1.0
