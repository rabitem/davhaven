# Security policy

## Supported versions

Davhaven is pre-1.0 and has no released versions yet. Development happens on `main`, security fixes are made on
`main` and published as a new container image, and there are no long-term support branches. Once releases exist,
this section will name the supported release lines.

| Version | Supported |
| --- | --- |
| `main` | yes |
| anything else | no |

## Reporting a vulnerability

Please do **not** open a public issue, discussion or pull request for a suspected vulnerability.

Report it privately through GitHub's private vulnerability reporting for
[`rabitem/davhaven`](https://github.com/rabitem/davhaven): open the repository's **Security** tab and choose
**Report a vulnerability** (or go directly to
<https://github.com/rabitem/davhaven/security/advisories/new>). Include:

- the affected component (CalDAV, management API, MCP, feeds, RSVP, mail, storage, ...) and version or commit,
- steps to reproduce or a proof of concept,
- the impact you expect (for example cross-tenant access, credential disclosure, denial of service).

Do not include real user data or production credentials in the report.

## What to expect

These are targets for a small volunteer-run project, not guarantees.

- Acknowledgement within 3 working days.
- An initial assessment, including severity, within 10 working days.
- A fix or mitigation and a coordinated disclosure date agreed with you. We credit reporters in the advisory
  unless you prefer to stay anonymous.

## Scope

In scope: this repository's code, its container image and its default configuration. Deployment-specific
infrastructure (reverse proxies, mail gateways, identity providers, hosting) is out of scope; report those to
the operator of the deployment.

## Hardening defaults

Tenant isolation is enforced by the database (composite keys and row-level security); credentials are stored as
keyed hashes; all outbound HTTP goes through an egress policy that denies private and metadata address ranges.
The rules behind these defaults are in [`docs/ENGINEERING_RULES.md`](docs/ENGINEERING_RULES.md) (tenant isolation
and security by default).
