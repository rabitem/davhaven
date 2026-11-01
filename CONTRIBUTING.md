# Contributing to Davhaven

Thank you for helping. This document explains how changes get into the repository. The binding rules for all
code are in [`docs/ENGINEERING_RULES.md`](docs/ENGINEERING_RULES.md); the design and contracts are in
[`docs/PLAN.md`](docs/PLAN.md). [`docs/AGENTS.md`](docs/AGENTS.md) summarises both on one page.

Davhaven is pre-1.0. Contributions are welcome, and no sign-off or contributor agreement is required beyond the
licence terms at the end of this file.

## Before you start

- Look for an existing issue or open one describing the problem. Larger changes start with a short design
  discussion in an issue, or an ADR in [`docs/adr/`](docs/adr/README.md).
- Keep a change inside the crates and modules it is about. The layering between crates is enforced by
  `cargo xtask arch-check`.
- Contract types (domain types, port traits, service traits, wire types) are shared by every crate. Prefer additive
  changes, and put a change to them in a pull request of its own so that it can be reviewed on its own.

## Development setup

- Toolchain: pinned in `rust-toolchain.toml`; rustup installs it on first use.
- Tools: `cargo install --locked cargo-nextest cargo-deny cargo-hack cargo-machete`.
- PostgreSQL: tests that need a database read `DATABASE_URL` and fail when it is missing. Outside CI you can set
  `DAVHAVEN_ALLOW_NO_DB=1` to skip them explicitly (the test then says so; nothing is tested against PostgreSQL).
  With `CI=true` a missing database is always a failure.

### Running the PostgreSQL tests with Docker

The test harness creates roles and databases on the server `DATABASE_URL` names, so use a throw-away server and a
superuser. Local servers are accepted; a remote one is refused unless you set `DAVHAVEN_TEST_DB_THROWAWAY=1`.

```sh
docker run --rm -d --name davhaven-pg -p 5432:5432 \
  -e POSTGRES_USER=davhaven -e POSTGRES_PASSWORD=davhaven -e POSTGRES_DB=davhaven \
  --tmpfs /var/lib/postgresql:rw,size=2g postgres:18

export DATABASE_URL=postgres://davhaven:davhaven@localhost:5432/davhaven
scripts/check.sh test

docker stop davhaven-pg
```

CI uses the same setup (PostgreSQL 18 with the data directory in memory). Every test world is a clone of a migrated
template database, so the schema in `crates/store-postgres/migrations/` is exercised on every run. See
[`docs/testing.md`](docs/testing.md) for the test harness.

### Checks

Run the same checks as CI before pushing:

```sh
scripts/check.sh                 # all steps
scripts/check.sh fmt clippy test # selected steps
```

The steps are `fmt clippy hack arch machete images deny doc test contracts unsupported`. The `contracts` step fails
when a generated document is out of date; regenerate it instead of editing it:

| Document | Regenerate with |
| --- | --- |
| `docs/configuration.md` | `cargo xtask config-docs` |
| `docs/permission-matrix.md` | `cargo xtask matrix` |
| `docs/openapi.json`, `docs/contracts/` | `cargo xtask contracts` |

The text of these documents comes from Rust doc comments and data files, so fix the source and regenerate.

## Making a change

- Keep pull requests small and focused; one logical change per pull request.
- Ship tests at the right level (unit, property, port contract, application, protocol, matrices). Every bug fix
  comes with a regression test. Permission expectations come from the hand-reviewed expectations file, never from
  the code under test.
- Time and randomness only through the `Clock` and `IdGenerator` ports; tests never sleep.
- Every public item has rustdoc; user-facing behaviour is documented in `docs/`.
- No `unwrap`, `expect`, `panic!`, `todo!` or `unimplemented!` outside tests; the only allowed stub is
  `AppError::unsupported()` / `PortError::unsupported()`.
- New dependencies are declared once in `[workspace.dependencies]` and inherited with `workspace = true`. Prefer
  few, maintained, permissively licensed crates (`cargo deny` checks licences and advisories).
- Nothing organisation-specific (names, URLs, hostnames, runner labels, branding) belongs in the repository.

## Commits and pull requests

- Commit messages and pull request titles follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat(dav): ...`, `fix(store-postgres): ...`, `docs: ...`, `ci: ...`, `chore(deps): ...`).
- No attribution footers or trailers added by tools.
- CI must be green before merge.
- Fill in the pull request template, including the crates and modules you touched.

## Continuous integration

The workflows are in `.github/workflows`. Runner time is the scarce resource, so there are few jobs and each does a
lot.

| Workflow | When | What it does |
| --- | --- | --- |
| `ci.yml` | pull requests, merge queue, `main` | `checks` (formatting, clippy with and without default features, each feature of the server, rustdoc with warnings as errors, `cargo xtask arch-check`, unused dependencies, image pins, drift of the generated documents, `cargo deny`, actionlint, zizmor) in four parallel `check` groups, and next to them `test` (nextest in two shards and the doctests on PostgreSQL with `TZ=Pacific/Chatham`); the `checks` and `test` runs sum them up. Then, on `main`, `release` and `coverage`. A newer push to a pull request cancels the run in progress. |
| `release.yml` | called by `ci.yml` on `main` after `checks` and `test` succeeded; `v*` tags; manual runs (a dry run) | Builds the image once, smoke-tests that image (`scripts/image-smoke.sh`), then pushes it to GHCR. A failing smoke test pushes nothing. No pull request builds the image. If the repository variable `DEPLOY_DISPATCH_REPO` is set, it also notifies that repository of the new digest. |
| `nightly.yml` | every night | Property tests with 20000 cases, repeated runs of the suite, the latest and the oldest supported PostgreSQL (15), a `cargo update` canary, the feature powerset, new advisories and fuzzing. The PostgreSQL matrices run in full (`CONFORMANCE_FULL=1`). |
| `openapi-clients.yml` | `main`, when the OpenAPI document changes | Client generation smoke test. |
| `ghcr-retention.yml` | weekly | Image retention. |
| `image-pins.yml` | weekly | Compares the digests of the pinned container images with their registries. |

Pull requests run a representative sample of the large matrices and client flows to keep the run short;
`CONFORMANCE_FULL=1` runs all of them, and the nightly workflow does. `.config/nextest.toml` kills a test after
three minutes by default (longer for the PostgreSQL matrices), so a hung test fails the run instead of holding a
runner.

### Image pins

The container images that workflows and the `Dockerfile` use are pinned by digest. Dependabot reads the
`Dockerfile` but not the images of a workflow, so `image-pins.yml` compares every pin with the digest its registry
gives the tag today and fails when one is stale. `scripts/image-pins.sh update` rewrites stale pins; review the
change and open a pull request. The Rust version of the job image is updated by hand together with
`rust-toolchain.toml`.

### Running the workflows on your own runners

By default every job runs on GitHub-hosted `ubuntu-latest`. A fork or deployment can use its own runners by setting
the repository variable `CI_RUNS_ON` to a JSON array of runner labels (delete the variable to go back):

```sh
gh variable set CI_RUNS_ON --body '["self-hosted","Linux","X64"]'
```

Pull requests from forks and from Dependabot always use `ubuntu-latest`, so their code never reaches a
self-hosted runner. Runners chosen by `CI_RUNS_ON` are trusted infrastructure: they may share a host and a Docker
daemon with other workloads, and only branches of the repository and `main` run on them. A runner needs Linux x64,
Docker with the buildx plugin, `curl`, `python3`, `git` and `bash`, and a runner user that may use Docker.

Jobs that run cargo run in a job container with CPU, memory and process limits and a low CPU weight, so that a
build cannot starve other work on a shared host. These limits bound resources; the container is not a security
boundary. The image job of the release is the one job that uses the Docker daemon of the runner and runs scripts of
the commit on the host, so it runs for `main`, tags and maintainers' manual runs only. It uses a private network
without a route to the outside, publishes no port of the host, and removes everything it created at the end, even
when the smoke test was killed.

## Reporting security issues

Never open a public issue for a vulnerability; follow [`SECURITY.md`](SECURITY.md).

## Code of conduct

Participation in this project is governed by the [code of conduct](CODE_OF_CONDUCT.md).

## License

Davhaven is licensed under MIT OR Apache-2.0, at your option. Unless you explicitly state otherwise, any
contribution intentionally submitted for inclusion in the project, as defined in the Apache-2.0 license, is
dual licensed as above, without any additional terms or conditions (see the [README](README.md#license)).
