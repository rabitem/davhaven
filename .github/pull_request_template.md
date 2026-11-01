## Summary

<!-- What does this change do and why? Link the issue or the section of docs/PLAN.md it implements. -->

## Scope

- Crates and modules touched:
- Contract changes (domain types, port traits, service traits, wire types)? <!-- none, or describe; keep them additive where possible -->

## Checklist

- [ ] `scripts/check.sh` passes (same commands as CI)
- [ ] Tests at the right level; bug fixes come with a regression test
- [ ] Rustdoc for every new public item; user-facing behaviour documented in `docs/`
- [ ] Generated documents regenerated with `cargo xtask`, not edited by hand
- [ ] No new dependency outside `[workspace.dependencies]`
- [ ] Title follows Conventional Commits
