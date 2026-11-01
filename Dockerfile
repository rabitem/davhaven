# The image of the `davhaven` server (PLAN 2.17, docs/operations/runbook.md).
#
# * Distroless `cc` on the non-root user 65532, pinned by digest (Dependabot keeps the digests current). The image
#   has no shell and no package manager: the binary is the only program in it, which is why the container health
#   check is `davhaven healthcheck`.
# * The binary is `/usr/local/bin/davhaven`. The root filesystem can be read-only: the server writes nothing unless
#   the configuration names a directory (`observability.dav_capture.dir`), which then has to be a volume or tmpfs.
# * Nothing is configured in the image: the deployment supplies the configuration, either as a file (`--config` or
#   `DAVHAVEN_CONFIG`) or as `DAVHAVEN_*` environment variables, and the secrets as files (`*_file` keys).
#   Set `DAVHAVEN_CONFIG` in the environment of the container, not only in its arguments, so that the health check
#   reads the same configuration as `serve`.
# * The revision is mandatory: `docker build --build-arg REVISION=<git sha>`. The release workflow passes
#   it; a build without it fails in the first stage instead of producing an image nobody can trace.

FROM rust:1.99.1-slim-trixie@sha256:b8e062b1c3a80183df83d9ba187cadd2b5ab84bc78d453dbfeb2fccd5f982247 AS build
ARG REVISION
# Use the image's toolchain as is; rust-toolchain.toml would otherwise pull in clippy, rustfmt and llvm-tools.
# DAVHAVEN_REVISION is read at compile time: the entity tag of a subscription feed carries it, so that a release that
# renders a feed differently never answers `304` for the bytes of the one before.
ENV RUSTUP_TOOLCHAIN=1.99.1 \
    CARGO_TERM_COLOR=never \
    DAVHAVEN_REVISION=${REVISION}
RUN test -n "${REVISION}" || { echo "the build argument REVISION (the git revision of the source) is mandatory" >&2; exit 1; }
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked -p davhaven-server --bin davhaven \
    && install -D -m 0755 target/release/davhaven /out/davhaven

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:08476c244888bfb425bae1ae4dd7c17f093e972aab8426883d97f3c6f280f7c1
ARG REVISION
LABEL org.opencontainers.image.title="davhaven" \
      org.opencontainers.image.description="A multi-tenant CalDAV and scheduling server" \
      org.opencontainers.image.licenses="Apache-2.0 OR MIT" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build /out/davhaven /usr/local/bin/davhaven
USER 65532:65532
# The listeners of the default configuration: public (DAV, web), internal (management API, MCP), ops (health,
# metrics). Which of them a deployment publishes is its decision; only `public` binds a non-loopback address by
# default.
EXPOSE 8080 8081 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/davhaven", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/davhaven"]
CMD ["serve"]
