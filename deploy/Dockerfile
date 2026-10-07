# Account server image: one static-like binary, no Claude Code, Node, or shell.
FROM rust:1.89-bookworm@sha256:948f9b08a66e7fe01b03a98ef1c7568292e07ec2e4fe90d88c07bb14563c84ff AS build
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# The client library embeds the build qualification harness.
COPY experiments/settings-renewal/*.py ./experiments/settings-renewal/
RUN cargo build --release --locked --features server --bin claudectl-server
RUN set -eu; \
    mkdir -p /runtime/etc/ssl /runtime/tmp; \
    chmod 1777 /runtime/tmp; \
    cp -a /etc/ssl/certs /runtime/etc/ssl/; \
    ldd /source/target/release/claudectl-server | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' \
      | xargs -r -I '{}' cp -L --parents '{}' /runtime

# Reuse the build image's matching glibc and TLS roots without a package manager.
FROM scratch
COPY --from=build /runtime /
COPY --from=build /source/target/release/claudectl-server /claudectl-server
USER 10001:10001
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["/claudectl-server", "health-check"]
ENTRYPOINT ["/claudectl-server"]
