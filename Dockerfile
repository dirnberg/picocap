# ---- build ----
FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

# ---- run (slim, non-root, no system deps) ----
FROM debian:trixie-slim
# unprivileged user
RUN useradd -r -u 10001 -s /usr/sbin/nologin picocap
COPY --from=build /src/target/release/picocap /usr/local/bin/picocap
USER 10001
EXPOSE 8088
# inside the container we must bind 0.0.0.0; restrict exposure at the host
# with -p 127.0.0.1:8088:8088 and require a token via PICOCAP_TOKEN.
ENTRYPOINT ["picocap"]
CMD ["serve", "0.0.0.0:8088"]
