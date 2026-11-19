# Frontend: Svelte, built to static files that the binary embeds.
FROM node:24-bookworm-slim AS web
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM rust:1.99-bookworm AS builder
WORKDIR /app

# Build the dependency graph first so Docker can reuse this layer when only
# source files change. The dummy main keeps Cargo happy while compiling
# dependencies.
COPY Cargo.toml Cargo.lock build.rs ./
RUN mkdir -p src \
    && printf 'fn main() {}\n' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src target/release/deps/gjallarhorn* target/release/gjallarhorn*

COPY src ./src
COPY --from=web /app/web/dist ./web/dist
RUN cargo build --release --locked

# glibc + libgcc only; TLS roots are compiled into the binary and the
# in-cluster CA comes from the service account mount.
FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/DiverOfDark/gjallarhorn" \
      org.opencontainers.image.description="Read-only dashboard over Trivy Operator reports" \
      org.opencontainers.image.licenses="MIT"
COPY --from=builder /app/target/release/gjallarhorn /usr/local/bin/gjallarhorn
# Fewer malloc arenas keeps resident memory flat for a mostly idle process.
ENV MALLOC_ARENA_MAX=2 \
    GJALLARHORN_BIND=0.0.0.0:8080
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/gjallarhorn"]
