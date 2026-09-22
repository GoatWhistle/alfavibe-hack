# ---- Build stage ----
FROM rust:1.89-slim AS builder
WORKDIR /build

# Кэширование зависимостей.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs \
    && cargo build --release 2>/dev/null || true

# Полная сборка.
COPY src ./src
COPY config ./config
RUN cargo build --release

# ---- Runtime stage (distroless, non-root) ----
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app

COPY --from=builder /build/target/release/pd-guard /app/pd-guard
COPY --from=builder /build/config /app/config

# Read-only FS, non-root.
USER nonroot

ENV PDG_CONFIG=/app/config/config.yaml
EXPOSE 8080 9090

ENTRYPOINT ["/app/pd-guard"]