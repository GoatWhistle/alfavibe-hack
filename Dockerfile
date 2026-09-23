# ---- Build stage ----
FROM rust:1.89-slim AS builder
WORKDIR /build

# Кэширование зависимостей.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src benches tools/loadgen && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs \
    && echo "fn main() {}" > benches/detection.rs \
    && echo "fn main() {}" > tools/loadgen/main.rs \
    && cargo build --release 2>/dev/null || true

# Полная сборка.
COPY benches ./benches
COPY src ./src
COPY config ./config
COPY tools ./tools
# touch: иначе cargo сочтёт заглушки из кэш-слоя свежее исходников.
RUN touch src/main.rs src/lib.rs benches/detection.rs tools/loadgen/main.rs \
    && cargo build --release

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
