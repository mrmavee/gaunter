FROM rust:1.92-alpine AS chef
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig make perl git cmake clang build-base
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
ENV OPENSSL_STATIC=1
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp target/release/gaunter /app/gaunter-bin

FROM alpine:3.23.3 AS runtime
RUN apk add --no-cache tor ca-certificates su-exec && \
    apk add --no-cache i2pd --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community && \
    rm -rf /usr/share/tor/geoip /usr/share/tor/geoip6
RUN addgroup -S gaunter && adduser -S gaunter -G gaunter
WORKDIR /app
COPY --from=builder /app/gaunter-bin /app/gaunter
COPY --from=builder /app/templates /app/templates
COPY infra/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN apk del apk-tools && rm -rf /var/cache/apk/* /lib/apk /usr/share/apk
EXPOSE 8080 8081
ENTRYPOINT ["/entrypoint.sh"]