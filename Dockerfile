# Build stage
FROM rust:bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY schema.cedarschema ./

RUN cargo build --release

# Runtime stage
FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --no-create-home permitd

COPY --from=builder /build/target/release/permitd /usr/local/bin/permitd

USER permitd

ENTRYPOINT ["permitd"]
CMD ["serve", "--config", "/etc/permitd/config.toml"]
