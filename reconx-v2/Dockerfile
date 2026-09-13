FROM rust:1.78-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin reconx

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/reconx /usr/local/bin/reconx
ENTRYPOINT ["reconx"]
