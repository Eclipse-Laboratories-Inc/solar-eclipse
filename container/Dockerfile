FROM solanalabs/rust:1.73.0 AS build
ARG VERSION=1.17.6
ARG NODE_MAJOR=18
RUN mkdir -p /app/solar-eclipse
WORKDIR /app/solar-eclipse

RUN apt-get -q update && \
    apt-get -qy install \
    build-essential git clang libssl-dev libudev-dev perl pkg-config protobuf-compiler

COPY . /app/solar-eclipse
RUN rm -rf /app/solar-eclipse/container
RUN cargo +1.73.0 build --release \
    --bin solana-faucet \
    --bin solana-genesis \
    --bin solana-validator \
    --bin solana \
    --bin solana-keygen \
    --bin solana-ledger-tool \
    --bin solana-test-validator

FROM debian:bookworm-20231120-slim
WORKDIR /app
COPY --from=build  /app/solar-eclipse/fetch-spl.sh /usr/local/bin/fetch-spl.sh
COPY --from=build  /app/solar-eclipse/target/release/solana                /usr/local/bin/eclipse
COPY --from=build  /app/solar-eclipse/target/release/solana-faucet         /usr/local/bin/eclipse-faucet
COPY --from=build  /app/solar-eclipse/target/release/solana-genesis        /usr/local/bin/eclipse-genesis
COPY --from=build  /app/solar-eclipse/target/release/solana-keygen         /usr/local/bin/eclipse-keygen
COPY --from=build  /app/solar-eclipse/target/release/solana-ledger-tool    /usr/local/bin/eclipse-ledger-tool
COPY --from=build  /app/solar-eclipse/target/release/solana-test-validator /usr/local/bin/eclipse-test-validator
COPY --from=build  /app/solar-eclipse/target/release/solana-validator      /usr/local/bin/eclipse-validator
