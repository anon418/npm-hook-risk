FROM node:20-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    strace \
    procps \
    iproute2 \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
