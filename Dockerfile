# Multi-stage production Dockerfile for PQHaven
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build
COPY pyproject.toml .
COPY src/ src/

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && pip install --no-cache-dir --prefix=/install . \
    && rm -rf /var/lib/apt/lists/*

FROM python:3.12-slim-bookworm AS final

LABEL org.opencontainers.image.title="PQHaven" \
      org.opencontainers.image.description="Autonomous Post-Quantum Cryptographic Bill of Materials (CBOM) & Crypto-Agility Engine" \
      org.opencontainers.image.vendor="PQHaven Sovereign Security" \
      org.opencontainers.image.licenses="Apache-2.0"

# Non-root user for air-gapped security
RUN groupadd -g 10001 pqhaven && \
    useradd -u 10001 -g pqhaven -s /bin/bash -m pqhaven

COPY --from=builder /install /usr/local

WORKDIR /workspace
RUN chown -R pqhaven:pqhaven /workspace

USER pqhaven:pqhaven

ENTRYPOINT ["pqscan"]
CMD ["--help"]
