FROM python:3.12-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc iptables tor iproute2 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/anonchain
COPY *.py *.c anonchain install.sh ./
RUN pip install --no-cache-dir rich requests urllib3 psutil && \
    bash install.sh

VOLUME ["/root/.anonchain"]
EXPOSE 9050 5353 9051 9052
ENTRYPOINT ["anonchain"]
