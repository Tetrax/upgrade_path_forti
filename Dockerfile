FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# tzdata supplies Europe/Paris to the collector scheduler; gosu drops root after
# preparing host-mounted data directories for the configured PUID/PGID.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssl tzdata gosu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/fortios

COPY requirements-runtime.txt ./
RUN python -m pip install --requirement requirements-runtime.txt

COPY app ./app
COPY scripts ./scripts
COPY data ./data
COPY docs ./docs
COPY docker/entrypoint.sh /usr/local/bin/fortios-entrypoint
COPY docker/cert_helper_entrypoint.sh /usr/local/bin/fortios-cert-helper-entrypoint
COPY docker/certctl.sh /usr/local/bin/fortios-certctl
COPY docker/cert_admin.sh /usr/local/bin/fortios-cert-admin

RUN mkdir -p /opt/fortios/data/advisory-images /opt/fortios/docs /opt/fortios/certificates \
    && chmod -R a+rX /opt/fortios/app /opt/fortios/scripts \
    && chmod 0755 /usr/local/bin/fortios-entrypoint \
      /usr/local/bin/fortios-cert-helper-entrypoint /usr/local/bin/fortios-certctl \
      /usr/local/bin/fortios-cert-admin

EXPOSE 8000

# No HEALTHCHECK here — Compose is the intended orchestrator and provides
# per-service healthchecks (docker-compose.yml, docker-compose.portainer.yml,
# docker-compose.portainer-import.yml). A Dockerfile-level HEALTHCHECK would
# apply to both the web and scheduler services, which is incorrect for the
# scheduler (a batch job, not an HTTP server). The healthcheck script also
# requires FORTIOS_CONTAINER_HEALTHCHECK=1, an orchestrator-level concern.
ENTRYPOINT ["/usr/local/bin/fortios-entrypoint"]
CMD ["python", "scripts/fortios_server.py", "--host", "0.0.0.0", "--port", "8000"]
