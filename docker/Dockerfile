# Single image shared by the kdc, app, and test services. It carries both the
# KDC server tooling and the client-side Kerberos libraries, plus the package
# installed with its GSSAPI backend — so every service is one `docker compose`
# away and the integration test exercises the real gssapi accept path.
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1

# krb5-kdc/krb5-admin-server: run a KDC. krb5-user: kinit/klist for the client.
# libkrb5-dev + gcc: build the `gssapi` Python extension. curl: healthchecks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        krb5-kdc krb5-admin-server krb5-user \
        libkrb5-dev gcc curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml README.md ./
COPY fastapi_spnego ./fastapi_spnego
RUN pip install --no-cache-dir -e '.[gssapi]' \
        'fastapi>=0.110.0' 'uvicorn[standard]>=0.29.0' \
        'pytest>=8.0.0' 'requests>=2.31.0' 'requests-gssapi>=1.3.0'

# Then the rest (examples, tests, docker scripts).
COPY . .
RUN chmod +x docker/kdc-entrypoint.sh

EXPOSE 8000
