# Base image is configurable (e.g. point it at a private mirror).
# Defaults to the official Python image on Docker Hub.
# checkov:skip=CKV_DOCKER_7:Base image comes from the PYTHON_IMAGE build arg, which is pinned to 3.12-alpine (never :latest)
ARG PYTHON_IMAGE=python:3.12-alpine

# ---------------------------------------------------------------------------
# Stage 1: build wheels (has compilers; never shipped)
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder

WORKDIR /build
# Copy only the dependency list first so this layer is cached until requirements change.
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip wheel --wheel-dir /wheels -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: minimal runtime image
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="appsec-api" \
      org.opencontainers.image.description="Flask API with structured security telemetry" \
      org.opencontainers.image.source="https://github.com/eguidey/aws-pipeline-2"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000

# Patch OS packages, then create an unprivileged user with no shell or home login.
RUN apk upgrade --no-cache \
 && addgroup -S app && adduser -S -G app -H -s /sbin/nologin app

WORKDIR /srv

# Install dependencies from the pre-built wheels (cached layer), then remove pip itself
# so an attacker who gets code execution can't easily install tooling.
COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links=/wheels /wheels/* \
 && rm -rf /wheels \
 && pip uninstall -y pip

# Application code last - it changes most often, so earlier layers stay cached.
COPY --chown=root:root app/ ./app/
COPY --chown=root:root wsgi.py gunicorn.conf.py ./

USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"

CMD ["gunicorn", "--config", "gunicorn.conf.py", "wsgi:app"]
