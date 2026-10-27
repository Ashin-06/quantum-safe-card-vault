# Runtime image: dependencies from the pinned lock, source copied in, runs as a non-root user.
FROM python:3.12-slim-bookworm AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY requirements.lock /tmp/
RUN python -m venv /opt/venv && /opt/venv/bin/pip install -r /tmp/requirements.lock

FROM python:3.12-slim-bookworm
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PQCPAYMENT_ENV=production PQCPAYMENT_HOST=0.0.0.0 PQCPAYMENT_PORT=8020 \
    PQCPAYMENT_DATABASE_URL=sqlite:////data/pqcpayment.db
RUN useradd --system --uid 10001 --no-create-home app && mkdir /data && chown app /data
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY pqcpayment pqcpayment
COPY web web
USER app
VOLUME /data
EXPOSE 8020
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ['PQCPAYMENT_PORT'], timeout=2)"]
CMD ["python", "-m", "pqcpayment", "serve"]
