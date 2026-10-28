# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.13.2 /uv /uvx /bin/
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv build --wheel --out-dir /dist

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    COLDTRAIL_DB=/data/coldtrail.db

RUN groupadd --gid 10001 coldtrail \
    && useradd --uid 10001 --gid coldtrail --create-home coldtrail \
    && mkdir -p /data \
    && chown coldtrail:coldtrail /data

COPY --from=builder /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

USER coldtrail
VOLUME ["/data"]
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; \
resp=urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=4); \
sys.exit(0 if resp.status == 200 else 1)"

ENTRYPOINT ["coldtrail"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8765"]
