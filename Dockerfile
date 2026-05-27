FROM python:3.11-slim AS builder

WORKDIR /build
COPY . .
RUN pip install --no-cache-dir build && \
    python -m build --wheel

FROM python:3.11-slim

COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/mcp_attest-*.whl && \
    rm /tmp/mcp_attest-*.whl && \
    adduser --disabled-password --no-create-home appuser

USER appuser
ENTRYPOINT ["mcp-attest"]
CMD ["--help"]
