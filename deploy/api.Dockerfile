# Recon API and the MCP endpoint: FastAPI + DuckDB over the serving store (mounted read-only at
# /data/serve), users' work in SQLite (mounted at /data/app), MCP over HTTP at /mcp.
FROM python:3.12-slim
RUN pip install --no-cache-dir duckdb==2.0.0 fastapi==0.162.0 uvicorn==0.54.0 mcp==2.3.0
WORKDIR /app
COPY api /app/api
COPY mcp_server /app/mcp_server
COPY pipeline /app/pipeline
COPY web/src/catalog.json /app/web/src/catalog.json
ENV RECON_SERVE=/data/serve/current PYTHONDONTWRITEBYTECODE=1
USER 65534:65534
EXPOSE 8787
# one worker: SQLite has one writer, and the MCP session manager runs once per process
CMD ["uvicorn", "api.app:application", "--host", "0.0.0.0", "--port", "8787", "--no-server-header", "--proxy-headers", "--forwarded-allow-ips", "*"]
