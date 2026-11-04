# Recon read API: FastAPI + DuckDB over the serving store (mounted read-only at /data/serve).
FROM python:3.12-slim
RUN pip install --no-cache-dir duckdb==2.0.0 fastapi==0.162.0 uvicorn==0.54.0
WORKDIR /app
COPY api /app/api
COPY web/src/catalog.json /app/web/src/catalog.json
ENV RECON_SERVE=/data/serve/current PYTHONDONTWRITEBYTECODE=1
USER 65534:65534
EXPOSE 8787
CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8787", "--workers", "2", "--no-server-header"]
