# Stage 1: build the React UI (final image stays a light Alpine)
FROM node:22-alpine AS ui
WORKDIR /build
COPY frontend/package.json ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build
# Stage 2: runtime - Python stdlib only, UI + Redfish proxy API
FROM python:3.12-alpine
WORKDIR /app
COPY app/server.py /app/server.py
COPY --from=ui /build/dist /app/static
RUN adduser -D -H ilo && mkdir -p /app/data && chown -R ilo /app
USER ilo
ENV PORT=8080 ILO_DATA_DIR=/app/data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://127.0.0.1:8080/api/health || exit 1
CMD ["python3", "server.py"]
