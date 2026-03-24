### Stage 1: Build React frontend
FROM node:20-slim AS frontend-build
WORKDIR /app/ui
COPY ui/package.json ui/package-lock.json* ./
RUN npm install
COPY ui/ ./
RUN npm run build

### Stage 2: Python backend with safe-install
FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends docker.io && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=frontend-build /app/ui/build /app/ui/build

COPY ../src/safe_install /app/safe_install
COPY backend/ /app/backend/

EXPOSE 9080

CMD ["python", "backend/main.py"]
