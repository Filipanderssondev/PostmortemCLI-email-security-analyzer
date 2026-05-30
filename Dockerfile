FROM docker.io/python:3.12-slim

LABEL maintainer="Filip Andersson <andersson.filip98@gmail.com>"
LABEL org.opencontainers.image.title="PostmortemCLI"
LABEL org.opencontainers.image.description="Email security analysis tool for SMHI"
LABEL org.opencontainers.image.source="https://github.com/Filipanderssondev/PostmortemCLI-email-security-analyzer"
LABEL org.opencontainers.image.licenses="Copyright 2026 Filip Andersson"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONPATH=/app
ENV POSTMORTEM_CONTAINER=1

RUN pip install -e .

RUN mkdir -p /data /data/reports

ENTRYPOINT ["postmortemcli"]