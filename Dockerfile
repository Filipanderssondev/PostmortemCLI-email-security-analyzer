FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*
# apt-get = Debian's package manager (slim is Debian-based)
# rm -rf /var/lib/apt/lists/* = clean up cache, keeps image size small

WORKDIR /app
COPY pyproject.toml .
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONPATH=/app
RUN pip install -e .
ENTRYPOINT ["postmortemcli"]