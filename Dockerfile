FROM python:3.12-alpine

RUN apk add --no-cache gcc musl-dev libffi-dev

WORKDIR /app

COPY pyproject.toml .
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONPATH=/app
# PYTHONPATH = tells Python where to look for modules
# Without this, "from main import main" fails because
# Python doesn't know to look in /app

RUN pip install -e .

ENTRYPOINT ["postmortemcli"]