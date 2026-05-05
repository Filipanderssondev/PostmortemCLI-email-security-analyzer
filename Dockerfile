FROM docker.io/python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONPATH=/app
ENV POSTMORTEM_CONTAINER=1

RUN pip install -e .

ENTRYPOINT ["postmortemcli"]