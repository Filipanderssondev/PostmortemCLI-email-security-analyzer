FROM python:3.12-alpine

WORKDIR /app

COPY pyproject.toml .
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install -e .

ENTRYPOINT ["postmortemcli"]