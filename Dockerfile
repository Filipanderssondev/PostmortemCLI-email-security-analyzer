FROM python:3.12-alpine

RUN apk add --no-cache gcc musl-dev libffi-dev

WORKDIR /app

COPY pyproject.toml .
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install -e .

# Create inbox folder inside container
# Drop .eml/.msg files here from your laptop while container is running
RUN mkdir -p /inbox

ENTRYPOINT ["postmortemcli"]
CMD ["--help"]