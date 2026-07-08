FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY open_aws_scanner/ open_aws_scanner/

RUN pip install --no-cache-dir .

EXPOSE 8000

CMD ["open-aws-scanner", "serve"]
