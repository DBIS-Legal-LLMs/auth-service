FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts

# set by CI (.github/workflows/ci.yml); returned by GET /health
ARG APP_VERSION=dev
ENV APP_VERSION=$APP_VERSION

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
