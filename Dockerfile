# Primera etapa para instalar dependencias
FROM python:3.11.4-slim as builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc

COPY ./demo-devops-python/requirements.txt ./requirements.txt
COPY ./dep_gunicorn.txt ./dep_gunicorn.txt
RUN cat /app/requirements.txt /app/dep_gunicorn.txt > /app/requirements2.txt && \
    pip wheel --no-cache-dir --wheel-dir /app/wheels -r /app/requirements2.txt

# Imagen final
FROM python:3.11.4-alpine

ENV APP_HOME=/app
WORKDIR $APP_HOME

COPY --from=builder /app/wheels /wheels
RUN pip install --no-cache /wheels/*

COPY ./demo-devops-python/ .
COPY ./scripts/entrypoint_dev.sh .
RUN chmod +x $APP_HOME/entrypoint_dev.sh

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint_dev.sh"]
